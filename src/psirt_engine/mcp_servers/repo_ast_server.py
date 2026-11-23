"""Read-only MCP Server: Tree-sitter AST analysis, call-graph reachability, git blame, and sanitized file reads.

Architectural trust boundary:
- Strictly READ-ONLY: zero file mutation, shell execution, or outbound network tools exist.
- Strict path containment: rejects any path traversal outside repo_root.
- Mandatory secret redaction on every code snippet returned to agents.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tree_sitter_go as tsgo
import tree_sitter_python as tspython

try:
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # pragma: no cover - mcp 1.x compatibility
    from mcp.server.fastmcp import FastMCP  # type: ignore[no-redef]
from tree_sitter import Language, Node, Parser

from psirt_engine.intake.sanitizer import (
    detect_prompt_injection_patterns,
    redact_secrets_and_pii,
)

PY_LANGUAGE = Language(tspython.language())
GO_LANGUAGE = Language(tsgo.language())

IGNORE_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".psirt-state", "dist", "build"}


@dataclass
class SymbolHit:
    file_path: str
    line_start: int
    line_end: int
    symbol: str
    enclosing_function: str | None
    snippet: str
    snippet_hash: str


class RepoASTService:
    """Strictly read-only AST & repository inspection service."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root.resolve()
        self._py_parser = Parser(PY_LANGUAGE)
        self._go_parser = Parser(GO_LANGUAGE)

    def _safe_resolve(self, rel_path: str) -> Path:
        candidate = (self.repo_root / rel_path).resolve()
        try:
            candidate.relative_to(self.repo_root)
        except ValueError as exc:
            raise PermissionError(f"Path traversal denied outside repository root: {rel_path}") from exc
        if not candidate.exists() or not candidate.is_file():
            raise FileNotFoundError(f"File not found: {rel_path}")
        return candidate

    def list_repo_files(self, extension: str | None = None) -> list[str]:
        results: list[str] = []
        for p in sorted(self.repo_root.rglob("*")):
            if p.is_dir() or any(part in IGNORE_DIRS for part in p.parts):
                continue
            if extension and p.suffix != extension:
                continue
            results.append(str(p.relative_to(self.repo_root)))
        return results

    def read_file_lines(self, rel_path: str, start_line: int = 1, end_line: int = 80) -> dict[str, Any]:
        target = self._safe_resolve(rel_path)
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        s = max(1, start_line)
        e = min(len(lines), max(s, end_line))
        raw_chunk = "\n".join(f"{i}: {lines[i - 1]}" for i in range(s, e + 1))
        sanitized, hits = redact_secrets_and_pii(raw_chunk)
        inj = detect_prompt_injection_patterns(sanitized)
        return {
            "file_path": rel_path,
            "line_start": s,
            "line_end": e,
            "content": sanitized,
            "redactions": len(hits),
            "prompt_injection_warnings": inj,
            "snippet_hash": hashlib.sha256(sanitized.encode("utf-8")).hexdigest()[:16],
        }

    def git_blame(self, rel_path: str, start_line: int = 1, end_line: int = 10) -> dict[str, Any]:
        target = self._safe_resolve(rel_path)
        try:
            proc = subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.repo_root),
                    "blame",
                    "-L",
                    f"{max(1, start_line)},{max(start_line, end_line)}",
                    "--porcelain",
                    str(target.relative_to(self.repo_root)),
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if proc.returncode != 0:
                return {"file_path": rel_path, "available": False, "note": "not a git-tracked file"}
            commit = proc.stdout.splitlines()[0].split()[0] if proc.stdout.strip() else "HEAD"
            author = next(
                (ln[len("author ") :] for ln in proc.stdout.splitlines() if ln.startswith("author ")),
                "unknown",
            )
            return {"file_path": rel_path, "available": True, "commit_sha": commit, "author": author}
        except Exception as exc:  # noqa: BLE001
            return {"file_path": rel_path, "available": False, "note": str(exc)}

    def _parse_file(self, path: Path) -> tuple[Node | None, bytes, str]:
        data = path.read_bytes()
        if path.suffix == ".py":
            return self._py_parser.parse(data).root_node, data, "python"
        if path.suffix == ".go":
            return self._go_parser.parse(data).root_node, data, "go"
        return None, data, "other"

    def find_imports(
        self, module_names: list[str], scope_dir: str | None = None
    ) -> list[dict[str, Any]]:
        """Find all Python and Go AST import statements referencing any of module_names."""
        targets = {m.lower() for m in module_names if m}
        scope_prefix = f"{scope_dir.strip('/')}/" if scope_dir and scope_dir != "." else ""
        hits: list[dict[str, Any]] = []

        for rel in self.list_repo_files():
            if scope_prefix and not rel.startswith(scope_prefix):
                continue
            if not rel.endswith((".py", ".go")):
                continue
            full = self.repo_root / rel
            root, src, lang = self._parse_file(full)
            if root is None:
                continue

            for node in _walk(root):
                if lang == "python" and node.type in ("import_statement", "import_from_statement"):
                    text = src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
                    clean, _ = redact_secrets_and_pii(text)
                    lowered = clean.lower()
                    if any(
                        t in lowered.replace(".", " ").split()
                        or lowered.startswith((f"import {t}", f"from {t}"))
                        for t in targets
                    ):
                        hits.append(
                            {
                                "file_path": rel,
                                "line_start": node.start_point[0] + 1,
                                "line_end": node.end_point[0] + 1,
                                "import_text": clean.strip(),
                            }
                        )
                elif lang == "go" and node.type == "import_spec":
                    text = src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
                    clean, _ = redact_secrets_and_pii(text)
                    stripped = clean.strip().strip('"')
                    if any(t in stripped.lower() for t in targets):
                        hits.append(
                            {
                                "file_path": rel,
                                "line_start": node.start_point[0] + 1,
                                "line_end": node.end_point[0] + 1,
                                "import_text": clean.strip(),
                            }
                        )
        return hits

    def get_symbol_callers(
        self, symbols: list[str], scope_dir: str | None = None
    ) -> list[dict[str, Any]]:
        """Find AST call expressions matching any target symbol (supports dotted & bare calls)."""
        normalized_targets = [s.strip() for s in symbols if s.strip()]
        bare_targets = {s.split(".")[-1] for s in normalized_targets}
        scope_prefix = f"{scope_dir.strip('/')}/" if scope_dir and scope_dir != "." else ""
        hits: list[dict[str, Any]] = []

        for rel in self.list_repo_files():
            if scope_prefix and not rel.startswith(scope_prefix):
                continue
            if not rel.endswith((".py", ".go")):
                continue
            if Path(rel).name.startswith("test_") or "/tests/" in f"/{rel}":
                continue
            full = self.repo_root / rel
            root, src, lang = self._parse_file(full)
            if root is None:
                continue

            call_type = "call" if lang == "python" else "call_expression"
            for node in _walk(root):
                if node.type != call_type:
                    continue
                func_node = node.child_by_field_name("function")
                if func_node is None:
                    continue
                callee = src[func_node.start_byte : func_node.end_byte].decode("utf-8", errors="replace").strip()
                matched = any(callee == t or callee.endswith(f".{t}") for t in normalized_targets)
                if not matched and "." not in callee:
                    matched = callee in bare_targets
                if not matched:
                    # Also match selector like ImageMath.eval when callee is ImageMath.eval
                    matched = any(t.endswith(f".{callee}") for t in normalized_targets)
                if not matched:
                    continue

                snippet_raw = src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
                snippet, _ = redact_secrets_and_pii(snippet_raw)
                enclosing = _find_enclosing_function(node, src, lang)
                hits.append(
                    {
                        "file_path": rel,
                        "line_start": node.start_point[0] + 1,
                        "line_end": node.end_point[0] + 1,
                        "symbol": callee,
                        "enclosing_function": enclosing,
                        "snippet": snippet,
                        "snippet_hash": hashlib.sha256(snippet.encode("utf-8")).hexdigest()[:16],
                    }
                )
        return hits

    def trace_reachability(
        self,
        import_names: list[str],
        vulnerable_symbols: list[str],
        scope_dir: str | None = None,
    ) -> dict[str, Any]:
        """Determine static AST reachability: imports -> vulnerable symbol call sites -> entrypoints."""
        imports = self.find_imports(import_names, scope_dir=scope_dir)
        callers = self.get_symbol_callers(vulnerable_symbols, scope_dir=scope_dir)
        reachable = len(imports) > 0 and len(callers) > 0

        # Trace callers of the enclosing function to build a 2-hop call path only when reachable
        call_path: list[str] = []
        if reachable and callers:
            first = callers[0]
            enc = first.get("enclosing_function")
            if enc:
                upstream = self.get_symbol_callers([enc], scope_dir=scope_dir)
                for up in upstream[:2]:
                    up_fn = up.get("enclosing_function") or "<module>"
                    call_path.append(f"{up['file_path']}:{up['line_start']}:{up_fn}")
                call_path.append(f"{first['file_path']}:{first['line_start']}:{enc}")
            call_path.append(f"{first['file_path']}:{first['line_start']}:{first['symbol']}")

        return {
            "imported": len(imports) > 0,
            "imports": imports,
            "symbol_invoked": len(callers) > 0,
            "callers": callers,
            "call_path": call_path,
            "reachable": reachable,
            "scope_dir": scope_dir or ".",
        }


def _walk(node: Node):
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(reversed(cur.children))


def _find_enclosing_function(node: Node, src: bytes, lang: str) -> str | None:
    cur = node.parent
    target_types = (
        {"function_definition"}
        if lang == "python"
        else {"function_declaration", "method_declaration"}
    )
    while cur is not None:
        if cur.type in target_types:
            name_node = cur.child_by_field_name("name")
            if name_node is not None:
                return src[name_node.start_byte : name_node.end_byte].decode("utf-8", errors="replace")
        cur = cur.parent
    return None


def create_repo_ast_mcp_server(repo_root: Path) -> FastMCP:
    """Instantiate the read-only FastMCP server exposing AST & repository inspection tools."""
    service = RepoASTService(repo_root)
    mcp = FastMCP("psirt-repo-ast-readonly")

    @mcp.tool()
    def list_repo_files(extension: str = "") -> list[str]:
        """List files in the target repository (read-only)."""
        return service.list_repo_files(extension=extension or None)

    @mcp.tool()
    def read_file_lines(rel_path: str, start_line: int = 1, end_line: int = 80) -> dict[str, Any]:
        """Read a line range from a repository file with automatic secret redaction (read-only)."""
        return service.read_file_lines(rel_path, start_line=start_line, end_line=end_line)

    @mcp.tool()
    def find_imports(module_names: list[str]) -> list[dict[str, Any]]:
        """Find Python/Go AST import statements matching module names (read-only)."""
        return service.find_imports(module_names)

    @mcp.tool()
    def get_symbol_callers(symbols: list[str]) -> list[dict[str, Any]]:
        """Find AST call sites invoking any of the given symbols (read-only)."""
        return service.get_symbol_callers(symbols)

    @mcp.tool()
    def trace_reachability(
        import_names: list[str], vulnerable_symbols: list[str]
    ) -> dict[str, Any]:
        """Trace static call-graph reachability from imports to vulnerable symbols (read-only)."""
        return service.trace_reachability(import_names, vulnerable_symbols)

    @mcp.tool()
    def git_blame(rel_path: str, start_line: int = 1, end_line: int = 10) -> dict[str, Any]:
        """Return git commit/author attribution for lines in a file (read-only)."""
        return service.git_blame(rel_path, start_line=start_line, end_line=end_line)

    return mcp


def main() -> None:
    repo = Path(os.environ.get("PSIRT_TARGET_REPO", ".")).resolve()
    server = create_repo_ast_mcp_server(repo)
    server.run()


if __name__ == "__main__":
    main()
