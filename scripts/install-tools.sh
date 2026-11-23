#!/usr/bin/env bash
# Install optional open-source deterministic security scanners used by Layer 1 intake.
# The engine also runs cleanly without these binaries using its built-in fallback scanners
# or pre-generated scanner JSON reports.

set -euo pipefail

BIN_DIR="${HOME}/.local/bin"
mkdir -p "${BIN_DIR}"

echo "Installing security scanner binaries into ${BIN_DIR}..."

install_if_missing() {
  local name="$1"
  shift
  if command -v "${name}" >/dev/null 2>&1; then
    echo "[ok] ${name} already installed at $(command -v "${name}")"
  else
    echo "[install] ${name}..."
    "$@"
  fi
}

# Anchore Syft (SBOM generation)
install_if_missing syft bash -c "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b '${BIN_DIR}'"

# Anchore Grype (SBOM / dependency CVE scanning)
install_if_missing grype bash -c "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b '${BIN_DIR}'"

# Google OSV-Scanner (Go install)
if command -v go >/dev/null 2>&1; then
  install_if_missing osv-scanner bash -c "GOBIN='${BIN_DIR}' go install github.com/google/osv-scanner/cmd/osv-scanner@latest"
  install_if_missing gitleaks bash -c "GOBIN='${BIN_DIR}' go install github.com/gitleaks/gitleaks/v8@latest"
  install_if_missing vexctl bash -c "GOBIN='${BIN_DIR}' go install github.com/openvex/vexctl@latest"
else
  echo "[skip] Go not found; skipping osv-scanner, gitleaks, vexctl"
fi

# Semgrep Community Edition (Python tool via uv or pip)
if command -v uv >/dev/null 2>&1; then
  install_if_missing semgrep uv tool install semgrep
elif command -v pipx >/dev/null 2>&1; then
  install_if_missing semgrep pipx install semgrep
else
  echo "[skip] Install semgrep manually via: pip install semgrep"
fi

echo ""
echo "Done. Ensure ${BIN_DIR} is in your PATH."
