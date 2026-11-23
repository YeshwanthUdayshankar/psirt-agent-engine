package main

import (
	"net/http"
	"os/exec"

	"golang.org/x/net/http2"
)

func startServer() *http.Server {
	srv := &http.Server{Addr: ":8443"}
	_ = http2.ConfigureServer(srv, &http2.Server{})
	return srv
}

func runDiag(host string) ([]byte, error) {
	return exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()
}

func main() {
	_ = startServer()
}
