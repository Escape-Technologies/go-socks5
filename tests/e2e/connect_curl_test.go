//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Escape-Technologies/go-socks5"
)

const (
	demoToken    = "PLA-995-socks5-ok"
	demoBody     = "hello-via-socks " + demoToken + "\n"
	listenAddr   = "127.0.0.1:0"
	curlTimeout  = 5 * time.Second
	demoHeader   = "X-Demo: " + demoToken
	socksGranted = "SOCKS5 request granted"
)

func TestE2E_CurlThroughSOCKS5(t *testing.T) {
	requireCurl(t)

	httpAddr := startHTTP(t)
	socksAddr := startSOCKS(t)
	url := "http://" + httpAddr + "/"

	direct := runCurl(t, "-sS", url)
	if !strings.Contains(direct.stdout, demoBody) {
		t.Fatalf("direct body: %q", direct.stdout)
	}

	proxied := runCurl(t, "-sS", "-D", "-", "--socks5", socksAddr, url)
	if !strings.HasPrefix(proxied.stdout, "HTTP/1.1 200") {
		t.Fatalf("proxied status: %q", proxied.stdout)
	}
	if !strings.Contains(proxied.stdout, demoHeader) {
		t.Fatalf("missing %s: %q", demoHeader, proxied.stdout)
	}
	if !strings.Contains(proxied.stdout, demoBody) {
		t.Fatalf("proxied body: %q", proxied.stdout)
	}

	hostname := runCurl(t, "-sS", "--socks5-hostname", socksAddr, url)
	if hostname.stdout != direct.stdout {
		t.Fatalf("hostname proxy mismatch: direct=%q proxied=%q", direct.stdout, hostname.stdout)
	}

	verbose := runCurl(t, "-sS", "-v", "--socks5", socksAddr, url)
	if !strings.Contains(verbose.stderr, socksGranted) {
		t.Fatalf("missing %q in curl stderr: %q", socksGranted, verbose.stderr)
	}
	if verbose.stdout != direct.stdout {
		t.Fatalf("verbose proxy mismatch: direct=%q proxied=%q", direct.stdout, verbose.stdout)
	}
}

type curlResult struct {
	stdout string
	stderr string
}

func requireCurl(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("curl"); err != nil {
		t.Fatalf("curl not found: %v", err)
	}
}

func runCurl(t *testing.T, args ...string) curlResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), curlTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "curl", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("curl %v: %v\nstderr=%s\nstdout=%s", args, err, stderr.String(), stdout.String())
	}
	return curlResult{stdout: stdout.String(), stderr: stderr.String()}
}

func startHTTP(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Demo", demoToken)
		_, _ = fmt.Fprint(w, demoBody)
	})

	ln := listenTCP(t)
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func startSOCKS(t *testing.T) string {
	t.Helper()
	server, err := socks5.New(&socks5.Config{})
	if err != nil {
		t.Fatalf("socks5.New: %v", err)
	}
	ln := listenTCP(t)
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func listenTCP(t *testing.T) net.Listener {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", listenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}
