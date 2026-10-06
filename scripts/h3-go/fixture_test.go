// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

package h3test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const host = "h3.go.test"
const deadline = 8 * time.Second

// 🛰️ A session owns exactly one QUIC connection and never redials a failed one.
type session struct {
	conn   *quic.Conn
	client *http3.ClientConn
	url    string
}

// 🧰 A fixture owns one child process, isolated credentials, and its log file.
type fixture struct {
	command   *exec.Cmd
	done      chan struct{}
	waitError error
	logPath   string
	address   string
	tls       *tls.Config
	ready     string
}

func start(t *testing.T, routes string, descriptors int) (*fixture, *session) {
	t.Helper()
	binary := os.Getenv("PINGCLAIR_BINARY")
	if binary == "" {
		t.Fatal("PINGCLAIR_BINARY must name the real Pingclair binary; use just h3-go")
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	token := rand.Text()
	cert, key, roots := certificate(t, root)
	tcp := must(net.Listen("tcp4", "127.0.0.1:0"))
	t.Cleanup(func() { _ = tcp.Close() })
	address := tcp.Addr().String()
	udp := must(net.ListenPacket("udp4", address))
	t.Cleanup(func() { _ = udp.Close() })
	config := fmt.Sprintf(`{
 admin off
 auto_https off
 servers {
  protocols h1 h2 h3
 }
}
https://%s:%d {
 bind 127.0.0.1
 tls %s %s
 @ready path /ready-%s
 respond @ready "%s"
 %s
}
`, host, tcp.Addr().(*net.TCPAddr).Port, cert, key, token, token, routes)
	configPath := filepath.Join(root, "Pingclairfile")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fixture{done: make(chan struct{}), logPath: filepath.Join(root, "server.log"), address: address, ready: token,
		tls: &tls.Config{RootCAs: roots, ServerName: host, NextProtos: []string{http3.NextProtoH3}, MinVersion: tls.VersionTLS13}}
	arguments := []string{binary, "run", configPath}
	if descriptors > 0 {
		// 🔻 Only the server child inherits the descriptor ceiling.
		arguments = append([]string{"/bin/sh", "-c", `ulimit -n "$1" || exit; shift; exec "$@"`, "h3-go", fmt.Sprint(descriptors)}, arguments...)
	}
	f.command = exec.Command(arguments[0], arguments[1:]...)
	f.command.Env = append(os.Environ(), "PINGCLAIR_TLS_STORE="+filepath.Join(root, "tls"), "RUST_LOG=info", "NO_COLOR=1")
	log := must(os.OpenFile(f.logPath, os.O_CREATE|os.O_WRONLY, 0600))
	f.command.Stdout, f.command.Stderr = log, log
	tcp.Close()
	udp.Close()
	if err := f.command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	go func() { f.waitError = f.command.Wait(); close(f.done) }()
	t.Cleanup(func() {
		select {
		case <-f.done:
		default:
			_ = f.command.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-f.done:
		case <-time.After(deadline):
			_ = f.command.Process.Kill()
			<-f.done
		}
		log.Close()
		if t.Failed() {
			t.Logf("🧾 Server log:\n%s", f.logs())
		}
	})
	until := time.Now().Add(deadline)
	for time.Now().Before(until) {
		select {
		case <-f.done:
			t.Fatalf("server exited before readiness: %v\n%s", f.waitError, f.logs())
		default:
		}
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		conn, err := quic.DialAddr(ctx, address, f.tls.Clone(), &quic.Config{MaxIdleTimeout: 20 * time.Second})
		cancel()
		if err == nil {
			c := &session{conn: conn, client: (&http3.Transport{}).NewClientConn(conn), url: "https://" + net.JoinHostPort(host, fmt.Sprint(tcp.Addr().(*net.TCPAddr).Port))}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			response, err := c.request(ctx, "/ready-"+token)
			if err == nil {
				body, readError := io.ReadAll(io.LimitReader(response.Body, 128))
				response.Body.Close()
				if readError == nil && response.StatusCode == 200 && response.ProtoMajor == 3 && string(body) == token {
					cancel()
					t.Cleanup(func() { _ = conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "") })
					return f, c
				}
			}
			cancel()
			_ = conn.CloseWithError(0, "")
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("unique HTTP/3 readiness token never arrived")
	return nil, nil
}

func (c *session) request(ctx context.Context, path string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+path, nil)
	if err != nil {
		return nil, err
	}
	return c.client.RoundTrip(request)
}

func (c *session) get(t *testing.T, path, expected string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), deadline)
	defer cancel()
	response, err := c.request(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || response.StatusCode != 200 || response.ProtoMajor != 3 || string(body) != expected {
		t.Fatalf("GET %s: status=%d protocol=%s body=%q error=%v", path, response.StatusCode, response.Proto, body, err)
	}
}

func (f *fixture) logs() string {
	file, err := os.Open(f.logPath)
	if err != nil {
		return err.Error()
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return err.Error()
	}
	if stat.Size() > 64*1024 {
		_, _ = file.Seek(-64*1024, io.SeekEnd)
	}
	return string(must(io.ReadAll(io.LimitReader(file, 64*1024))))
}

// 🧾 Scan every log line with bounded memory so retry bursts cannot hide early evidence.
func (f *fixture) logged(t *testing.T, fragment string) bool {
	t.Helper()
	file := must(os.Open(f.logPath))
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), fragment) {
			return true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return false
}

func await(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(deadline):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

// 🔐 The test trusts only its own short-lived fixture certificate.
func certificate(t *testing.T, root string) (string, string, *x509.CertPool) {
	t.Helper()
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true}
	der := must(x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key))
	certPath, keyPath := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: must(x509.MarshalPKCS8PrivateKey(key))})
	for path, data := range map[string][]byte{certPath: certPEM, keyPath: keyPEM} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("invalid fixture certificate")
	}
	return certPath, keyPath, roots
}

func proxyRoute(address string) string {
	return "reverse_proxy http://" + strings.TrimPrefix(address, "http://")
}
