// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

package h3test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// 🔁 Every transport keeps one actual connection, with no pool able to redial.
func TestClientAuthReload(t *testing.T) {
	for _, change := range []string{"mode", "roots", "pins"} {
		t.Run(change, func(t *testing.T) {
			root := t.TempDir()
			first, _, _ := certificate(t, root)
			second, _, _ := certificate(t, t.TempDir())
			trustPath := filepath.Join(root, "client.pem")
			if err := os.WriteFile(trustPath, must(os.ReadFile(first)), 0600); err != nil {
				t.Fatal(err)
			}
			auth := "mode request"
			switch change {
			case "roots":
				auth = fmt.Sprintf("mode verify_if_given\n trust_pool file {\n pem_file %s\n }", trustPath)
			case "pins":
				auth += "\n trusted_leaf_cert_file " + trustPath
			}
			admin := must(net.Listen("tcp4", "127.0.0.1:0"))
			adminAddress := admin.Addr().String()
			admin.Close()
			f, h3 := startConfigured(t, `respond "before"`, 0, func(config string) string {
				config = strings.Replace(config, "admin off", "admin "+adminAddress, 1)
				lines := strings.Split(config, "\n")
				for i, line := range lines {
					if strings.HasPrefix(line, " tls ") {
						lines[i] += " {\n client_auth {\n " + auth + "\n }\n }"
					}
				}
				return strings.Join(lines, "\n")
			})
			connect := func(alpn string) *tls.Conn {
				config := f.tls.Clone()
				config.NextProtos = []string{alpn}
				conn := must(tls.DialWithDialer(&net.Dialer{Timeout: deadline}, "tcp", f.address, config))
				t.Cleanup(func() { _ = conn.Close() })
				if conn.ConnectionState().NegotiatedProtocol != alpn {
					t.Fatalf("ALPN did not negotiate %s", alpn)
				}
				return conn
			}
			h1 := connect("http/1.1")
			reader := bufio.NewReader(h1)
			h2Transport := must(http2.ConfigureTransports(&http.Transport{}))
			h2 := must(h2Transport.NewClientConn(connect("h2")))
			probe := func(status int, body string) {
				t.Helper()
				ctx, cancel := context.WithTimeout(t.Context(), deadline)
				defer cancel()
				request := must(http.NewRequestWithContext(ctx, http.MethodGet, h3.url+"/probe", nil))
				if err := h1.SetDeadline(time.Now().Add(deadline)); err != nil {
					t.Fatal(err)
				}
				if err := request.Write(h1); err != nil {
					t.Fatal(err)
				}
				responses := []*http.Response{must(http.ReadResponse(reader, request)), must(h2.RoundTrip(request)), must(h3.request(ctx, "/probe"))}
				for i, response := range responses {
					got := string(must(io.ReadAll(io.LimitReader(response.Body, 4097))))
					response.Body.Close()
					if response.StatusCode != status || response.ProtoMajor != i+1 || got != body {
						t.Fatalf("H%d: status=%d protocol=%s body=%q; want %d %q", i+1, response.StatusCode, response.Proto, got, status, body)
					}
				}
			}
			reload := func(config string) {
				t.Helper()
				if change != "mode" {
					client := &http.Client{Transport: &http.Transport{}, Timeout: deadline}
					defer client.CloseIdleConnections()
					response := must(client.Post("http://"+adminAddress+"/load", "text/caddyfile", strings.NewReader(config)))
					defer response.Body.Close()
					if response.StatusCode != 200 {
						t.Fatalf("Admin reload: %s: %s", response.Status, must(io.ReadAll(io.LimitReader(response.Body, 4097))))
					}
					return
				}
				const success = "Configuration reloaded successfully"
				before := strings.Count(f.logs(), success)
				if err := os.WriteFile(f.configPath, []byte(config), 0600); err != nil {
					t.Fatal(err)
				}
				if err := f.command.Process.Signal(syscall.SIGUSR1); err != nil {
					t.Fatal(err)
				}
				until := time.Now().Add(deadline)
				for time.Now().Before(until) {
					if strings.Count(f.logs(), success) > before {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
				t.Fatal("reload never completed")
			}
			probe(200, "before")
			config := string(must(os.ReadFile(f.configPath)))
			reload(config)
			probe(200, "before")
			config = strings.ReplaceAll(config, `respond "before"`, `respond "after"`)
			reload(config)
			probe(200, "after")
			if change == "mode" {
				config = strings.ReplaceAll(config, "mode request", "mode require")
			} else if err := os.WriteFile(trustPath, must(os.ReadFile(second)), 0600); err != nil {
				t.Fatal(err)
			}
			reload(config)
			probe(421, "TLS client-auth policy changed; reconnect")
		})
	}
}
