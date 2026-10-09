// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

package h3test

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// 🛡️ The listener allowlist has the same observable policy on all transports.
func TestExpectedUnderscoreHeaders(t *testing.T) {
	for _, scope := range []string{"default", "global", "addressed"} {
		t.Run(scope, func(t *testing.T) {
			fields := []string{"x_probe", "x-probe", "webhook_event", "webhook-event", "webhook_bad.dot", "global_field", "x_other"}
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				observed := map[string][]string{}
				for _, name := range fields {
					if values := r.Header.Values(name); len(values) > 0 {
						observed[name] = values
					}
				}
				_ = json.NewEncoder(w).Encode(observed)
			}))
			defer origin.Close()
			f, h3 := startConfigured(t, "reverse_proxy "+origin.URL, 0, func(config string) string {
				switch scope {
				case "global":
					return strings.Replace(config, "protocols h1 h2 h3", "protocols h1 h2 h3\n expected_underscore_headers X_Probe Webhook_* Global_Field", 1)
				case "addressed":
					for _, word := range strings.Fields(config) {
						if strings.HasPrefix(word, "https://") {
							_, port, err := net.SplitHostPort(strings.TrimPrefix(word, "https://"))
							if err != nil {
								t.Fatal(err)
							}
							return strings.Replace(config, "admin off", fmt.Sprintf("admin off\n servers {\n expected_underscore_headers Global_Field\n }\n servers 127.0.0.1:%s {\n expected_underscore_headers X_Probe Webhook_*\n }", port), 1)
						}
					}
					t.Fatal("fixture has no HTTPS site")
				}
				return config
			})
			connect := func(alpn string) *tls.Conn {
				config := f.tls.Clone()
				config.NextProtos = []string{alpn}
				conn := must(tls.DialWithDialer(&net.Dialer{Timeout: deadline}, "tcp", f.address, config))
				t.Cleanup(func() { _ = conn.Close() })
				if conn.ConnectionState().NegotiatedProtocol != alpn {
					t.Fatalf("missing ALPN %s", alpn)
				}
				return conn
			}
			h1 := connect("http/1.1")
			reader := bufio.NewReader(h1)
			h2 := must(must(http2.ConfigureTransports(&http.Transport{})).NewClientConn(connect("h2")))
			for _, repeated := range []bool{false, true} {
				request := must(http.NewRequestWithContext(t.Context(), "GET", h3.url+"/probe", nil))
				request.Header = http.Header{
					"X_Probe": {"kept"}, "X-Probe": {"alias"},
					"Webhook_Event": {"prefix"}, "Webhook-Event": {"alias"},
					"Webhook_Bad.Dot": {"unvetted"}, "Global_Field": {"global"}, "X_Other": {"dropped"},
				}
				if repeated {
					request.Header.Add("X_Probe", "second")
				}
				if err := h1.SetDeadline(time.Now().Add(deadline)); err != nil {
					t.Fatal(err)
				}
				if err := request.Write(h1); err != nil {
					t.Fatal(err)
				}
				responses := []*http.Response{must(http.ReadResponse(reader, request)), must(h2.RoundTrip(request)), must(h3.client.RoundTrip(request))}
				expected := map[string][]string{"x-probe": {"alias"}, "webhook-event": {"alias"}}
				if scope != "default" {
					expected = map[string][]string{"webhook_event": {"prefix"}}
					if !repeated {
						expected["x_probe"] = []string{"kept"}
					}
					if scope == "global" {
						expected["global_field"] = []string{"global"}
					}
				}
				for i, response := range responses {
					body := must(io.ReadAll(io.LimitReader(response.Body, 8192)))
					response.Body.Close()
					observed := map[string][]string{}
					if err := json.Unmarshal(body, &observed); err != nil {
						t.Fatalf("H%d: %s: %v", i+1, body, err)
					}
					if response.StatusCode != 200 || response.ProtoMajor != i+1 || !reflect.DeepEqual(observed, expected) {
						t.Fatalf("H%d repeated=%v: status=%d proto=%s got=%v want=%v", i+1, repeated, response.StatusCode, response.Proto, observed, expected)
					}
				}
			}
		})
	}
}
