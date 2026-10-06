// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

package h3test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// 🌊 Gated events prove incremental delivery; sustained writes expose upstream cancellation.
func TestSSEProgressCancellationAndSibling(t *testing.T) {
	for _, action := range []string{"context", "body-close"} {
		t.Run(action, func(t *testing.T) { runSSE(t, action, false) })
	}
}

func runSSE(t *testing.T, action string, idleAfterEvents bool) {
	t.Helper()
	advance, abandoned := make(chan struct{}), make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(abandoned)
		w.Header().Set("Content-Type", "text/event-stream")
		pulse := time.NewTicker(10 * time.Millisecond)
		defer pulse.Stop()
		for i := 0; ; i++ {
			if _, err := fmt.Fprintf(w, "data: %d\n\n", i); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			if i < 3 || idleAfterEvents {
				select {
				case <-advance:
				case <-r.Context().Done():
					return
				}
			} else {
				select {
				case <-pulse.C:
				case <-r.Context().Done():
					return
				}
			}
		}
	}))
	t.Cleanup(origin.Close)
	f, c := start(t, proxyRoute(origin.URL), 0)
	ctx, cancel := context.WithTimeout(t.Context(), deadline)
	defer cancel()
	response, err := c.request(ctx, "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != 3 || response.StatusCode != 200 || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("unexpected SSE response: %s %d %v", response.Proto, response.StatusCode, response.Header)
	}
	reader := bufio.NewReader(response.Body)
	for i := 0; i < 4; i++ {
		line, err := reader.ReadString('\n')
		if err != nil || line != fmt.Sprintf("data: %d\n", i) {
			t.Fatalf("event %d: %q, %v", i, line, err)
		}
		blank, err := reader.ReadString('\n')
		if err != nil || blank != "\n" {
			t.Fatalf("event terminator: %q, %v", blank, err)
		}
		if i == 0 {
			c.get(t, "/ready-"+f.ready, f.ready)
		}
		if i < 3 {
			select {
			case advance <- struct{}{}:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	if action == "context" {
		cancel()
	} else {
		response.Body.Close()
	}
	await(t, abandoned, "upstream cancellation")
	c.get(t, "/ready-"+f.ready, f.ready)
}

// 🔁 Fully consumed responses reuse the origin socket and the same explicit QUIC connection.
func TestUpstreamConnectionReuse(t *testing.T) {
	var accepted atomic.Int32
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.RemoteAddr)
	}))
	origin.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	origin.Start()
	t.Cleanup(origin.Close)
	_, c := start(t, proxyRoute(origin.URL), 0)
	peers := make(map[string]struct{})
	const requests = 8
	for range requests {
		ctx, cancel := context.WithTimeout(t.Context(), deadline)
		response, err := c.request(ctx, "/reuse")
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 128))
		response.Body.Close()
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 || response.ProtoMajor != 3 || len(body) == 0 || len(body) == 128 {
			t.Fatalf("unexpected reuse response: %d %q", response.StatusCode, body)
		}
		peers[string(body)] = struct{}{}
	}
	// 🔁 Downstream FIN can arrive before the upstream session returns to its pool.
	if got := accepted.Load(); int(got) != len(peers) || got >= requests {
		t.Fatalf("reuse absent or inconsistent: %d connections, %d peers, %d requests", got, len(peers), requests)
	}
	t.Logf("🔁 %d responses used %d origin sockets", requests, len(peers))
}
