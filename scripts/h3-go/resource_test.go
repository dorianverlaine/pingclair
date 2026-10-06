// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

package h3test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 🔻 A 64-request burst must cause genuine child-only EMFILE without evicting the live origin.
func TestDescriptorExhaustionKeepsBackend(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	var arrivals atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals.Add(1)
		select {
		case <-release:
			fmt.Fprint(w, "ok")
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(origin.Close)
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	f, c := start(t, proxyRoute(origin.URL), 64)
	ctx, cancel := context.WithTimeout(t.Context(), deadline)
	defer cancel()
	results := make(chan bool, 64)
	launch := make(chan struct{})
	for range 64 {
		go func() {
			<-launch
			response, err := c.request(ctx, "/probe")
			ok := false
			if err == nil {
				body, readError := io.ReadAll(io.LimitReader(response.Body, 16))
				response.Body.Close()
				ok = readError == nil && response.StatusCode == 200 && string(body) == "ok"
			}
			results <- ok
		}()
	}
	close(launch)
	observed := false
	for ctx.Err() == nil {
		if f.logged(t, "Local resource failure on H3 connect") {
			observed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	once.Do(func() { close(release) })
	if !observed {
		t.Fatal("burst did not produce a genuine local resource failure")
	}
	failed := 0
	for range 64 {
		select {
		case ok := <-results:
			if !ok {
				failed++
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if failed == 0 || arrivals.Load() == 0 {
		t.Fatalf("vacuous exhaustion result: failures=%d origin requests=%d", failed, arrivals.Load())
	}
	if f.logged(t, "Marking H3 upstream") {
		t.Fatal("local exhaustion marked the healthy backend down")
	}
	// 🛡️ The immediate probe cannot wait out the backend cooldown.
	c.get(t, "/probe", "ok")
	t.Logf("🔻 64 concurrent requests: %d failed locally; healthy backend retained", failed)
}
