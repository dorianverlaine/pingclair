// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

package h3test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// 🧾 An oversized header block is refused before routing, on HTTP/3 too.
//
// H1/H2 enforce `max_header_bytes` before any matcher runs; H3 enforced it
// after route resolution, so the same request to a path that matched nothing
// was answered 404 — and site variables and matchers ran on headers that
// should already have been refused (#229). The refusal names the field too,
// which is the client's whole diagnosis (#288).
func TestOversizedHeaderRefusedBeforeRouting(t *testing.T) {
	_, session := start(t, "limits {\n  max_header_bytes 8192\n }\n handle /matched {\n  respond \"ok\"\n }", 0)
	ctx, cancel := context.WithTimeout(t.Context(), deadline)
	defer cancel()

	oversized := func(path string) (int, string) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, session.url+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Big", strings.Repeat("x", 9000))
		response, err := session.client.RoundTrip(request)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(body)
	}

	// 🚫 A path that matches nothing is refused as an oversized request, not
	// as a missing route.
	status, body := oversized("/not-a-route")
	if status != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("an unmatched path must answer 431, not %d: %q", status, body)
	}
	if !strings.Contains(strings.ToLower(body), "x-big") {
		t.Fatalf("the refusal must name the field: %q", body)
	}

	// 🎯 A path that does match keeps the same refusal, so the check moved
	// rather than being duplicated.
	status, body = oversized("/matched")
	if status != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("a matched path must answer 431, not %d: %q", status, body)
	}
}
