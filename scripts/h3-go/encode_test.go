// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

package h3test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// 🧾 A HEAD describes the response its GET would receive, over HTTP/3 too.
//
// RFC 9110 §9.3.2 asks a `HEAD` for the fields the same request with `GET`
// would send, and §8.6 makes any `Content-Length` the length of the content
// that request would receive. Announcing the origin's identity length while
// the `GET` receives gzip bytes is neither (#264).
func TestHeadDescribesTheGetsEncodedResponse(t *testing.T) {
	body := strings.Repeat("compressible text ", 512)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(origin.Close)
	_, session := start(t, "encode gzip\n "+proxyRoute(origin.URL), 0)

	representation := func(method string) http.Header {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), deadline)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, method, session.url+"/text", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Accept-Encoding", "gzip")
		response, err := session.client.RoundTrip(request)
		if err != nil {
			t.Fatalf("%s /text: %v", method, err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		if response.StatusCode != 200 {
			t.Fatalf("%s /text: status=%d", method, response.StatusCode)
		}
		return response.Header
	}

	head := representation(http.MethodHead)
	get := representation(http.MethodGet)
	if head.Get("Content-Encoding") != "gzip" {
		t.Fatalf("the HEAD must describe the representation its GET receives: %v", head)
	}
	if get.Get("Content-Encoding") != "gzip" {
		t.Fatalf("the GET must be the encoded representation: %v", get)
	}
	if head.Get("Content-Length") != get.Get("Content-Length") {
		t.Fatalf("HEAD Content-Length=%q, GET Content-Length=%q",
			head.Get("Content-Length"), get.Get("Content-Length"))
	}
	if head.Get("Content-Length") != "" {
		t.Fatalf("the identity length must not describe gzip bytes: %q", head.Get("Content-Length"))
	}
}
