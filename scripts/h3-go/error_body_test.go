// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

package h3test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 🧾 The built-in error body is the same sentence on HTTP/3 as on H1/H2.
//
// HTTP/3 used to answer a missing file with an empty 404 and a body over
// `request_body max_size` with the bare phrase, so the same refusal carried
// different bytes depending on the transport (#252, #253).
func TestBuiltinErrorBodiesMatchTheOtherTransports(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "present.txt"), []byte("present"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, session := start(t, fmt.Sprintf(
		"root * %s\n file_server\n handle /upload {\n  request_body {\n   max_size 10\n  }\n  respond \"accepted\"\n }",
		root,
	), 0)
	ctx, cancel := context.WithTimeout(t.Context(), deadline)
	defer cancel()

	cases := []struct {
		name   string
		method string
		path   string
		body   io.Reader
		status int
		text   string
	}{
		{"missing file", http.MethodGet, "/missing.txt", nil, http.StatusNotFound, "404 Not Found"},
		{"declared too large", http.MethodPost, "/upload", strings.NewReader(strings.Repeat("x", 100)), http.StatusRequestEntityTooLarge, "413 Request Entity Too Large"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequestWithContext(ctx, test.method, session.url+test.path, test.body)
			if err != nil {
				t.Fatal(err)
			}
			response, err := session.client.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != test.status {
				t.Fatalf("status=%d, want %d (%q)", response.StatusCode, test.status, body)
			}
			if string(body) != test.text {
				t.Fatalf("body=%q, want %q", body, test.text)
			}
			if contentType := response.Header.Get("Content-Type"); contentType != "text/plain" {
				t.Fatalf("content-type=%q, want text/plain", contentType)
			}
		})
	}
}
