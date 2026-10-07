// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

package h3test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/fcgi"
	"strings"
	"testing"
	"time"
)

// 🧾 What the FastCGI responder saw, per request, in arrival order.
type fastcgiSeen struct {
	contentLength int64
	body          string
}

// 📏 A lengthless HTTP/3 body reaches FastCGI with the length Pingclair measured.
//
// PHP-FPM reads exactly `CONTENT_LENGTH` bytes from STDIN, so a request that
// never declared a length has to be read and measured before the exchange opens
// (#248). HTTP/3 has no chunked coding — a body is just DATA frames — so this is
// the transport's ordinary shape, and a bodyless DELETE is ordinary traffic
// too. The responder is Go's own FastCGI server, so its `ContentLength` is the
// CONTENT_LENGTH the proxy sent, not a value this test arranged.
func TestLengthlessFastCGIRequestOverH3(t *testing.T) {
	seen := make(chan fastcgiSeen, 2)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Errorf("reading the proxied body: %v", err)
		}
		seen <- fastcgiSeen{contentLength: r.ContentLength, body: string(body)}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("fcgi-ok"))
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = fcgi.Serve(listener, handler) }()

	_, session := start(t, fmt.Sprintf(
		"root * /tmp\n handle /php/* {\n  php_fastcgi 127.0.0.1:%d\n }",
		listener.Addr().(*net.TCPAddr).Port,
	), 0)

	// 📥 A POST with a body whose length was never declared: on HTTP/1.1 this is
	// a chunked upload, and on HTTP/3 it is simply what an unknown-length body
	// looks like.
	post, err := http.NewRequestWithContext(t.Context(), http.MethodPost, session.url+"/php/index.php",
		io.NopCloser(strings.NewReader("hello")))
	if err != nil {
		t.Fatal(err)
	}
	if post.ContentLength != 0 {
		t.Fatalf("the test needs an undeclared length, got ContentLength=%d", post.ContentLength)
	}
	response, err := session.client.RoundTrip(post)
	if err != nil {
		t.Fatalf("POST /php/index.php: %v", err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != "fcgi-ok" {
		t.Fatalf("POST /php/index.php: status=%d body=%q error=%v", response.StatusCode, body, err)
	}
	select {
	case request := <-seen:
		if request.contentLength != 5 || request.body != "hello" {
			t.Fatalf("the responder must see the measured length: %+v", request)
		}
	case <-time.After(deadline):
		t.Fatal("the responder never received the measured-body request")
	}

	// 🫥 A DELETE that says nothing about a body has an empty one; 411 is not
	// the answer to it.
	delete, err := http.NewRequestWithContext(t.Context(), http.MethodDelete, session.url+"/php/index.php", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err = session.client.RoundTrip(delete)
	if err != nil {
		t.Fatalf("DELETE /php/index.php: %v", err)
	}
	body, err = io.ReadAll(io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || string(body) != "fcgi-ok" {
		t.Fatalf("DELETE /php/index.php: status=%d body=%q error=%v", response.StatusCode, body, err)
	}
	select {
	case request := <-seen:
		if request.contentLength != 0 || request.body != "" {
			t.Fatalf("a bodyless request must arrive as zero bytes: %+v", request)
		}
	case <-time.After(deadline):
		t.Fatal("the responder never received the bodyless request")
	}
}

// 🧱 A lengthless body past the buffering ceiling fails closed with 413.
//
// The length has to exist before the first STDIN byte, so a body this server
// will not hold cannot reach php-fpm: streaming it would arrive there as
// `CONTENT_LENGTH: 0` with unknown bytes behind it (#248).
func TestLengthlessFastCGIBodyPastItsCeilingOverH3(t *testing.T) {
	seen := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- struct{}{}
		w.WriteHeader(http.StatusOK)
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = fcgi.Serve(listener, handler) }()

	_, session := start(t, fmt.Sprintf(
		"root * /tmp\n handle /php/* {\n  php_fastcgi 127.0.0.1:%d {\n   request_buffers 1KiB\n  }\n }",
		listener.Addr().(*net.TCPAddr).Port,
	), 0)

	oversized := strings.Repeat("x", 2048)
	post, err := http.NewRequestWithContext(t.Context(), http.MethodPost, session.url+"/php/index.php",
		io.NopCloser(strings.NewReader(oversized)))
	if err != nil {
		t.Fatal(err)
	}
	response, err := session.client.RoundTrip(post)
	if err != nil {
		t.Fatalf("POST /php/index.php: %v", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	response.Body.Close()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("a body past the measuring ceiling must be refused, got status=%d", response.StatusCode)
	}
	select {
	case <-seen:
		t.Fatal("the responder must never see a body this server could not measure")
	case <-time.After(300 * time.Millisecond):
	}
}
