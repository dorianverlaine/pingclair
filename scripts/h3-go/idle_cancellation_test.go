// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

package h3test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 🛑 Both cancellation APIs release an idle origin while sibling streams remain usable.
func TestIdleSSECancellation(t *testing.T) {
	for _, action := range []string{"context", "body-close"} {
		t.Run(action, func(t *testing.T) { runSSE(t, action, true) })
	}
}

// 🛑 Cancellation also releases an origin that has not sent response headers yet.
func TestCancellationBeforeResponseHeaders(t *testing.T) {
	entered, abandoned := make(chan struct{}), make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(abandoned)
	}))
	t.Cleanup(origin.Close)
	f, c := start(t, proxyRoute(origin.URL), 0)
	ctx, cancel := context.WithTimeout(t.Context(), deadline)
	defer cancel()
	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		response, err := c.request(ctx, "/waiting-for-headers")
		if response != nil {
			response.Body.Close()
		}
		result <- err
	}()
	await(t, entered, "admitted origin request")
	cancel()
	await(t, abandoned, "upstream cancellation before headers")
	await(t, finished, "cancelled client request")
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	c.get(t, "/ready-"+f.ready, f.ready)
}
