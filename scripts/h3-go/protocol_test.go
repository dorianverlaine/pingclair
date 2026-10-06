// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

package h3test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// 🚫 Raw QPACK bypasses net/http's header sanitization; only the malformed stream may reset.
func TestMalformedHeadersKeepConnection(t *testing.T) {
	f, c := start(t, `respond "ok"`, 0)
	for _, name := range []string{"connection", "keep-alive", "upgrade"} {
		ctx, cancel := context.WithTimeout(t.Context(), deadline)
		stream := must(c.conn.OpenStreamSync(ctx))
		_ = stream.SetDeadline(time.Now().Add(deadline))
		var block bytes.Buffer
		encoder := qpack.NewEncoder(&block)
		for _, field := range []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: host}, {Name: ":path", Value: "/"}, {Name: name, Value: "keep-alive"}} {
			if err := encoder.WriteField(field); err != nil {
				t.Fatal(err)
			}
		}
		frame := quicvarint.Append(nil, 1)
		frame = quicvarint.Append(frame, uint64(block.Len()))
		frame = append(frame, block.Bytes()...)
		if _, err := stream.Write(frame); err != nil {
			t.Fatal(err)
		}
		_ = stream.Close()
		_, err := stream.Read(make([]byte, 1))
		cancel()
		var reset *quic.StreamError
		if !errors.As(err, &reset) || !reset.Remote || reset.ErrorCode != quic.StreamErrorCode(http3.ErrCodeMessageError) {
			t.Fatalf("%s: expected remote H3_MESSAGE_ERROR, got %v", name, err)
		}
		c.get(t, "/ready-"+f.ready, f.ready)
	}
}

// 🛑 GOAWAY refuses new request streams while an admitted request finishes before H3_NO_ERROR.
func TestGracefulShutdownDrainsRequest(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
			fmt.Fprint(w, "completed")
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(origin.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	f, c := start(t, proxyRoute(origin.URL), 0)
	ctx, cancel := context.WithTimeout(t.Context(), deadline)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		response, err := c.request(ctx, "/slow")
		if err == nil {
			body, readError := io.ReadAll(io.LimitReader(response.Body, 64))
			response.Body.Close()
			if readError != nil || response.StatusCode != 200 || string(body) != "completed" {
				err = fmt.Errorf("in-flight request: status=%d body=%q error=%v", response.StatusCode, body, readError)
			}
		}
		result <- err
	}()
	await(t, entered, "admitted origin request")
	if err := f.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	refused := false
	for ctx.Err() == nil {
		stream, err := c.client.OpenRequestStream(ctx)
		if err != nil {
			// 🧾 quic-go v0.63.0 exposes GOAWAY through a client error, not the raw frame ID.
			if err.Error() != "connection in graceful shutdown" {
				t.Fatalf("new stream failed before GOAWAY: %v", err)
			}
			refused = true
			break
		}
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		time.Sleep(10 * time.Millisecond)
	}
	if !refused {
		t.Fatal("GOAWAY never refused new streams")
	}
	close(release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	await(t, c.conn.Context().Done(), "clean QUIC close")
	var closed *quic.ApplicationError
	cause := context.Cause(c.conn.Context())
	// 🧹 quic-go may initiate the clean close after its last admitted stream finishes.
	if !errors.As(cause, &closed) || closed.ErrorCode != quic.ApplicationErrorCode(http3.ErrCodeNoError) {
		t.Fatalf("expected H3_NO_ERROR after drain, got %v", cause)
	}
	await(t, f.done, "server exit")
	if f.waitError != nil {
		t.Fatal(f.waitError)
	}
}
