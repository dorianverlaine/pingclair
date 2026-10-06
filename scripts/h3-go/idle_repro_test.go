//go:build h3_idle_repro

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

package h3test

import "testing"

// 🔬 This opt-in reproduction requires cancellation while the origin has stopped writing.
func TestIdleSSECancellation(t *testing.T) {
	runSSE(t, "body-close", true)
}
