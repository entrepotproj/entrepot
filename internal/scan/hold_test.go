package scan

import (
	"testing"
	"time"
)

func received(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	case <-time.After(50 * time.Millisecond):
		return false
	}
}

func TestHoldHub(t *testing.T) {
	h := newHoldHub(2)
	a, unsubA, ok := h.subscribe([]string{"c1"})
	if !ok {
		t.Fatal("subscribe a")
	}
	b, unsubB, ok := h.subscribe([]string{"c1", "c2"})
	if !ok {
		t.Fatal("subscribe b")
	}
	if _, _, ok := h.subscribe([]string{"c3"}); ok {
		t.Fatal("over the limit")
	}

	h.signal("c2")
	if received(a) || !received(b) {
		t.Fatal("c2 should only wake b")
	}
	// Signals don't block and coalesce while nobody reads.
	h.signal("c1")
	h.signal("c1")
	if !received(a) || !received(b) || received(a) {
		t.Fatal("c1 should wake a and b once")
	}

	unsubA()
	if h.activeHolds() != 1 || len(h.waiters["c1"]) != 1 {
		t.Fatalf("after unsubscribe: active %d, waiters %v", h.activeHolds(), h.waiters)
	}
	unsubB()
	if h.activeHolds() != 0 || len(h.waiters) != 0 {
		t.Fatalf("not cleaned up: %v", h.waiters)
	}

	h.shutdown()
	select {
	case <-h.stop:
	default:
		t.Fatal("stop not closed")
	}
	if _, _, ok := h.subscribe([]string{"c1"}); ok {
		t.Fatal("subscribed after shutdown")
	}
	h.shutdown() // idempotent
}
