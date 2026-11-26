package scan

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	holdDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "entrepot_scan_hold_duration_seconds",
		Help:    "How long downloads were held waiting for a scan verdict, by outcome (served, blocked, timeout, cancelled, refused).",
		Buckets: prometheus.ExponentialBuckets(0.05, 2, 14),
	}, []string{"outcome"})
	holdsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "entrepot_scan_holds_active",
		Help: "Downloads currently held waiting for a scan verdict.",
	})
)

// holdHub wakes downloads held for a component's verdict. Signals come from
// Evaluate in this process and from Postgres notifications sent by other
// processes; held requests also poll, so a lost signal only adds latency.
type holdHub struct {
	mu      sync.Mutex
	waiters map[string]map[chan struct{}]struct{}
	active  int
	max     int
	stopped bool
	stop    chan struct{}
}

func newHoldHub(max int) *holdHub {
	return &holdHub{waiters: map[string]map[chan struct{}]struct{}{}, max: max, stop: make(chan struct{})}
}

// subscribe registers a held request for the components. ok is false when
// the hub is full or shutting down. The channel receives a value when any
// of the components' verdict may have changed.
func (h *holdHub) subscribe(ids []string) (ch chan struct{}, unsubscribe func(), ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopped || (h.max > 0 && h.active >= h.max) {
		return nil, nil, false
	}
	ch = make(chan struct{}, 1)
	for _, id := range ids {
		set := h.waiters[id]
		if set == nil {
			set = map[chan struct{}]struct{}{}
			h.waiters[id] = set
		}
		set[ch] = struct{}{}
	}
	h.active++
	holdsActive.Inc()
	return ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, id := range ids {
			if set := h.waiters[id]; set != nil {
				delete(set, ch)
				if len(set) == 0 {
					delete(h.waiters, id)
				}
			}
		}
		h.active--
		holdsActive.Dec()
	}, true
}

// signal wakes the requests held for a component.
func (h *holdHub) signal(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.waiters[id] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// shutdown makes held requests give up (they answer "pending") and refuses
// new holds.
func (h *holdHub) shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.stopped {
		h.stopped = true
		close(h.stop)
	}
}

// Active returns the number of held requests.
func (h *holdHub) activeHolds() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.active
}
