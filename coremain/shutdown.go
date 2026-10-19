package coremain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// Admission and completion share a mutex: once stop returns, no handler can
// begin plugin execution. Completion includes response finalizers, not merely
// the return from a DNS sequence. This also covers requests on existing TCP,
// HTTP and QUIC connections that closing a listening socket does not stop.
type requestDrain struct {
	mu       sync.Mutex
	active   int
	stopping bool
	drained  chan struct{}
}

func (d *requestDrain) begin() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopping {
		return false
	}
	d.active++
	return true
}

func (d *requestDrain) end() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.active--
	if d.stopping && d.active == 0 {
		close(d.drained)
	}
}

func (d *requestDrain) stop() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.stopping {
		d.stopping = true
		d.drained = make(chan struct{})
		if d.active == 0 {
			close(d.drained)
		}
	}
	return d.drained
}

type drainingHandler struct {
	drain *requestDrain
	inner server.Handler
}

func (h *drainingHandler) Handle(ctx context.Context, q *dns.Msg, meta server.QueryMeta, pack func(*dns.Msg) (*[]byte, error)) *[]byte {
	if !h.drain.begin() {
		return nil
	}
	defer h.drain.end()
	return h.inner.Handle(ctx, q, meta, pack)
}

// TrackDNSHandler binds a transport entry to the service shutdown lifecycle.
func (m *Mosdns) TrackDNSHandler(h server.Handler) server.Handler {
	return &drainingHandler{drain: &m.requests, inner: h}
}

func (m *Mosdns) trackHTTPHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.requests.begin() {
			http.Error(w, "server shutting down", http.StatusServiceUnavailable)
			return
		}
		defer m.requests.end()
		h.ServeHTTP(w, r)
	})
}

const queryDrainTimeout = 10 * time.Second

func (m *Mosdns) closePlugins(timeout time.Duration) error {
	m.logger.Info("stopping query admission and draining active requests")
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-m.requests.stop():
	case <-timer.C:
		// A plugin that ignores context cancellation must not let us publish a
		// clean checkpoint while it can still mutate DNS exposure history.
		err := fmt.Errorf("query drain exceeded %s; plugin state left dirty", timeout)
		m.logger.Error("shutdown incomplete", zap.String("reason", "query_drain_timeout"), zap.Error(err))
		return err
	}

	order := append([]string(nil), m.pluginOrder...)
	if len(order) == 0 { // Deterministic behavior for NewTestMosdnsWithPlugins.
		for tag := range m.plugins {
			order = append(order, tag)
		}
		sort.Strings(order)
	}
	var errs []error
	for i := len(order) - 1; i >= 0; i-- {
		tag := order[i]
		if closer, ok := m.plugins[tag].(io.Closer); ok {
			m.logger.Info("closing plugin", zap.String("tag", tag))
			if err := closer.Close(); err != nil {
				m.logger.Error("failed to close plugin", zap.String("tag", tag), zap.Error(err))
				errs = append(errs, fmt.Errorf("close plugin %s: %w", tag, err))
			}
		}
	}
	return errors.Join(errs...)
}

// WaitClosed includes errors encountered during draining or final checkpoints.
func (m *Mosdns) WaitClosed() error {
	err := m.sc.WaitClosed()
	return errors.Join(err, m.shutdownErr)
}
