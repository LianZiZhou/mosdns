package coremain

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/miekg/dns"
)

type shutdownHandlerFunc func()

func (f shutdownHandlerFunc) Handle(context.Context, *dns.Msg, server.QueryMeta, func(*dns.Msg) (*[]byte, error)) *[]byte {
	f()
	return nil
}

type shutdownCloserFunc func() error

func (f shutdownCloserFunc) Close() error { return f() }

func TestShutdownDrainsAdmittedHandlersAndRejectsLateWork(t *testing.T) {
	const workers = 128
	entered := make(chan struct{}, workers)
	release := make(chan struct{})
	var completed atomic.Int32
	var closed atomic.Bool
	m := NewTestMosdnsWithPlugins(map[string]any{
		"state": shutdownCloserFunc(func() error {
			if n := completed.Load(); n != workers {
				t.Errorf("checkpoint ran before finalizers completed: %d/%d", n, workers)
			}
			closed.Store(true)
			return nil
		}),
	})
	h := m.TrackDNSHandler(shutdownHandlerFunc(func() {
		entered <- struct{}{}
		<-release
		completed.Add(1)
	}))
	var requests sync.WaitGroup
	for range workers {
		requests.Add(1)
		go func() {
			defer requests.Done()
			h.Handle(context.Background(), nil, server.QueryMeta{}, nil)
		}()
	}
	for range workers {
		<-entered
	}
	// Stop admission atomically while existing TCP/QUIC connections may still
	// deliver more requests. Those requests cannot reach any plugin.
	m.requests.stop()
	done := make(chan error, 1)
	go func() { done <- m.closePlugins(time.Second) }()
	for range workers {
		h.Handle(context.Background(), nil, server.QueryMeta{}, nil)
	}
	if closed.Load() {
		t.Fatal("state closed with active requests")
	}
	close(release)
	requests.Wait()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !closed.Load() || completed.Load() != workers {
		t.Fatal("not all admitted handlers completed")
	}
}

func TestShutdownTimeoutDoesNotPublishCleanState(t *testing.T) {
	var closed atomic.Bool
	m := NewTestMosdnsWithPlugins(map[string]any{"state": shutdownCloserFunc(func() error {
		closed.Store(true)
		return nil
	})})
	if !m.requests.begin() {
		t.Fatal("failed to admit query")
	}
	defer m.requests.end()
	start := time.Now()
	if err := m.closePlugins(10 * time.Millisecond); err == nil {
		t.Fatal("stuck query was reported as clean shutdown")
	}
	if closed.Load() || time.Since(start) > time.Second {
		t.Fatal("timeout must preserve dirty plugin state and return promptly")
	}
}

func TestShutdownIncludesAPIHandlersAndReturnsCloseErrors(t *testing.T) {
	m := NewTestMosdnsWithPlugins(nil)
	entered, release := make(chan struct{}), make(chan struct{})
	h := m.trackHTTPHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	}))
	served := make(chan struct{})
	go func() {
		defer close(served)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}()
	<-entered
	drained := m.requests.stop()
	select {
	case <-drained:
		t.Fatal("active API request escaped drain tracking")
	default:
	}
	rejected := httptest.NewRecorder()
	h.ServeHTTP(rejected, httptest.NewRequest("GET", "/", nil))
	if rejected.Code != http.StatusServiceUnavailable {
		t.Fatal("new API request was admitted during shutdown")
	}
	close(release)
	<-served
	<-drained
	want := errors.New("fsync failed")
	m.plugins = map[string]any{"state": shutdownCloserFunc(func() error { return want })}
	if err := m.closePlugins(time.Second); !errors.Is(err, want) {
		t.Fatalf("checkpoint error was discarded: %v", err)
	}
}
