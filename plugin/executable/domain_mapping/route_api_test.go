package domain_mapping

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func apiJSON(t *testing.T, p *DomainMapping, query string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/lookup?"+query, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRouteViewMatchesFullAcrossIdentityAndExpiry(t *testing.T) {
	p, now := testPlugin(t, Args{})
	p.record(testContext(t, "old.example", "192.168.1.1", dns.TypeA, "old.example. 60 IN A 203.0.113.1"))
	p.record(testContext(t, "global.example", "192.168.1.2", dns.TypeA, "global.example. 60 IN A 203.0.113.1"))
	p.record(testContext(t, "new.example", "192.168.1.1", dns.TypeA, "new.example. 1 IN A 203.0.113.1"))
	for _, elapsed := range []time.Duration{0, 2 * time.Second, time.Minute} {
		*now = now.Add(elapsed)
		for _, suffix := range []string{"", "&client=192.168.1.1", "&client=192.168.1.2", "&client=192.168.1.3"} {
			query := "ip=203.0.113.1" + suffix
			full := apiJSON(t, p, query)
			route := apiJSON(t, p, query+"&view=route")
			if _, exists := route["candidates"]; exists {
				t.Fatal("route view constructed diagnostic candidates")
			}
			if _, exists := full["candidates"]; !exists {
				t.Fatal("default v1 diagnostic contract changed")
			}
			delete(full, "candidates")
			if !reflect.DeepEqual(full, route) {
				t.Fatalf("view disagreement: full=%v route=%v", full, route)
			}
		}
	}
}

func TestRouteViewRejectsInvalidSelector(t *testing.T) {
	p, _ := testPlugin(t, Args{})
	for _, query := range []string{"view=", "view=unknown", "view=route&view=full"} {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/lookup?ip=203.0.113.1&"+query, nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("accepted %s: %d", query, w.Code)
		}
	}
	if got := apiJSON(t, p, "ip=203.0.113.1&view=full"); got["status"] != "miss" {
		t.Fatal(got)
	}
}

func waitAPICondition(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !check() {
		select {
		case <-deadline:
			t.Fatal("API condition did not become true")
		case <-tick.C:
		}
	}
}

func TestAPIAdmissionAndCancellationReleaseLockedWaiter(t *testing.T) {
	p, _ := testPlugin(t, Args{API: APIArgs{MaxConcurrent: 1, Timeout: 5000}})
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		p.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/v1/lookup?ip=203.0.113.1&view=route", nil).WithContext(ctx))
		close(done)
	}()
	waitAPICondition(t, func() bool { return p.apiActive.Load() == 1 })
	second := httptest.NewRecorder()
	p.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/v1/lookup?ip=203.0.113.2", nil))
	if second.Code != http.StatusServiceUnavailable || p.apiRejected.Load() != 1 {
		t.Fatalf("unbounded admission: %d", second.Code)
	}
	// Stats uses the same gate: diagnostics must not bypass admission limits.
	stats := httptest.NewRecorder()
	p.API().ServeHTTP(stats, httptest.NewRequest(http.MethodGet, "/v1/stats", nil))
	if stats.Code != http.StatusServiceUnavailable {
		t.Fatal("stats bypassed admission")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled request remained blocked on index mutex")
	}
	if first.Code != http.StatusServiceUnavailable || p.apiActive.Load() != 0 {
		t.Fatal("cancellation leaked API admission")
	}
}

func TestAPIServerBudgetReleasesLockedWaiter(t *testing.T) {
	p, _ := testPlugin(t, Args{API: APIArgs{Timeout: 10}})
	p.mu.Lock()
	defer p.mu.Unlock()
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/lookup?ip=203.0.113.1&view=route", nil))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server budget failed to bound lock wait")
	}
	if w.Code != http.StatusServiceUnavailable || p.apiTimeouts.Load() != 1 || p.apiActive.Load() != 0 {
		t.Fatalf("budget failure: status=%d timeouts=%d active=%d", w.Code, p.apiTimeouts.Load(), p.apiActive.Load())
	}
}

func TestRouteCancellationInterruptsBatchedExpiry(t *testing.T) {
	p, now := testPlugin(t, Args{})
	ip, client := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("192.168.1.1")
	const count = 4096
	for i := 0; i < count; i++ {
		p.index.put(client, ip, Candidate{Domain: fmt.Sprintf("d%d.example", i), Source: "a", ObservedAt: *now, ExpiresAt: now.Add(time.Second)})
	}
	expired := now.Add(2 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var batches atomic.Int32
	p.now = func() time.Time {
		if batches.Add(1) == 2 {
			cancel()
		}
		return expired
	}
	if _, err := p.LookupRouteContext(ctx, ip, client); !errors.Is(err, context.Canceled) {
		t.Fatalf("query did not stop cleanup: %v", err)
	}
	if remaining := len(p.index.records); remaining == 0 || remaining == count {
		t.Fatalf("cleanup was not bounded in batches: remaining=%d", remaining)
	}
	if got, err := p.LookupRouteContext(context.Background(), ip, client); err != nil || got.Status != "miss" || got.Conflict {
		t.Fatalf("expired state became evidence: %+v %v", got, err)
	}
}

func TestAPILimitValidation(t *testing.T) {
	for _, api := range []APIArgs{{MaxConcurrent: -1}, {Timeout: -1}} {
		if _, err := New(Args{API: api}); err == nil {
			t.Fatalf("accepted invalid API limits: %+v", api)
		}
	}
}

// net.Pipe has no kernel send buffer: a peer that never reads deterministically
// blocks both an in-handler large write and the server's small final flush.
type apiPipeListener struct {
	conn     net.Conn
	accepted atomic.Bool
	closed   chan struct{}
	once     sync.Once
}

func (l *apiPipeListener) Accept() (net.Conn, error) {
	if l.accepted.CompareAndSwap(false, true) {
		return l.conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *apiPipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}
func (l *apiPipeListener) Addr() net.Addr { return l.conn.LocalAddr() }

func TestAPIWriteDeadlineReleasesSlowReaders(t *testing.T) {
	for _, view := range []string{"full", "route"} {
		t.Run(view, func(t *testing.T) {
			p, now := testPlugin(t, Args{API: APIArgs{Timeout: 50, MaxConcurrent: 1}})
			ip := netip.MustParseAddr("203.0.113.1")
			for i := 0; i < 32; i++ {
				p.index.put(netip.Addr{}, ip, Candidate{Domain: fmt.Sprintf("d%d.%s.example", i, strings.Repeat("x", 60)), Source: "a", ObservedAt: *now, ExpiresAt: now.Add(time.Minute)})
			}
			serverConn, clientConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			listener := &apiPipeListener{conn: serverConn, closed: make(chan struct{})}
			closed := make(chan struct{})
			server := &http.Server{Handler: p.API(), ConnState: func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					close(closed)
				}
			}}
			defer server.Close()
			go server.Serve(listener)
			if _, err := fmt.Fprintf(clientConn, "GET /v1/lookup?ip=203.0.113.1&view=%s HTTP/1.1\r\nHost: localhost\r\n\r\n", view); err != nil {
				t.Fatal(err)
			}
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("non-reading client kept response write alive after deadline")
			}
			if p.apiActive.Load() != 0 {
				t.Fatal("slow reader leaked admission")
			}
			if view == "full" && p.apiTimeouts.Load() != 1 {
				t.Fatal("handler write timeout was not counted")
			}
		})
	}
}

func TestAPIWriteDeadlineDoesNotPoisonKeepAlive(t *testing.T) {
	p, _ := testPlugin(t, Args{API: APIArgs{Timeout: 50}})
	server := httptest.NewUnstartedServer(p.API())
	var connections atomic.Int32
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	for i := 0; i < 2; i++ {
		resp, err := server.Client().Get(server.URL + "/v1/lookup?ip=203.0.113.1&view=route")
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		err = json.NewDecoder(resp.Body).Decode(&value)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || value["status"] != "miss" {
			t.Fatalf("keep-alive lookup failed: %+v %v", value, err)
		}
		if i == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if connections.Load() != 1 {
		t.Fatal("response deadline prevented connection reuse")
	}
}
