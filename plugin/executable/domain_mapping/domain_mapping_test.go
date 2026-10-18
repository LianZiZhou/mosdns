package domain_mapping

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	cacheplugin "github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func testPlugin(t *testing.T, args Args) (*DomainMapping, *time.Time) {
	t.Helper()
	p, err := New(args)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	return p, &now
}

// record models an immediately finalized response for package-level tests.
// Production execution always waits for EntryHandler's final encoding hook.
func (p *DomainMapping) record(qCtx *query_context.Context) {
	if finalize := p.prepare(qCtx); finalize != nil {
		finalize(qCtx.R())
	}
}

func testContext(t *testing.T, name, client string, typ uint16, records ...string) *query_context.Context {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), typ)
	qCtx := query_context.NewContext(q)
	if client != "" {
		qCtx.ServerMeta.ClientAddr = netip.MustParseAddr(client)
	}
	r := new(dns.Msg)
	r.SetReply(q)
	for _, record := range records {
		rr, err := dns.NewRR(record)
		if err != nil {
			t.Fatal(err)
		}
		r.Answer = append(r.Answer, rr)
	}
	qCtx.SetResponse(r)
	return qCtx
}

func lookup(p *DomainMapping, ip, client string) LookupResult {
	var clientIP netip.Addr
	if client != "" {
		clientIP = netip.MustParseAddr(client)
	}
	return p.Lookup(netip.MustParseAddr(ip), clientIP)
}

func TestClientPriorityConflictAndExpiry(t *testing.T) {
	p, now := testPlugin(t, Args{})
	p.record(testContext(t, "First.Example", "192.168.1.2", dns.TypeA, "First.Example. 10 IN A 203.0.113.1"))
	*now = now.Add(time.Second)
	p.record(testContext(t, "second.example", "192.168.1.3", dns.TypeA, "second.example. 20 IN A 203.0.113.1"))
	if got := lookup(p, "203.0.113.1", "192.168.1.2"); got.Domain != "first.example" || got.Scope != "client" || got.Conflict {
		t.Fatalf("client priority: %+v", got)
	}
	if got := lookup(p, "203.0.113.1", "192.168.1.4"); got.Domain != "second.example" || got.Scope != "global" || !got.Conflict || len(got.Candidates) != 2 {
		t.Fatalf("global fallback: %+v", got)
	}
	*now = now.Add(time.Second)
	p.record(testContext(t, "third.example", "192.168.1.2", dns.TypeA, "third.example. 1 IN A 203.0.113.1"))
	if got := lookup(p, "203.0.113.1", "192.168.1.2"); got.Domain != "third.example" || !got.Conflict {
		t.Fatalf("same-client conflict: %+v", got)
	}
	*now = now.Add(time.Second)
	if got := lookup(p, "203.0.113.1", "192.168.1.2"); got.Domain != "first.example" || got.Conflict {
		t.Fatalf("expired candidate: %+v", got)
	}
	*now = now.Add(18 * time.Second)
	if got := lookup(p, "203.0.113.1", ""); got.Status != "miss" || len(got.Candidates) != 0 {
		t.Fatalf("expired mapping: %+v", got)
	}
}

func TestCNAMEChainTTLAndUnrelatedRecords(t *testing.T) {
	p, now := testPlugin(t, Args{})
	p.record(testContext(t, "original.example", "192.168.1.2", dns.TypeA,
		"endpoint.example. 100 IN A 203.0.113.1",
		"alias.example. 7 IN CNAME endpoint.example.",
		"original.example. 60 IN CNAME alias.example.",
		"unrelated.example. 60 IN A 203.0.113.2"))
	got := lookup(p, "203.0.113.1", "192.168.1.2")
	if got.Domain != "original.example" || got.Source != "a" || !got.ExpiresAt.Equal(now.Add(7*time.Second)) {
		t.Fatalf("CNAME association: %+v", got)
	}
	if got := lookup(p, "203.0.113.2", ""); got.Status != "miss" {
		t.Fatalf("unrelated record leaked: %+v", got)
	}
	*now = now.Add(7 * time.Second)
	if got := lookup(p, "203.0.113.1", ""); got.Status != "miss" {
		t.Fatalf("CNAME TTL not respected: %+v", got)
	}
}

func TestHTTPSHintsAndIPv6(t *testing.T) {
	p, now := testPlugin(t, Args{})
	qCtx := testContext(t, "service.example", "2001:db8::1", dns.TypeHTTPS,
		`service.example. 20 IN HTTPS 1 . alpn="h2,h3" ipv4hint=203.0.113.1 ipv6hint=2001:db8::10 ech=AQIDBA==`)
	before := qCtx.R().String()
	p.record(qCtx)
	for _, ip := range []string{"203.0.113.1", "2001:db8::10"} {
		got := lookup(p, ip, "2001:db8::1")
		if got.Domain != "service.example" || got.Source != "https_hint" || !got.ExpiresAt.Equal(now.Add(20*time.Second)) {
			t.Fatalf("hint association: %+v", got)
		}
	}
	if before != qCtx.R().String() {
		t.Fatal("HTTPS parameters were modified")
	}
	p.record(testContext(t, "v6.example", "192.168.1.2", dns.TypeAAAA, "v6.example. 60 IN AAAA 2001:db8::20"))
	if got := lookup(p, "2001:db8::20", "2001:db8::2"); got.Domain != "v6.example" || got.Scope != "global" {
		t.Fatalf("cross-family global fallback: %+v", got)
	}
}

func TestSVCBAliasTTLAndDuplicateEvidence(t *testing.T) {
	p, now := testPlugin(t, Args{})
	p.record(testContext(t, "service.test", "", dns.TypeSVCB,
		"service.test. 10 IN SVCB 0 endpoint.test.",
		"endpoint.test. 60 IN SVCB 1 . ipv4hint=203.0.113.1"))
	if got := lookup(p, "203.0.113.1", ""); got.Domain != "service.test" || got.Source != "svcb_hint" || !got.ExpiresAt.Equal(now.Add(10*time.Second)) {
		t.Fatalf("SVCB alias: %+v", got)
	}
	p.record(testContext(t, "duplicate.test", "", dns.TypeA,
		"duplicate.test. 10 IN A 203.0.113.2", "duplicate.test. 60 IN A 203.0.113.2"))
	if got := lookup(p, "203.0.113.2", ""); !got.ExpiresAt.Equal(now.Add(10 * time.Second)) {
		t.Fatalf("duplicate TTL was extended: %+v", got)
	}
}

func TestBoundedIndexAndRepeatedObservation(t *testing.T) {
	p, now := testPlugin(t, Args{Size: 2})
	p.record(testContext(t, "one.example", "192.168.1.1", dns.TypeA, "one.example. 60 IN A 203.0.113.1"))
	*now = now.Add(time.Second)
	p.record(testContext(t, "one.example", "192.168.1.1", dns.TypeA, "one.example. 1 IN A 203.0.113.1"))
	if got := lookup(p, "203.0.113.1", ""); !got.ExpiresAt.Equal(now.Add(59 * time.Second)) {
		t.Fatalf("earlier valid client cache forgotten: %+v", got)
	}
	p.record(testContext(t, "two.example", "192.168.1.1", dns.TypeA, "two.example. 60 IN A 203.0.113.2"))
	p.record(testContext(t, "three.example", "192.168.1.1", dns.TypeA, "three.example. 60 IN A 203.0.113.3"))
	if got := lookup(p, "203.0.113.1", ""); got.Status != "miss" {
		t.Fatalf("oldest observation not evicted: %+v", got)
	}
	if s := p.Snapshot(); s.Observations != 2 || s.ObservationEvicts != 1 || len(p.index.expiry) != 2 {
		t.Fatalf("unbounded index: %+v", s)
	}
}

func TestHTTPContract(t *testing.T) {
	p, _ := testPlugin(t, Args{})
	p.record(testContext(t, "example.test", "192.168.1.1", dns.TypeA, "example.test. 60 IN A 203.0.113.1"))
	for _, test := range []struct {
		url    string
		status int
	}{
		{"/v1/lookup?ip=203.0.113.1&client=192.168.1.1", 200},
		{"/v1/lookup?ip=203.0.113.2", 200},
		{"/v1/lookup", 400},
		{"/v1/lookup?ip=invalid", 400},
		{"/v1/lookup?ip=203.0.113.1&client=", 400},
		{"/v1/lookup?ip=203.0.113.1&client=bad", 400},
		{"/v1/lookup?ip=fe80::1%25eth0", 400},
		{"/v1/stats", 200},
	} {
		t.Run(test.url, func(t *testing.T) {
			w := httptest.NewRecorder()
			p.API().ServeHTTP(w, httptest.NewRequest(http.MethodGet, test.url, nil))
			if w.Code != test.status {
				t.Fatalf("code = %d, body = %s", w.Code, w.Body)
			}
			if test.status == 200 {
				var decoded map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
					t.Fatal(err)
				}
				if _, ok := decoded["status"]; ok && decoded["version"] != float64(1) {
					t.Fatalf("wrong version: %v", decoded)
				}
			}
		})
	}
}

func TestOuterCacheRecordsEveryClientAndKeepsFullCandidates(t *testing.T) {
	p, _ := testPlugin(t, Args{Allocation: AllocationArgs{Enable: true}})
	c := cacheplugin.NewCache(&cacheplugin.Args{}, cacheplugin.Opts{})
	t.Cleanup(func() { _ = c.Close() })
	var upstreamCalls int
	chain := []*sequence.ChainNode{{RE: p}, {RE: c}, {E: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
		if q.R() != nil {
			if len(q.R().Answer) != 2 {
				t.Fatal("allocation changed the shared DNS cache")
			}
			return nil
		}
		upstreamCalls++
		r := testContext(t, "example.test", "", dns.TypeA, "example.test. 60 IN A 203.0.113.1", "example.test. 60 IN A 203.0.113.2").R()
		q.SetResponse(r)
		return nil
	})}}
	for _, client := range []string{"192.168.1.1", "192.168.1.2"} {
		q := testContext(t, "example.test", client, dns.TypeA)
		q.SetResponse(nil)
		walker := sequence.NewChainWalker(chain, nil)
		if err := walker.ExecNext(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		q.FinalizeResponse(q.R())
		if len(q.R().Answer) != 1 {
			t.Fatal("allocation did not filter client response")
		}
		if got := lookup(p, "203.0.113.1", client); got.Scope != "client" {
			t.Fatalf("cache client not recorded: %+v", got)
		}
	}
	if upstreamCalls != 1 {
		t.Fatalf("cache missed: upstream called %d times", upstreamCalls)
	}
}

func TestLazyCacheRecordsOnlyReturnedAnswer(t *testing.T) {
	p, _ := testPlugin(t, Args{})
	c := cacheplugin.NewCache(&cacheplugin.Args{LazyCacheTTL: 60}, cacheplugin.Opts{})
	t.Cleanup(func() { _ = c.Close() })
	var upstreamCalls atomic.Int32
	refreshed := make(chan struct{})
	chain := []*sequence.ChainNode{{RE: p}, {RE: c}, {E: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
		if q.R() != nil {
			return nil
		}
		record := "example.test. 1 IN A 203.0.113.1"
		if upstreamCalls.Add(1) > 1 {
			record = "example.test. 60 IN A 203.0.113.2"
			defer close(refreshed)
		}
		q.SetResponse(testContext(t, "example.test", "", dns.TypeA, record).R())
		return nil
	})}}
	run := func(client string) {
		q := testContext(t, "example.test", client, dns.TypeA)
		q.SetResponse(nil)
		walker := sequence.NewChainWalker(chain, nil)
		if err := walker.ExecNext(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		q.FinalizeResponse(q.R())
	}
	run("192.168.1.1")
	time.Sleep(1100 * time.Millisecond)
	run("192.168.1.2")
	select {
	case <-refreshed:
	case <-time.After(time.Second):
		t.Fatal("lazy refresh did not run")
	}
	if got := lookup(p, "203.0.113.1", "192.168.1.2"); got.Scope != "client" || got.ExpiresAt.Sub(*got.ObservedAt) != 5*time.Second {
		t.Fatalf("lazy response not recorded: %+v", got)
	}
	if got := lookup(p, "203.0.113.2", ""); got.Status != "miss" {
		t.Fatalf("background refresh recorded before client receives it: %+v", got)
	}
}

func TestFailedSequenceDoesNotRecord(t *testing.T) {
	p, _ := testPlugin(t, Args{})
	q := testContext(t, "example.test", "", dns.TypeA, "example.test. 60 IN A 203.0.113.1")
	walker := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(context.Context, *query_context.Context) error {
		return errors.New("upstream failed")
	})}}, nil)
	if err := p.Exec(context.Background(), q, walker); err == nil {
		t.Fatal("error not propagated")
	}
	if got := lookup(p, "203.0.113.1", ""); got.Status != "miss" {
		t.Fatalf("failed sequence recorded: %+v", got)
	}
}
