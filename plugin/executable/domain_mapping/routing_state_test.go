package domain_mapping

import (
	"fmt"
	"testing"
	"time"
)

func TestRoutingRestartPreservesSmallLRUEvictionAndAccessOrder(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	p.args.Routing.Size = 2
	p.routes.init(2)
	const client = "192.168.6.180"
	p.record(clientPool(t, "first.test", client, 300, "203.0.113.1"))
	p.record(clientPool(t, "second.test", client, 300, "203.0.113.2"))
	v3Lookup(t, p, "203.0.113.1", client) // first is hot, despite older DNS time
	p.record(clientPool(t, "third.test", client, 300, "203.0.113.3"))
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	q, err := New(p.args)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if got := v3Lookup(t, q, "203.0.113.2", client); got.Status != "miss" {
		t.Fatalf("restart resurrected an evicted hint from retained history: %+v", got)
	}
	if got := v3Lookup(t, q, "203.0.113.1", client); got.Domain != "first.test" {
		t.Fatal("restart chose recent historical DNS instead of actual LRU contents")
	}
	if len(q.index.records) != 3 || len(q.routes.entries) != 2 {
		t.Fatal("separate history and routing capacities did not survive restart")
	}
}

func TestRoutingRestartPreservesRecentTruncationAndEmptyCache(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	const client, ip = "192.168.6.180", "203.0.113.1"
	for i := 0; i < 40; i++ {
		p.record(clientPool(t, fmt.Sprintf("domain-%02d.test", i), client, 300, ip))
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	q, err := New(p.args)
	if err != nil {
		t.Fatal(err)
	}
	got := v3Lookup(t, q, ip, client)
	if got.CandidatesComplete || got.Reason != "candidate_limit" || len(got.Domains) != 32 {
		t.Fatalf("restart certified a truncated recent set: %+v", got)
	}
	q.mu.Lock()
	q.routes.init(q.args.Routing.Size)
	q.mu.Unlock()
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := New(q.args)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got := v3Lookup(t, r, ip, client); got.Status != "miss" {
		t.Fatal("explicit empty v3 cache was treated as legacy history migration")
	}
}

func TestRoutingPersistedEvidenceRejectsUnboundedOrInventedRecentFacts(t *testing.T) {
	p, now := testPlugin(t, Args{})
	base := stateRoutingHint{Client: "192.168.6.180", IP: "203.0.113.1", Domain: "ordinary.test", Source: "a", ObservedAt: *now, DNSExpiresAt: now.Add(time.Minute)}
	for _, bad := range []stateRoutingHint{
		func() stateRoutingHint { r := base; r.TruncatedUntil = now.Add(25 * time.Hour); return r }(),
		func() stateRoutingHint {
			r := base
			r.Recent = []stateRecentDomain{{Domain: "future.test", ObservedAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour)}}
			return r
		}(),
		func() stateRoutingHint { r := base; r.Recent = make([]stateRecentDomain, 33); return r }(),
	} {
		if err := p.restoreRouting([]stateRoutingHint{bad}); err == nil {
			t.Fatal("corrupt persisted evidence accepted")
		}
	}
}
