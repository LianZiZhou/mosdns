package domain_mapping

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func v3Lookup(t *testing.T, p *DomainMapping, ip, client string) LookupResultV3 {
	t.Helper()
	var addr netip.Addr
	if client != "" {
		addr = netip.MustParseAddr(client)
	}
	got, err := p.LookupV3Context(context.Background(), netip.MustParseAddr(ip), addr)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestV3NativeSizeLatestHintAndClientIsolation(t *testing.T) {
	p, now := testPlugin(t, Args{Routing: RoutingArgs{Size: 2}, Retention: RetentionArgs{Mode: retentionLRU}})
	const ip = "203.0.113.1"
	p.record(clientPool(t, "first.test", "192.168.6.180", 1, ip))
	*now = now.Add(time.Second)
	p.record(clientPool(t, "latest.test", "192.168.6.180", 1, ip))
	p.record(clientPool(t, "other-client.test", "192.168.6.181", 1, ip))
	got := v3Lookup(t, p, ip, "192.168.6.180")
	if got.Status != "hit" || got.Domain != "latest.test" || !reflect.DeepEqual(got.Domains, []string{"first.test", "latest.test"}) {
		t.Fatalf("latest actual DNS did not replace hint: %+v", got)
	}
	if got := v3Lookup(t, p, ip, "192.168.6.182"); got.Status != "miss" {
		t.Fatalf("another client's evidence leaked: %+v", got)
	}
	if got := v3Lookup(t, p, ip, ""); got.Status != "miss" {
		t.Fatalf("client observations leaked into an implicit global cache: %+v", got)
	}
	// Touching .180 makes only that key hot; capacity is two TOTAL, not two
	// per client, not two domains, and not the historical observation limit.
	p.record(clientPool(t, "third-client.test", "192.168.6.182", 1, ip))
	if got := v3Lookup(t, p, ip, "192.168.6.181"); got.Status != "miss" {
		t.Fatal("LRU did not evict the untouched scoped hint")
	}
	if got := v3Lookup(t, p, ip, "192.168.6.180"); got.Domain != "latest.test" {
		t.Fatal("lookup failed to retain the selected hint")
	}
	if len(p.routes.entries) != 2 || len(p.index.records) != 4 || p.routes.evictions != 1 {
		t.Fatal("routing capacity was coupled to the historical index")
	}
	defaults, _ := testPlugin(t, Args{})
	if defaults.args.Routing.Size != 4096 {
		t.Fatalf("native-style default changed: %d", defaults.args.Routing.Size)
	}
}

func TestV3ThirtyDaysOfConnectionsDoNotRenewDNSOrHistoricalBucket(t *testing.T) {
	p, now := testPlugin(t, Args{Retention: RetentionArgs{Mode: retentionLRU}})
	const client, ip = "192.168.6.180", "203.0.113.1"
	p.record(clientPool(t, "old-ai.test", client, 300, ip))
	*now = now.Add(time.Second)
	p.record(clientPool(t, "ordinary.test", client, 300, ip))
	before := make(map[observationKey]Candidate)
	for key, entry := range p.index.records {
		before[key] = entry.Candidate
	}
	for hour := 0; hour < 30*24; hour++ {
		*now = now.Add(time.Hour)
		got := v3Lookup(t, p, ip, client)
		if got.Domain != "ordinary.test" || !got.DNSStale || len(got.Domains) != 0 || !got.CandidatesComplete {
			t.Fatalf("history was renewed by a connection at hour %d: %+v", hour, got)
		}
	}
	for key, entry := range p.index.records {
		if !reflect.DeepEqual(entry.Candidate, before[key]) {
			t.Fatal("v3 touched historical candidate timestamps")
		}
	}
	if p.stats.RetentionRenewals != 0 || p.stats.RetentionTouches != 0 {
		t.Fatal("v3 incorrectly renewed the legacy whole bucket")
	}
}

func TestV3RecentEvidenceBoundsAndTruncationHorizon(t *testing.T) {
	p, now := testPlugin(t, Args{})
	const client, ip = "192.168.6.180", "203.0.113.1"
	for i := 0; i < maxRecentDomains+8; i++ {
		p.record(clientPool(t, fmt.Sprintf("domain-%02d.test", i), client, 1, ip))
	}
	got := v3Lookup(t, p, ip, client)
	if got.Domain != "domain-39.test" || got.CandidatesComplete || len(got.Domains) != 32 || got.Reason != "candidate_limit" {
		t.Fatalf("truncated evidence not explicit: %+v", got)
	}
	*now = now.Add(299 * time.Second)
	if got := v3Lookup(t, p, ip, client); got.CandidatesComplete {
		t.Fatal("lost recent evidence was prematurely called complete")
	}
	*now = now.Add(time.Second)
	got = v3Lookup(t, p, ip, client)
	if !got.CandidatesComplete || len(got.Domains) != 0 || got.Status != "hit" {
		t.Fatalf("expired recent facts permanently poisoned hint: %+v", got)
	}
	if recentWindow(300*time.Second) != 50*time.Minute || recentWindow(0) != 5*time.Minute || recentWindow(365*24*time.Hour) != 24*time.Hour {
		t.Fatal("recent evidence horizon does not use bounded 10x actual DNS TTL")
	}
}

func TestV3RecoveryAliasAndUnknownExposureDoNotOverrideFreshHint(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	const client, ip = "192.168.6.180", "203.0.113.1"
	p.mu.Lock()
	p.clients.guardUntil = time.Now().Add(24 * time.Hour)
	p.clients.incompleteUntil = p.clients.guardUntil
	p.mu.Unlock()
	p.record(testContext(t, "ordinary.test", client, dns.TypeA,
		"ordinary.test. 300 IN CNAME canonical.test.", "canonical.test. 300 IN A 203.0.113.1"))
	legacy := v2Lookup(t, p, ip, client)
	if legacy.Complete {
		t.Fatal("test did not create the legacy incomplete condition")
	}
	got := v3Lookup(t, p, ip, client)
	if got.Status != "hit" || got.Domain != "ordinary.test" || !got.CandidatesComplete || !got.AllocationRecovering || got.Reason != "" {
		t.Fatalf("allocator recovery leaked into v3 routing: %+v", got)
	}
	if got := v3Lookup(t, p, "203.0.113.2", client); got.Status != "miss" || got.Domain != "" {
		t.Fatal("recovery invented a routing identity")
	}
}

func TestV3FinalizedRepliesOnlyAndCancellation(t *testing.T) {
	p, _ := testPlugin(t, Args{})
	const client, ip = "192.168.6.180", "203.0.113.1"
	q := clientPool(t, "not-sent.test", client, 300, ip)
	finish := p.prepare(q)
	if got := v3Lookup(t, p, ip, client); got.Status != "miss" {
		t.Fatal("unencoded response became routing evidence")
	}
	finish(nil)
	if got := v3Lookup(t, p, ip, client); got.Status != "miss" {
		t.Fatal("failed response became routing evidence")
	}
	p.record(q)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	touches := p.routes.touches
	if _, err := p.LookupV3Context(ctx, netip.MustParseAddr(ip), netip.MustParseAddr(client)); err == nil || p.routes.touches != touches {
		t.Fatal("cancelled lookup touched the hint cache")
	}
}

func TestV3HTTPContractAndParameterValidation(t *testing.T) {
	p, _ := testPlugin(t, Args{})
	p.record(clientPool(t, "ordinary.test", "192.168.6.180", 300, "203.0.113.1"))
	r := httptest.NewRecorder()
	p.API().ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/v3/lookup?ip=203.0.113.1&client=192.168.6.180", nil))
	var result map[string]json.RawMessage
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &result) != nil {
		t.Fatalf("invalid v3 response: %d", r.Code)
	}
	if string(result["version"]) != "3" || string(result["status"]) != `"hit"` || result["complete"] != nil || result["expires_at"] != nil {
		t.Fatalf("v3 inherited ambiguous v2 semantics: %s", r.Body.String())
	}
	for _, suffix := range []string{"", "?ip=bad", "?ip=203.0.113.1&ip=203.0.113.2", "?ip=203.0.113.1&client=", "?ip=203.0.113.1&client=192.168.6.180&client=192.168.6.181"} {
		r = httptest.NewRecorder()
		p.API().ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/v3/lookup"+suffix, nil))
		if r.Code != http.StatusBadRequest {
			t.Fatalf("accepted invalid lookup %q: %d", suffix, r.Code)
		}
	}
}
