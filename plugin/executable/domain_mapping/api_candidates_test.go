package domain_mapping

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func longCandidateDomain(i int) string {
	return fmt.Sprintf("n%05d%s.%s.%s.%s", i, strings.Repeat("a", 57), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61))
}

func TestHTTPBoundsThousandsOfLongCandidates(t *testing.T) {
	p, _ := testPlugin(t, Args{})
	const count = 4000
	for i := 0; i < count; i++ {
		domain := longCandidateDomain(i)
		if len(domain) != 253 {
			t.Fatalf("fixture is not a maximum-length domain: %d", len(domain))
		}
		q := testContext(t, domain, "192.168.1.1", dns.TypeA, domain+". 60 IN A 203.0.113.1")
		// Exercise names that really fit in DNS wire format, not oversized strings
		// inserted directly into the observation index.
		if _, err := q.R().Pack(); err != nil {
			t.Fatalf("invalid response fixture: %v", err)
		}
		p.record(q)
	}
	s := httptest.NewServer(p.API())
	t.Cleanup(s.Close)
	for _, suffix := range []string{"", "&client=192.168.1.1"} {
		t.Run(suffix, func(t *testing.T) {
			resp, err := s.Client().Get(s.URL + "/v1/lookup?ip=203.0.113.1" + suffix)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			const providerLimit = 1 << 20
			body, err := io.ReadAll(io.LimitReader(resp.Body, providerLimit+1))
			if err != nil || resp.StatusCode != http.StatusOK || len(body) > providerLimit {
				t.Fatalf("provider cannot consume lookup: status=%d bytes=%d error=%v", resp.StatusCode, len(body), err)
			}
			var got LookupResult
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatal(err)
			}
			if got.Status != "hit" || !got.Conflict || got.Domain != longCandidateDomain(count-1) || len(got.Candidates) != maxLookupCandidates {
				t.Fatalf("bounded result lost selection or conflict: %+v", got)
			}
			for i, candidate := range got.Candidates {
				if candidate.Domain != longCandidateDomain(count-1-i) {
					t.Fatalf("candidate %d is not in recency order: %+v", i, candidate)
				}
			}
			t.Logf("%d domains returned %d diagnostic candidates in %d bytes", count, len(got.Candidates), len(body))
		})
	}
	if got := p.Snapshot(); got.Observations != count || got.ObservationEvicts != 0 {
		t.Fatalf("API limiting changed retained observations: %+v", got)
	}
}

func TestBoundedCandidatesMatchFullCapacityReference(t *testing.T) {
	var index observationIndex
	const size = 65536
	index.init(size)
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr("203.0.113.1")
	// Every domain appears from four different clients. Global lookup must
	// deduplicate them and choose the newest source, regardless of map order.
	for i := 0; i < size; i++ {
		client := netip.AddrFrom4([4]byte{192, 168, 1, byte(i/16384 + 1)})
		domain := fmt.Sprintf("d%05d.example", i%16384)
		source := "a"
		if i >= size/2 {
			source = "https_hint"
		}
		index.put(client, ip, Candidate{Domain: domain, Source: source, ObservedAt: now.Add(time.Duration(i) * time.Nanosecond), ExpiresAt: now.Add(time.Hour)})
	}
	check := func() {
		t.Helper()
		latest := make(map[string]*observation)
		for _, o := range index.records {
			if old := latest[o.Domain]; old == nil || old.sequence < o.sequence {
				latest[o.Domain] = o
			}
		}
		var want []*observation
		for _, o := range latest {
			want = append(want, o)
		}
		sort.Slice(want, func(i, j int) bool { return want[i].sequence > want[j].sequence })
		got := index.candidates(lookupKey{ip: ip})
		if len(got) != min(maxLookupCandidates, len(want)) {
			t.Fatalf("candidate count = %d for %d distinct domains", len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i].Candidate {
				t.Fatalf("candidate %d differs from full reference: got=%+v want=%+v", i, got[i], want[i].Candidate)
			}
		}
		if len(index.records) != len(index.expiry) || len(index.records) != index.order.Len() {
			t.Fatal("candidate selection changed the expiry or observation order index")
		}
		for i, o := range index.expiry {
			if o.heapPos != i {
				t.Fatal("candidate selection modified the expiry heap positions")
			}
		}
	}
	check()
	// Re-observe an older domain and then force one capacity eviction. Its new
	// source must win without changing eviction or expiry bookkeeping.
	index.put(netip.MustParseAddr("192.168.1.1"), ip, Candidate{Domain: "d00000.example", Source: "a", ObservedAt: now.Add(time.Second), ExpiresAt: now.Add(2 * time.Hour)})
	if evicted := index.put(netip.MustParseAddr("192.168.1.5"), ip, Candidate{Domain: "new.example", Source: "a", ObservedAt: now.Add(2 * time.Second), ExpiresAt: now.Add(2 * time.Hour)}); evicted != 1 {
		t.Fatalf("capacity eviction changed: %d", evicted)
	}
	check()
	index.expire(now.Add(time.Hour))
	check()
	index.expire(now.Add(2 * time.Hour))
	check()
}

func TestCandidateLimitDoesNotInventConflictFromDuplicateDomains(t *testing.T) {
	p, now := testPlugin(t, Args{})
	ip := netip.MustParseAddr("203.0.113.1")
	for i := 1; i <= 100; i++ {
		p.index.put(netip.AddrFrom4([4]byte{192, 168, 1, byte(i)}), ip, Candidate{Domain: "same.example", Source: "a", ObservedAt: *now, ExpiresAt: now.Add(time.Minute)})
	}
	if got := p.Lookup(ip, netip.Addr{}); got.Status != "hit" || got.Conflict || len(got.Candidates) != 1 {
		t.Fatalf("duplicate observations became a domain conflict: %+v", got)
	}
}
