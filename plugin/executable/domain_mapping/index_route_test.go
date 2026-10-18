package domain_mapping

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"testing"
	"time"
)

func TestRouteIndexMatchesIndependentReference(t *testing.T) {
	const capacity = 31
	var index observationIndex
	index.init(capacity)
	type referenceObservation struct {
		candidate Candidate
		sequence  int
	}
	reference := make(map[observationKey]referenceObservation)
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	clients := []netip.Addr{{}, netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("2001:db8::1")}
	ips := []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("2001:db8::10")}
	random := rand.New(rand.NewSource(79))
	for step := 1; step <= 3000; step++ {
		now = now.Add(time.Duration(random.Intn(3)) * time.Second)
		// The model expires everything. The real index may leave an expiry
		// backlog after bounded maintenance before accepting the next write.
		for key, record := range reference {
			if !now.Before(record.candidate.ExpiresAt) {
				delete(reference, key)
			}
		}
		index.expireBatch(now, random.Intn(3))
		key := observationKey{
			lookupKey: lookupKey{client: clients[random.Intn(len(clients))], ip: ips[random.Intn(len(ips))]},
			domain:    fmt.Sprintf("d%02d.example", random.Intn(12)), source: []string{"a", "https_hint"}[random.Intn(2)],
		}
		candidate := Candidate{Domain: key.domain, Source: key.source, ObservedAt: now, ExpiresAt: now.Add(time.Duration(1+random.Intn(80)) * time.Second)}
		var wantEvictions uint64
		if old, found := reference[key]; found {
			if candidate.ExpiresAt.Before(old.candidate.ExpiresAt) {
				candidate.ExpiresAt = old.candidate.ExpiresAt
			}
		} else if len(reference) == capacity {
			var oldest observationKey
			oldestSequence := step
			for k, record := range reference {
				if record.sequence < oldestSequence {
					oldest, oldestSequence = k, record.sequence
				}
			}
			delete(reference, oldest)
			wantEvictions = 1
		}
		reference[key] = referenceObservation{candidate: candidate, sequence: step}
		if got := index.put(key.client, key.ip, candidate); got != wantEvictions {
			t.Fatalf("step %d: evictions = %d, want %d", step, got, wantEvictions)
		}
		index.expire(now)
		if len(index.records) != len(reference) || len(index.expiry) != len(reference) || index.order.Len() != len(reference) {
			t.Fatalf("step %d: record, heap or order count differs from reference", step)
		}
		for _, client := range clients {
			for _, ip := range ips {
				lookup := lookupKey{client: client, ip: ip}
				latestByDomain := make(map[string]referenceObservation)
				for k, record := range reference {
					if k.ip != ip || (client.IsValid() && k.client != client) {
						continue
					}
					if old, found := latestByDomain[k.domain]; !found || record.sequence > old.sequence {
						latestByDomain[k.domain] = record
					}
				}
				var want []referenceObservation
				for _, record := range latestByDomain {
					want = append(want, record)
				}
				sort.Slice(want, func(i, j int) bool { return want[i].sequence > want[j].sequence })
				selected, conflict, found := index.route(lookup)
				if found != (len(want) > 0) || conflict != (len(want) > 1) || (found && selected != want[0].candidate) {
					t.Fatalf("step %d %v: selection=%+v conflict=%t found=%t reference=%+v", step, lookup, selected, conflict, found, want)
				}
				candidates := index.candidates(lookup)
				if len(candidates) != min(maxLookupCandidates, len(want)) {
					t.Fatalf("step %d: candidate count %d differs from %d", step, len(candidates), len(want))
				}
				for i, got := range candidates {
					if got != want[i].candidate {
						t.Fatalf("step %d: diagnostic candidate %d differs from reference", step, i)
					}
				}
				bucket := index.buckets[lookup]
				if len(want) == 0 {
					if bucket != nil {
						t.Fatalf("step %d: empty bucket retained", step)
					}
					continue
				}
				counts := make(map[string]int)
				for e := bucket.order.Front(); e != nil; e = e.Next() {
					counts[e.Value.(*observation).Domain]++
				}
				if len(counts) != len(bucket.domains) {
					t.Fatalf("step %d: distinct domain counts diverged", step)
				}
				for domain, count := range counts {
					if count != bucket.domains[domain] {
						t.Fatalf("step %d: domain %q reference count diverged", step, domain)
					}
				}
			}
		}
	}
}

func TestRouteExpiryBatchBoundsWorkAndReclaimsExpiredCapacity(t *testing.T) {
	var index observationIndex
	index.init(300)
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr("203.0.113.1")
	client := netip.MustParseAddr("192.168.1.1")
	index.put(client, ip, Candidate{Domain: "live.example", Source: "a", ObservedAt: now, ExpiresAt: now.Add(time.Hour)})
	for i := 1; i < 300; i++ {
		index.put(client, ip, Candidate{Domain: fmt.Sprintf("d%d.example", i), Source: "a", ObservedAt: now, ExpiresAt: now.Add(time.Second)})
	}
	now = now.Add(2 * time.Second)
	// Even without maintenance, a capacity-pressure write must not evict the
	// oldest live record while an expired observation still occupies a slot.
	if evicted := index.put(client, ip, Candidate{Domain: "new.example", Source: "a", ObservedAt: now, ExpiresAt: now.Add(time.Hour)}); evicted != 0 {
		t.Fatal("expired capacity reclamation was counted as a live eviction")
	}
	if complete := index.expireBatch(now, 128); complete || len(index.records) != 172 {
		t.Fatalf("expiry batch removed more or fewer than 128 entries: complete=%t records=%d", complete, len(index.records))
	}
	if complete := index.expireBatch(now, 128); complete || len(index.records) != 44 {
		t.Fatalf("second expiry batch has wrong boundary: complete=%t records=%d", complete, len(index.records))
	}
	if complete := index.expireBatch(now, 128); !complete || len(index.records) != 2 {
		t.Fatalf("last expiry batch did not finish: complete=%t records=%d", complete, len(index.records))
	}
	selected, conflict, found := index.route(lookupKey{client: client, ip: ip})
	if !found || !conflict || selected.Domain != "new.example" {
		t.Fatalf("expiry lost the newest live selection or the older live conflict: %+v %t %t", selected, conflict, found)
	}
	if got := index.candidates(lookupKey{ip: ip}); len(got) != 2 || got[1].Domain != "live.example" {
		t.Fatalf("live oldest observation was evicted: %+v", got)
	}
}

type cancelDuringDiagnosticWalk struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *cancelDuringDiagnosticWalk) Err() error {
	c.checks++
	if c.checks == 3 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestCandidateDiagnosticsObserveCancellationDuringDuplicateWalk(t *testing.T) {
	var index observationIndex
	index.init(513)
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr("203.0.113.1")
	index.put(netip.Addr{}, ip, Candidate{Domain: "old.example", Source: "a", ObservedAt: now, ExpiresAt: now.Add(time.Hour)})
	for i := 1; i <= 512; i++ {
		client := netip.AddrFrom4([4]byte{192, 168, byte(i >> 8), byte(i)})
		index.put(client, ip, Candidate{Domain: "repeated.example", Source: "a", ObservedAt: now, ExpiresAt: now.Add(time.Hour)})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checked := &cancelDuringDiagnosticWalk{Context: ctx, cancel: cancel}
	if got, err := index.candidatesContext(checked, lookupKey{ip: ip}); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("cancelled diagnostics returned a partial result: %+v, %v", got, err)
	}
	if selected, conflict, found := index.route(lookupKey{ip: ip}); !found || !conflict || selected.Domain != "repeated.example" {
		t.Fatal("cancelling a diagnostic read modified the index")
	}
}

func BenchmarkRouteIndex(b *testing.B) {
	for _, count := range []int{32, 4000, 65536} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			var index observationIndex
			index.init(count)
			now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
			key := lookupKey{client: netip.MustParseAddr("192.168.1.1"), ip: netip.MustParseAddr("203.0.113.1")}
			for i := 0; i < count; i++ {
				index.put(key.client, key.ip, Candidate{Domain: fmt.Sprintf("d%d.example", i), Source: "a", ObservedAt: now, ExpiresAt: now.Add(time.Hour)})
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, conflict, found := index.route(key); !found || !conflict {
					b.Fatal("unexpected route result")
				}
			}
		})
	}
}

var benchmarkLookupResult LookupResult

func benchmarkLookupFixture(b *testing.B, count int) (*DomainMapping, netip.Addr, netip.Addr) {
	b.Helper()
	p, err := New(Args{Size: count})
	if err != nil {
		b.Fatal(err)
	}
	ip, client := netip.MustParseAddr("203.0.113.8"), netip.MustParseAddr("192.168.1.12")
	now := time.Now().UTC()
	for i := 0; i < count; i++ {
		p.index.put(client, ip, Candidate{
			Domain: fmt.Sprintf("host-%05d.bridge.example", i), Source: "a",
			ObservedAt: now, ExpiresAt: now.Add(time.Hour),
		})
	}
	return p, ip, client
}

// These benchmarks include lock acquisition, the real clock/expiry check, and
// construction of the exported result. HTTP transport and JSON are excluded.
func BenchmarkLookupRouteContext(b *testing.B) {
	for _, count := range []int{32, 4000, 65536} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			p, ip, client := benchmarkLookupFixture(b, count)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			b.ReportAllocs()
			for b.Loop() {
				result, err := p.LookupRouteContext(ctx, ip, client)
				if err != nil || result.Status != "hit" || !result.Conflict {
					b.Fatalf("unexpected route lookup: %+v %v", result, err)
				}
				benchmarkLookupResult = result
			}
		})
	}
}

func BenchmarkLookupFull(b *testing.B) {
	for _, count := range []int{32, 4000, 65536} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			p, ip, client := benchmarkLookupFixture(b, count)
			b.ReportAllocs()
			for b.Loop() {
				result := p.Lookup(ip, client)
				if result.Status != "hit" || !result.Conflict || len(result.Candidates) != maxLookupCandidates {
					b.Fatalf("unexpected full lookup: %+v", result)
				}
				benchmarkLookupResult = result
			}
		})
	}
}
