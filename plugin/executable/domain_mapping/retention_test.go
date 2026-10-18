package domain_mapping

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func retentionRoute(t *testing.T, p *DomainMapping, ip, client string) LookupResult {
	t.Helper()
	var addr netip.Addr
	if client != "" {
		addr = netip.MustParseAddr(client)
	}
	result, err := p.LookupRouteContext(context.Background(), netip.MustParseAddr(ip), addr)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func retentionRecord(t *testing.T, p *DomainMapping, domain, client, ip string, ttl uint32) {
	t.Helper()
	p.record(testContext(t, domain, client, dns.TypeA, fmt.Sprintf("%s. %d IN A %s", domain, ttl, ip)))
}

func TestRetentionConfiguration(t *testing.T) {
	for _, mode := range []string{"", "ttl", "sliding", "lru"} {
		p, err := New(Args{Retention: RetentionArgs{Mode: mode}})
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		size := 65536
		if mode == "sliding" || mode == "lru" {
			size = 262144
		}
		if p.args.Size != size || p.args.Retention.TTLMultiplier != 10 || p.args.Retention.MinWindow != 300 || p.args.Retention.MaxWindow != 86400 {
			t.Fatalf("mode %q defaults: %+v", mode, p.args)
		}
	}
	maxInt := int(^uint(0) >> 1)
	invalid := []RetentionArgs{
		{Mode: "invalid"}, {TTLMultiplier: -1}, {MinWindow: -1}, {MaxWindow: -1},
		{MinWindow: 600, MaxWindow: 300},
	}
	if int64(maxInt) > int64((1<<63-1)/time.Second) {
		invalid = append(invalid, RetentionArgs{TTLMultiplier: maxInt}, RetentionArgs{MinWindow: maxInt}, RetentionArgs{MaxWindow: maxInt})
	}
	for _, r := range invalid {
		if _, err := New(Args{Retention: r}); err == nil {
			t.Fatalf("accepted invalid retention: %+v", r)
		}
	}
	for _, mode := range []string{"sliding", "lru"} {
		if _, err := New(Args{Allocation: AllocationArgs{Enable: true}, Retention: RetentionArgs{Mode: mode}}); err == nil {
			t.Fatalf("accepted allocation with %s retention", mode)
		}
		p, err := New(Args{Size: 42, Retention: RetentionArgs{Mode: mode, TTLMultiplier: 10}})
		if err != nil || p.args.Size != 42 {
			t.Fatalf("explicit size/multiplier: p=%+v, err=%v", p, err)
		}
	}
}

func TestRetentionSlidingWindow(t *testing.T) {
	for _, tt := range []struct {
		ttl    uint32
		window time.Duration
	}{{5, 300 * time.Second}, {300, 3000 * time.Second}, {^uint32(0), 86400 * time.Second}} {
		t.Run(fmt.Sprint(tt.ttl), func(t *testing.T) {
			p, now := testPlugin(t, Args{Retention: RetentionArgs{Mode: "sliding"}})
			start := *now
			retentionRecord(t, p, "test.example", "192.168.1.1", "203.0.113.1", tt.ttl)
			initial := lookup(p, "203.0.113.1", "192.168.1.1")
			if !initial.ExpiresAt.Equal(start.Add(tt.window)) || !initial.DNSExpiresAt.Equal(start.Add(time.Duration(tt.ttl)*time.Second)) {
				t.Fatalf("wrong initial lease/DNS expiry: %+v", initial)
			}
			for range 3 {
				*now = now.Add(tt.window / 2)
				got := retentionRoute(t, p, "203.0.113.1", "192.168.1.1")
				if got.Status != "hit" || !got.ExpiresAt.Equal(now.Add(tt.window)) || !got.ObservedAt.Equal(start) || !got.DNSExpiresAt.Equal(*initial.DNSExpiresAt) {
					t.Fatalf("route failed to slide independently of DNS: %+v", got)
				}
			}
			if got := p.Snapshot(); got.RetentionRenewals != 3 || got.RetentionTouches != 3 {
				t.Fatalf("renewal counters: %+v", got)
			}
			*now = now.Add(tt.window)
			if got := retentionRoute(t, p, "203.0.113.1", "192.168.1.1"); got.Status != "miss" {
				t.Fatalf("idle sliding lease survived: %+v", got)
			}
		})
	}
}

func TestRetentionLRUColdEvidenceAndStrictTTL(t *testing.T) {
	for _, mode := range []string{"ttl", "sliding", "lru"} {
		t.Run(mode, func(t *testing.T) {
			p, now := testPlugin(t, Args{Retention: RetentionArgs{Mode: mode}})
			retentionRecord(t, p, "cold.example", "192.168.1.1", "203.0.113.1", 5)
			*now = now.Add(48 * time.Hour)
			got := retentionRoute(t, p, "203.0.113.1", "192.168.1.1")
			if mode == "lru" {
				if got.Status != "hit" || !got.DNSStale || got.RetentionMode != mode || !got.ExpiresAt.After(*now) {
					t.Fatalf("LRU cold evidence lost: %+v", got)
				}
				if len(p.index.expiry) != 0 {
					t.Fatal("LRU allocated an expiry heap")
				}
			} else if got.Status != "miss" {
				t.Fatalf("expired evidence survived in %s: %+v", mode, got)
			}
		})
	}
}

func TestRetentionTTLZeroAndLegacyWire(t *testing.T) {
	for _, mode := range []string{"ttl", "sliding", "lru"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := testPlugin(t, Args{Retention: RetentionArgs{Mode: mode}})
			retentionRecord(t, p, "zero.example", "192.168.1.1", "203.0.113.1", 0)
			got := retentionRoute(t, p, "203.0.113.1", "192.168.1.1")
			if mode == "ttl" {
				if got.Status != "miss" {
					t.Fatalf("strict mode retained zero TTL: %+v", got)
				}
				retentionRecord(t, p, "live.example", "192.168.1.1", "203.0.113.1", 5)
				for _, value := range []any{lookup(p, "203.0.113.1", "192.168.1.1"), p.Snapshot()} {
					wire, err := json.Marshal(value)
					if err != nil {
						t.Fatal(err)
					}
					for _, field := range []string{"dns_expires_at", "dns_stale", "retention_", "observation_capacity"} {
						if strings.Contains(string(wire), field) {
							t.Fatalf("legacy wire changed: %s", wire)
						}
					}
				}
			} else if got.Status != "hit" || !got.DNSStale {
				t.Fatalf("zero TTL evidence missing: %+v", got)
			}
		})
	}
}

func TestRetentionShortDNSAnswerDoesNotShrinkWindow(t *testing.T) {
	for _, mode := range []string{"sliding", "lru"} {
		t.Run(mode, func(t *testing.T) {
			p, now := testPlugin(t, Args{Retention: RetentionArgs{Mode: mode}})
			retentionRecord(t, p, "lazy.example", "192.168.1.1", "203.0.113.1", 300)
			*now = now.Add(10 * time.Second)
			retentionRecord(t, p, "lazy.example", "192.168.1.1", "203.0.113.1", 5)
			dnsObserved := *now
			*now = now.Add(20 * time.Second)
			got := retentionRoute(t, p, "203.0.113.1", "192.168.1.1")
			if !got.ExpiresAt.Equal(now.Add(3000*time.Second)) || !got.DNSExpiresAt.Equal(dnsObserved.Add(5*time.Second)) || !got.DNSStale {
				t.Fatalf("lazy answer shrank remembered TTL or altered DNS timestamp: %+v", got)
			}
			// Even a backward clock step or earlier request cannot shorten
			// an already granted routing lease.
			longExpiry := *got.ExpiresAt
			*now = now.Add(-time.Second)
			if got := retentionRoute(t, p, "203.0.113.1", "192.168.1.1"); !got.ExpiresAt.Equal(longExpiry) {
				t.Fatalf("lease shortened: %+v", got)
			}
		})
	}
}

func TestRetentionAccessLRUPreservesDNSOwnership(t *testing.T) {
	p, now := testPlugin(t, Args{Size: 3, Retention: RetentionArgs{Mode: "lru"}})
	retentionRecord(t, p, "old.example", "192.168.1.1", "203.0.113.1", 5)
	oldObserved := *now
	*now = now.Add(time.Second)
	retentionRecord(t, p, "new.example", "192.168.1.2", "203.0.113.1", 5)
	retentionRecord(t, p, "cold.example", "192.168.1.3", "203.0.113.2", 5)
	oldKey := observationKey{lookupKey: lookupKey{client: netip.MustParseAddr("192.168.1.1"), ip: netip.MustParseAddr("203.0.113.1")}, domain: "old.example", source: "a"}
	sequence := p.index.records[oldKey].sequence
	*now = now.Add(20 * time.Second)
	old := retentionRoute(t, p, "203.0.113.1", "192.168.1.1")
	if old.Domain != "old.example" || !old.ObservedAt.Equal(oldObserved) || p.index.records[oldKey].sequence != sequence {
		t.Fatalf("route rewrote DNS evidence: %+v", old)
	}
	global := retentionRoute(t, p, "203.0.113.1", "192.168.1.9")
	if global.Domain != "new.example" || !global.Conflict || global.Scope != "global" {
		t.Fatalf("access replaced newest DNS owner: %+v", global)
	}
	retentionRoute(t, p, "203.0.113.1", "192.168.1.1")
	retentionRecord(t, p, "extra.example", "192.168.1.4", "203.0.113.3", 5)
	if _, ok := p.index.records[oldKey]; !ok {
		t.Fatal("hot LRU observation evicted")
	}
	if got := lookup(p, "203.0.113.2", "192.168.1.3"); got.Status != "miss" {
		t.Fatalf("cold record not evicted by access LRU: %+v", got)
	}
	// A new DNS observation for the hot client's reused IP immediately wins.
	retentionRecord(t, p, "replacement.example", "192.168.1.1", "203.0.113.1", 5)
	if got := retentionRoute(t, p, "203.0.113.1", "192.168.1.1"); got.Domain != "replacement.example" || !got.Conflict {
		t.Fatalf("latest DNS observation did not win: %+v", got)
	}
}

func TestRetentionDiagnosticsDoNotTouchOwner(t *testing.T) {
	for _, mode := range []string{"sliding", "lru"} {
		t.Run(mode, func(t *testing.T) {
			p, now := testPlugin(t, Args{Size: 2, Retention: RetentionArgs{Mode: mode}})
			retentionRecord(t, p, "owner.example", "192.168.1.1", "203.0.113.1", 5)
			retentionRecord(t, p, "other.example", "192.168.1.2", "203.0.113.2", 5)
			owner := p.index.order.Front().Value.(*observation)
			expires := owner.ExpiresAt
			step := 200 * time.Second
			if mode == "lru" {
				step = 48 * time.Hour
			}
			*now = now.Add(step)
			for range 3 {
				for _, client := range []string{"192.168.1.1", "192.168.1.9", ""} {
					if got := lookup(p, "203.0.113.1", client); got.Status != "hit" || !got.ExpiresAt.After(*now) {
						t.Fatalf("diagnostic evidence not usable: %+v", got)
					}
				}
				if s := p.Snapshot(); s.RetentionTouches != 0 || s.RetentionRenewals != 0 {
					t.Fatalf("read mutated counters: %+v", s)
				}
			}
			if !owner.ExpiresAt.Equal(expires) || p.index.order.Front().Value != owner || len(p.index.records) != 2 {
				t.Fatal("read renewed owner, promoted LRU, or created client evidence")
			}
			if mode == "sliding" {
				*now = expires
				if got := retentionRoute(t, p, "203.0.113.1", "192.168.1.1"); got.Status != "miss" {
					t.Fatalf("diagnostics/global extended sliding expiry: %+v", got)
				}
			} else {
				retentionRecord(t, p, "fresh.example", "192.168.1.3", "203.0.113.3", 5)
				if got := lookup(p, "203.0.113.1", "192.168.1.1"); got.Status != "miss" {
					t.Fatalf("diagnostics/global protected cold LRU: %+v", got)
				}
			}
		})
	}
}

func TestRetentionGlobalTouchesCapacityWithoutRenewingOwner(t *testing.T) {
	for _, mode := range []string{"sliding", "lru"} {
		t.Run(mode, func(t *testing.T) {
			p, now := testPlugin(t, Args{Size: 2, Retention: RetentionArgs{Mode: mode}})
			retentionRecord(t, p, "owner.example", "192.168.1.1", "203.0.113.1", 5)
			retentionRecord(t, p, "cold.example", "192.168.1.2", "203.0.113.2", 5)
			owner := p.index.order.Front().Value.(*observation)
			expires, observed, sequence := owner.ExpiresAt, owner.ObservedAt, owner.sequence
			step := 200 * time.Second
			if mode == "lru" {
				step = 48 * time.Hour
			}
			*now = now.Add(step)
			for _, client := range []string{"192.168.1.9", ""} {
				got := retentionRoute(t, p, "203.0.113.1", client)
				if got.Status != "hit" || got.Scope != "global" || !got.ExpiresAt.After(*now) {
					t.Fatalf("global evidence not usable: %+v", got)
				}
			}
			if !owner.ExpiresAt.Equal(expires) || !owner.ObservedAt.Equal(observed) || owner.sequence != sequence || len(p.index.records) != 2 {
				t.Fatal("global route renewed owner, changed DNS order, or created client evidence")
			}
			if p.index.order.Back().Value != owner {
				t.Fatal("global route did not promote capacity LRU")
			}
			if got := p.Snapshot(); got.RetentionTouches != 2 || got.RetentionRenewals != 0 {
				t.Fatalf("global counters: %+v", got)
			}
			retentionRecord(t, p, "fresh.example", "192.168.1.3", "203.0.113.3", 5)
			if got := lookup(p, "203.0.113.2", "192.168.1.2"); got.Status != "miss" {
				t.Fatalf("global route did not protect hot capacity: %+v", got)
			}
			if mode == "sliding" {
				*now = expires
				if got := retentionRoute(t, p, "203.0.113.1", "192.168.1.1"); got.Status != "miss" {
					t.Fatalf("global route renewed sliding owner: %+v", got)
				}
			}
		})
	}
}

func TestRetentionCanceledAfterLockDoesNotTouch(t *testing.T) {
	p, now := testPlugin(t, Args{Retention: RetentionArgs{Mode: "lru"}})
	retentionRecord(t, p, "owner.example", "192.168.1.1", "203.0.113.1", 5)
	retentionRecord(t, p, "other.example", "192.168.1.2", "203.0.113.2", 5)
	owner := p.index.order.Front().Value.(*observation)
	expires := owner.ExpiresAt
	*now = now.Add(20 * time.Second)
	for _, client := range []string{"192.168.1.1", "192.168.1.9"} {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		p.now = func() time.Time {
			calls++
			// First clock read belongs to lockCurrent; the second occurs
			// after successful lock acquisition, before lookup mutation.
			if calls == 2 {
				cancel()
			}
			return *now
		}
		_, err := p.LookupRouteContext(ctx, netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr(client))
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("route cancellation: %v", err)
		}
		if p.index.order.Front().Value != owner || !owner.ExpiresAt.Equal(expires) || p.stats.RetentionTouches != 0 || p.stats.RetentionRenewals != 0 {
			t.Fatal("canceled route changed access or lease state")
		}
	}
}

func TestRetentionLookupTimestampsDoNotAliasState(t *testing.T) {
	p, now := testPlugin(t, Args{Retention: RetentionArgs{Mode: "lru"}})
	retentionRecord(t, p, "owner.example", "192.168.1.1", "203.0.113.1", 5)
	expires := now.Add(5 * time.Second)
	got := lookup(p, "203.0.113.1", "192.168.1.1")
	*got.DNSExpiresAt = time.Time{}
	*got.Candidates[0].DNSExpiresAt = time.Time{}
	route := retentionRoute(t, p, "203.0.113.1", "192.168.1.1")
	if !route.DNSExpiresAt.Equal(expires) {
		t.Fatal("diagnostic timestamp aliases retained observation")
	}
	*route.DNSExpiresAt = time.Time{}
	again := retentionRoute(t, p, "203.0.113.1", "192.168.1.1")
	if !again.DNSExpiresAt.Equal(expires) {
		t.Fatal("route timestamp aliases retained observation")
	}
}

func TestRetentionLRUAdvertisesFullWindowBeforeStoredExpiry(t *testing.T) {
	for _, mode := range []string{"lru", "sliding"} {
		t.Run(mode, func(t *testing.T) {
			p, now := testPlugin(t, Args{Retention: RetentionArgs{Mode: mode}})
			retentionRecord(t, p, "owner.example", "192.168.1.1", "203.0.113.1", 5)
			owner := p.index.order.Front().Value.(*observation)
			storedExpiry := owner.ExpiresAt
			*now = storedExpiry.Add(-time.Millisecond)
			for _, got := range []LookupResult{lookup(p, "203.0.113.1", "192.168.1.1"), retentionRoute(t, p, "203.0.113.1", "192.168.1.9")} {
				want := storedExpiry
				if mode == "lru" {
					want = now.Add(300 * time.Second)
				}
				if !got.ExpiresAt.Equal(want) {
					t.Fatalf("lease too short or sliding cutoff bypassed: got=%v want=%v", got.ExpiresAt, want)
				}
				if !owner.ExpiresAt.Equal(storedExpiry) {
					t.Fatal("response lease modified owner")
				}
			}
		})
	}
}
