package domain_mapping

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"testing"
	"time"
)

// The model deliberately uses only a map and logical observation/access
// counters. It does not share the index's lists, buckets, or expiry helpers.
func TestRetentionLRUMatchesIndependentReference(t *testing.T) {
	const capacity, steps = 31, 5000
	const seed int64 = 88420031
	p, now := testPlugin(t, Args{Size: capacity, Retention: RetentionArgs{Mode: "lru"}})
	type referenceRecord struct{ observed, accessed int }
	reference := make(map[observationKey]referenceRecord)
	random := rand.New(rand.NewSource(seed))
	clients := []netip.Addr{{}, netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("192.168.1.2"), netip.MustParseAddr("2001:db8::1")}
	ips := []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("203.0.113.3")}
	var evictions uint64

	// Select from the exact client first, then the global view. The newest
	// DNS observation wins regardless of which record was accessed last.
	selectRecord := func(ip, client netip.Addr) (observationKey, bool, string, bool) {
		for _, scope := range []netip.Addr{client, {}} {
			var selected observationKey
			newest := -1
			domains := make(map[string]bool)
			for key, record := range reference {
				if key.ip != ip || (scope.IsValid() && key.client != scope) {
					continue
				}
				domains[key.domain] = true
				if record.observed > newest {
					newest, selected = record.observed, key
				}
			}
			if newest >= 0 {
				name := "global"
				if scope.IsValid() {
					name = "client"
				}
				return selected, len(domains) > 1, name, true
			}
		}
		return observationKey{}, false, "global", false
	}

	for step := 1; step <= steps; step++ {
		// Advance well beyond both DNS TTLs and renewable windows. LRU
		// evidence must survive idle time until capacity eviction occurs.
		*now = now.Add(time.Second * time.Duration(random.Intn(30000)))
		client, ip := clients[random.Intn(len(clients))], ips[random.Intn(len(ips))]
		operation := "DNS observation"
		if random.Intn(3) == 0 {
			key := observationKey{
				lookupKey: lookupKey{client: client, ip: ip},
				domain:    fmt.Sprintf("d%d.example", random.Intn(21)), source: "a",
			}
			if _, exists := reference[key]; !exists && len(reference) == capacity {
				var oldest observationKey
				oldestAccess := step + 1
				for candidate, record := range reference {
					if record.accessed < oldestAccess {
						oldest, oldestAccess = candidate, record.accessed
					}
				}
				delete(reference, oldest)
				evictions++
			}
			reference[key] = referenceRecord{observed: step, accessed: step}
			clientText := ""
			if client.IsValid() {
				clientText = client.String()
			}
			retentionRecord(t, p, key.domain, clientText, ip.String(), uint32(random.Intn(600)))
		} else {
			key, conflict, scope, found := selectRecord(ip, client)
			var result LookupResult
			if random.Intn(2) == 0 {
				operation = "route lookup"
				var err error
				result, err = p.LookupRouteContext(context.Background(), ip, client)
				if err != nil {
					t.Fatalf("seed %d step %d: route lookup failed: %v", seed, step, err)
				}
				if found {
					record := reference[key]
					record.accessed = step
					reference[key] = record
				}
			} else {
				operation = "diagnostic lookup"
				result = p.Lookup(ip, client)
			}
			if (result.Status == "hit") != found || result.Scope != scope || result.Conflict != conflict || (found && result.Domain != key.domain) {
				t.Fatalf("seed %d step %d %s client=%v ip=%v: got %+v, want domain=%q scope=%s conflict=%t found=%t", seed, step, operation, client, ip, result, key.domain, scope, conflict, found)
			}
		}

		if len(p.index.records) != len(reference) || p.index.order.Len() != len(reference) || len(p.index.expiry) != 0 || cap(p.index.expiry) != 0 {
			t.Fatalf("seed %d step %d %s: records=%d LRU=%d expiry=%d/%d, want %d retained records and no expiry heap", seed, step, operation, len(p.index.records), p.index.order.Len(), len(p.index.expiry), cap(p.index.expiry), len(reference))
		}
		if p.stats.ObservationEvicts != evictions {
			t.Fatalf("seed %d step %d %s: evictions=%d, want %d", seed, step, operation, p.stats.ObservationEvicts, evictions)
		}
		for key := range reference {
			if p.index.records[key] == nil {
				t.Fatalf("seed %d step %d %s: wrong record evicted: %+v", seed, step, operation, key)
			}
		}
		lastAccess := -1
		for element := p.index.order.Front(); element != nil; element = element.Next() {
			key := element.Value.(*observation).key
			access := reference[key].accessed
			if access <= lastAccess {
				t.Fatalf("seed %d step %d %s: LRU order for %+v has access %d after %d", seed, step, operation, key, access, lastAccess)
			}
			lastAccess = access
		}
		for key, bucket := range p.index.buckets {
			counts := make(map[string]int)
			lastObservation := -1
			for element := bucket.order.Front(); element != nil; element = element.Next() {
				observation := element.Value.(*observation)
				record, exists := reference[observation.key]
				if !exists || observation.key.ip != key.ip || (key.client.IsValid() && observation.key.client != key.client) {
					t.Fatalf("seed %d step %d %s: invalid observation %+v in bucket %+v", seed, step, operation, observation.key, key)
				}
				if record.observed <= lastObservation {
					t.Fatalf("seed %d step %d %s: bucket %+v selection order changed without DNS observation", seed, step, operation, key)
				}
				lastObservation = record.observed
				counts[observation.Domain]++
			}
			if len(counts) == 0 || len(counts) != len(bucket.domains) {
				t.Fatalf("seed %d step %d %s: bucket %+v has invalid distinct-domain counts", seed, step, operation, key)
			}
			for domain, count := range counts {
				if bucket.domains[domain] != count {
					t.Fatalf("seed %d step %d %s: bucket %+v domain=%q count=%d, want %d", seed, step, operation, key, domain, bucket.domains[domain], count)
				}
			}
		}
	}
}
