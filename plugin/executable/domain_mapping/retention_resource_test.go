package domain_mapping

import (
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// These intentionally large profiles are opt-in. They measure the production
// index, without retaining a parallel input dataset, DNS messages or HTTP state.
const retentionResourceCapacity = 262144

var retentionResourceEpoch = time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)

func requireRetentionResourceProfile(tb testing.TB) {
	tb.Helper()
	if testing.Short() || os.Getenv("MOSDNS_RETENTION_RESOURCE") != "1" {
		tb.Skip("set MOSDNS_RETENTION_RESOURCE=1 without -short to profile 262144 observations")
	}
}

func retentionResourceKey(i int, shared bool) lookupKey {
	if shared {
		return lookupKey{
			client: netip.AddrFrom4([4]byte{10, 0, 0, 1}),
			ip:     netip.AddrFrom4([4]byte{203, 0, 113, 1}),
		}
	}
	return lookupKey{
		client: netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}),
		ip:     netip.AddrFrom4([4]byte{198, byte(i >> 16), byte(i >> 8), byte(i)}),
	}
}

func retentionResourcePut(index *observationIndex, i int, shared bool) {
	key := retentionResourceKey(i, shared)
	dnsExpires := retentionResourceEpoch.Add(5 * time.Minute)
	index.put(key.client, key.ip, Candidate{
		Domain:       "resource-" + strconv.Itoa(i) + ".example",
		Source:       "a",
		ObservedAt:   retentionResourceEpoch,
		ExpiresAt:    dnsExpires,
		DNSExpiresAt: &dnsExpires,
	})
}

func newRetentionResourceIndex(tb testing.TB) *observationIndex {
	tb.Helper()
	r := RetentionArgs{Mode: retentionLRU}
	if err := r.normalize(); err != nil {
		tb.Fatal(err)
	}
	index := &observationIndex{retention: r}
	index.init(retentionResourceCapacity)
	return index
}

func checkRetentionResourceBounds(tb testing.TB, index *observationIndex, shared bool) {
	tb.Helper()
	if len(index.records) != retentionResourceCapacity || index.order.Len() != retentionResourceCapacity {
		tb.Fatalf("records/order not capacity-bounded: %d/%d", len(index.records), index.order.Len())
	}
	if len(index.expiry) != 0 || cap(index.expiry) != 0 {
		tb.Fatalf("LRU retained expiry backing storage: len=%d cap=%d", len(index.expiry), cap(index.expiry))
	}
	wantBuckets := 2 * retentionResourceCapacity
	if shared {
		wantBuckets = 2
	}
	if len(index.buckets) != wantBuckets {
		tb.Fatalf("bucket count=%d, want %d", len(index.buckets), wantBuckets)
	}
	for entry := index.order.Front(); entry != nil; entry = entry.Next() {
		o := entry.Value.(*observation)
		if index.records[o.key] != o || o.order != entry || o.heapPos != -1 {
			tb.Fatal("dangling or inconsistent observation in global LRU")
		}
	}
	memberships, distinctDomainSlots := 0, 0
	for key, bucket := range index.buckets {
		if bucket.order.Len() == 0 || len(bucket.domains) == 0 {
			tb.Fatal("empty bucket retained")
		}
		countSum := 0
		for _, count := range bucket.domains {
			if count <= 0 {
				tb.Fatal("non-positive domain reference count retained")
			}
			countSum += count
		}
		if countSum != bucket.order.Len() {
			tb.Fatal("domain reference counts differ from bucket membership")
		}
		for entry := bucket.order.Front(); entry != nil; entry = entry.Next() {
			o := entry.Value.(*observation)
			if index.records[o.key] != o || o.key.ip != key.ip || (key.client.IsValid() && o.key.client != key.client) {
				tb.Fatal("orphaned or misplaced bucket observation")
			}
			if entry != o.bucketOrders[0] && entry != o.bucketOrders[1] {
				tb.Fatal("bucket observation has no matching membership handle")
			}
		}
		memberships += bucket.order.Len()
		distinctDomainSlots += len(bucket.domains)
	}
	if memberships != 2*retentionResourceCapacity || distinctDomainSlots != 2*retentionResourceCapacity {
		tb.Fatalf("unbounded/missing secondary index entries: memberships=%d domain_slots=%d", memberships, distinctDomainSlots)
	}
}

func TestRetentionResourceProfile(t *testing.T) {
	requireRetentionResourceProfile(t)
	t.Logf("runtime=%s GOOS=%s GOARCH=%s GOMAXPROCS=%d capacity=%d", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.GOMAXPROCS(0), retentionResourceCapacity)
	for _, shared := range []bool{false, true} {
		name := "unique_client_ip"
		if shared {
			name = "shared_ip_many_domains"
		}
		t.Run(name, func(t *testing.T) {
			// Initialize package-level netip state before the allocation baseline.
			_ = retentionResourceKey(0, shared)
			runtime.GC()
			var before, after, churned runtime.MemStats
			runtime.ReadMemStats(&before)
			started := time.Now()
			index := newRetentionResourceIndex(t)
			for i := 0; i < retentionResourceCapacity; i++ {
				retentionResourcePut(index, i, shared)
			}
			buildTime := time.Since(started)
			runtime.GC()
			runtime.ReadMemStats(&after)
			runtime.KeepAlive(index)
			retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
			t.Logf("RESOURCE scenario=%s records=%d retained_bytes=%d retained_MiB=%.3f bytes_per_record=%.2f build_ms=%.3f build_ns_per_record=%.1f total_alloc_MiB=%.3f mallocs_per_record=%.2f GC_cycles=%d", name, retentionResourceCapacity, retained, float64(retained)/(1<<20), float64(retained)/retentionResourceCapacity, float64(buildTime)/float64(time.Millisecond), float64(buildTime)/retentionResourceCapacity, float64(after.TotalAlloc-before.TotalAlloc)/(1<<20), float64(after.Mallocs-before.Mallocs)/retentionResourceCapacity, after.NumGC-before.NumGC)
			checkRetentionResourceBounds(t, index, shared)

			// Fully replace the cold population while periodically accessing one
			// stable client-scoped route in the unique-address scenario. The
			// shared-address scenario continually changes its latest candidate.
			hotKey := retentionResourceKey(0, false)
			const churnCount = retentionResourceCapacity + retentionResourceCapacity/8
			started = time.Now()
			for j := 0; j < churnCount; j++ {
				if !shared && j%64 == 0 {
					o, conflict := index.routeObservation(hotKey)
					if o == nil || conflict {
						t.Fatal("hot client-scoped record was lost or became ambiguous")
					}
					index.touchRoute(o, retentionResourceEpoch.Add(time.Hour+time.Duration(j)*time.Second))
				}
				retentionResourcePut(index, retentionResourceCapacity+j, shared)
			}
			churnTime := time.Since(started)
			index.expire(retentionResourceEpoch.AddDate(10, 0, 0))
			checkRetentionResourceBounds(t, index, shared)
			if !shared {
				if _, conflict, found := index.route(hotKey); !found || conflict {
					t.Fatal("LRU did not retain the active client route after a full-capacity churn")
				}
				if _, _, found := index.route(retentionResourceKey(1, false)); found {
					t.Fatal("cold original record survived full-capacity churn")
				}
			}
			runtime.GC()
			runtime.ReadMemStats(&churned)
			runtime.KeepAlive(index)
			retained = int64(churned.HeapAlloc) - int64(before.HeapAlloc)
			t.Logf("CHURN scenario=%s inserts=%d retained_bytes=%d retained_MiB=%.3f bytes_per_record=%.2f churn_ms=%.3f records=%d buckets=%d expiry_len=%d expiry_cap=%d", name, churnCount, retained, float64(retained)/(1<<20), float64(retained)/retentionResourceCapacity, float64(churnTime)/float64(time.Millisecond), len(index.records), len(index.buckets), len(index.expiry), cap(index.expiry))
		})
	}
}

var retentionResourceCandidateSink Candidate

func BenchmarkRetentionLargeIndexRoute(b *testing.B) {
	requireRetentionResourceProfile(b)
	for _, shared := range []bool{false, true} {
		name := "unique_client_ip"
		if shared {
			name = "shared_ip_many_domains"
		}
		b.Run(fmt.Sprintf("%s/%d", name, retentionResourceCapacity), func(b *testing.B) {
			index := newRetentionResourceIndex(b)
			for i := 0; i < retentionResourceCapacity; i++ {
				retentionResourcePut(index, i, shared)
			}
			// Spread lookups across the whole index, avoiding key/string creation
			// in the measured path. Shared-IP lookups exercise conflict metadata.
			keys := make([]lookupKey, 1024)
			for i := range keys {
				keys[i] = retentionResourceKey(i*retentionResourceCapacity/len(keys), shared)
			}
			now := retentionResourceEpoch.Add(time.Hour)
			query := 0
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				o, conflict := index.routeObservation(keys[query&(len(keys)-1)])
				if o == nil || conflict != shared {
					b.Fatal("unexpected route selection")
				}
				// Production route lookup selects and touches the latest candidate
				// even when other domains make the address ambiguous.
				index.touchRoute(o, now.Add(time.Duration(query)))
				retentionResourceCandidateSink = index.retentionCandidate(o, now)
				query++
			}
			runtime.KeepAlive(index)
		})
	}
}
