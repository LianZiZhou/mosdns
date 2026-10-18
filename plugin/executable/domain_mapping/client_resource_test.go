package domain_mapping

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

// Opt-in production history compatibility and bounded-resource profiles.
func TestClientRealHistoryImport(t *testing.T) {
	path := os.Getenv("MOSDNS_ALLOCATION_IMPORT")
	if path == "" {
		t.Skip("set MOSDNS_ALLOCATION_IMPORT to a legacy migration JSON")
	}
	snapshot, err := readStateImport(path)
	if err != nil {
		t.Fatal(err)
	}
	args := Args{Size: 262144, Retention: RetentionArgs{Mode: "lru"}, Allocation: AllocationArgs{Enable: true, ClientScope: true, StateFile: filepath.Join(t.TempDir(), "state.gz"), ImportFile: path}}
	start := time.Now()
	p, err := New(args)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if len(p.index.records) != len(snapshot.Records) {
		t.Fatalf("import=%d retained=%d", len(snapshot.Records), len(p.index.records))
	}
	if !snapshot.HistoryComplete && !p.clients.guardUntil.After(time.Now().Add(23*time.Hour)) {
		t.Fatal("partial history was treated as complete")
	}
	for _, k := range snapshot.IncompleteBuckets {
		got := v2Lookup(t, p, k.IP, k.Client)
		if got.Complete || got.Status != "ambiguous" {
			t.Fatalf("truncated bucket became complete: %+v", got)
		}
	}
	info, err := os.Stat(args.Allocation.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("import_records=%d incomplete_buckets=%d checkpoint_bytes=%d import_and_checkpoint=%v", len(snapshot.Records), len(snapshot.IncompleteBuckets), info.Size(), time.Since(start))
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	args.Allocation.ImportFile = ""
	q, err := New(args)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if len(q.index.records) != len(snapshot.Records) {
		t.Fatal("clean restart changed imported record count")
	}
}

func TestClientCheckpointResources(t *testing.T) {
	requireRetentionResourceProfile(t)
	p := newClientTestPlugin(t, retentionResourceCapacity)
	p.mu.Lock()
	for i := 0; i < retentionResourceCapacity; i++ {
		retentionResourcePut(&p.index, i, false)
	}
	p.mu.Unlock()
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	var peak atomic.Uint64
	peak.Store(baseline.HeapAlloc)
	stop := make(chan struct{})
	sampleDone := make(chan struct{})
	go func() {
		defer close(sampleDone)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
			}
		}
	}()
	lookupDone := make(chan []time.Duration)
	go func() {
		key := retentionResourceKey(0, false)
		var durations []time.Duration
		for {
			select {
			case <-stop:
				lookupDone <- durations
				return
			default:
				started := time.Now()
				_, _ = p.LookupV2Context(context.Background(), key.ip, key.client)
				durations = append(durations, time.Since(started))
				time.Sleep(time.Millisecond)
			}
		}
	}()
	start := time.Now()
	profileState := &stateStore{p: p, path: filepath.Join(filepath.Dir(p.args.Allocation.StateFile), "profile.state")}
	if err := profileState.checkpoint(); err != nil {
		t.Fatal(err)
	}
	if profileState.file != nil {
		_ = profileState.file.Close()
	}
	elapsed := time.Since(start)
	close(stop)
	<-sampleDone
	durations := <-lookupDone
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	info, err := os.Stat(profileState.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("records=%d checkpoint=%v disk_bytes=%d heap_base=%d heap_peak=%d concurrent_lookup_n=%d p99=%v max=%v", len(p.index.records), elapsed, info.Size(), baseline.HeapAlloc, peak.Load(), len(durations), durations[len(durations)*99/100], durations[len(durations)-1])
}

func BenchmarkClientDNSWithAsyncState(b *testing.B) {
	dir := b.TempDir()
	seed := filepath.Join(dir, "import.json")
	if err := os.WriteFile(seed, []byte(`{"version":1,"history_complete":true,"records":[]}`), 0600); err != nil {
		b.Fatal(err)
	}
	p, err := New(Args{Size: 262144, Retention: RetentionArgs{Mode: "lru"}, Allocation: AllocationArgs{Enable: true, ClientScope: true, StateFile: filepath.Join(dir, "state"), ImportFile: seed}})
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close()
	// Reuse a real parsed response; this measures prepare/finalize including
	// ownership, copy, WAL enqueue and classifier lookup, excluding DNS parsing.
	question := new(dns.Msg)
	question.SetQuestion("bench.test.", dns.TypeA)
	q := query_context.NewContext(question)
	q.ServerMeta.ClientAddr = netip.MustParseAddr("192.168.6.180")
	answer := new(dns.Msg)
	answer.SetReply(question)
	rr, err := dns.NewRR("bench.test. 300 IN A 203.0.113.1")
	if err != nil {
		b.Fatal(err)
	}
	answer.Answer = []dns.RR{rr}
	q.SetResponse(answer)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.record(q)
	}
	b.StopTimer()
}
