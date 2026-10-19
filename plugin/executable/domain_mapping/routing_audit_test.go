package domain_mapping

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestUncertainRestartDoesNotReconstructLRUFromDNSEvents(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	p.args.Routing.Size = 2
	p.routes.init(2)
	const clientText = "192.168.6.180"
	client := netip.MustParseAddr(clientText)
	p.record(clientPool(t, "first.test", clientText, 300, "203.0.113.1"))
	p.record(clientPool(t, "evicted.test", clientText, 300, "203.0.113.2"))
	snapshot := p.state.snapshot()
	v3Lookup(t, p, "203.0.113.1", clientText) // This touch is intentionally not in WAL.
	p.record(clientPool(t, "new.test", clientText, 300, "203.0.113.3"))
	if got := v3Lookup(t, p, "203.0.113.2", clientText); got.Status != "miss" {
		t.Fatal("setup did not evict the old identity")
	}
	h := p.routes.entries[lookupKey{client: client, ip: netip.MustParseAddr("203.0.113.3")}]
	event := stateEventFor("new.test", client, []evidence{{ip: netip.MustParseAddr("203.0.113.3"), source: "a", ttl: 300}}, nil, false, h.observedAt)
	event.RoutingSequence = p.routes.sequence
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	for _, dirty := range []bool{true, false} {
		name := "fresh-wal-without-marker"
		if dirty {
			name = "dirty-restart"
		}
		t.Run(name, func(t *testing.T) {
			args := p.args
			dir := t.TempDir()
			args.Allocation.StateFile = filepath.Join(dir, "state")
			args.Allocation.ImportFile = filepath.Join(dir, "snapshot.json")
			body, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(args.Allocation.ImportFile, body, 0600); err != nil {
				t.Fatal(err)
			}
			if dirty {
				if err := os.WriteFile(args.Allocation.StateFile+".dirty", nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			body, err = json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			wal := make([]byte, 36, 36+len(body))
			binary.BigEndian.PutUint32(wal[:4], uint32(len(body)))
			sum := sha256.Sum256(body)
			copy(wal[4:], sum[:])
			wal = append(wal, body...)
			if err := os.WriteFile(args.Allocation.StateFile+".wal", wal, 0600); err != nil {
				t.Fatal(err)
			}
			q, err := New(args)
			if err != nil {
				t.Fatal(err)
			}
			defer q.Close()
			for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
				if got := v3Lookup(t, q, ip, clientText); got.Status != "miss" {
					t.Fatalf("uncertain restart resurrected a historical hint: %+v", got)
				}
			}
			if len(q.index.records) != 3 {
				t.Fatal("cold routing discarded allocator exposure evidence")
			}
			q.record(clientPool(t, "actual-new.test", clientText, 300, "203.0.113.3"))
			if got := v3Lookup(t, q, "203.0.113.3", clientText); got.Domain != "actual-new.test" {
				t.Fatal("new finalized DNS could not immediately warm recovery routing")
			}
		})
	}
}

func TestActualDNSOverridesFuturePersistedHintAfterClockRollback(t *testing.T) {
	p, now := testPlugin(t, Args{})
	client, ip := "192.168.6.180", "203.0.113.1"
	future := now.Add(24 * time.Hour)
	if err := p.restoreRouting([]stateRoutingHint{{
		Client: client, IP: ip, Domain: "stale-ai.test", Source: "a", ObservedAt: future,
		DNSExpiresAt: future.Add(300 * time.Second), TruncatedUntil: future.Add(time.Hour),
		Recent: []stateRecentDomain{{Domain: "stale-ai.test", ObservedAt: future, ExpiresAt: future.Add(50 * time.Minute)}},
	}}); err != nil {
		t.Fatal(err)
	}
	p.record(clientPool(t, "actual-new.test", client, 300, ip))
	got := v3Lookup(t, p, ip, client)
	if got.Domain != "actual-new.test" || !got.ObservedAt.Equal(*now) || !got.CandidatesComplete || !reflect.DeepEqual(got.Domains, []string{"actual-new.test"}) {
		t.Fatalf("future persisted time pinned a routing identity or conflict: %+v", got)
	}
	// A backwards clock change during the same process must also use actual
	// response order, not the larger previously observed wall-clock value.
	*now = now.Add(-time.Hour)
	p.record(clientPool(t, "another-actual.test", client, 60, ip))
	if got := v3Lookup(t, p, ip, client); got.Domain != "another-actual.test" || len(got.Domains) != 1 {
		t.Fatalf("live clock rollback kept future facts: %+v", got)
	}
}

func TestFutureHintCannotBeKeptHotWithoutFreshDNS(t *testing.T) {
	p, now := testPlugin(t, Args{})
	future := now.Add(24 * time.Hour)
	if err := p.restoreRouting([]stateRoutingHint{{Client: "192.168.6.180", IP: "203.0.113.1", Domain: "future-ai.test", Source: "a", ObservedAt: future, DNSExpiresAt: future.Add(time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	if got := v3Lookup(t, p, "203.0.113.1", "192.168.6.180"); got.Status != "miss" || len(p.routes.entries) != 0 {
		t.Fatalf("future identity remained available for route accesses: %+v", got)
	}
}

func TestHistoricalAliasDoesNotRevokeCurrentlySafePreference(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	const client, a, b, c = "192.168.6.180", "203.0.113.1", "203.0.113.2", "203.0.113.3"
	p.record(clientPool(t, "gemini.test", client, 300, a, b))
	p.record(clientPool(t, "gstatic.test", client, 300, a, b))
	alias := testContext(t, "gemini.test", client, dns.TypeA, "gemini.test. 300 IN CNAME canonical.test.", "canonical.test. 300 IN A 203.0.113.1")
	before := alias.R().String()
	p.record(alias)
	if alias.R().String() != before {
		t.Fatal("current complex response was altered")
	}
	q := clientPool(t, "gemini.test", client, 300, a, b)
	p.record(q)
	if got := answerAddresses(q); !reflect.DeepEqual(got, []string{a}) {
		t.Fatalf("historical alias revoked the valid preference: %v", got)
	}
	q = clientPool(t, "gemini.test", client, 300, a, b)
	q.R().AuthenticatedData = true
	before = q.R().String()
	p.record(q)
	if q.R().String() != before {
		t.Fatal("existing preference bypassed current DNSSEC safety")
	}
	q = clientPool(t, "gemini.test", client, 300, b, c)
	p.record(q)
	if got := answerAddresses(q); !reflect.DeepEqual(got, []string{b, c}) {
		t.Fatalf("historical guard permitted a NEW assignment: %v", got)
	}
}
