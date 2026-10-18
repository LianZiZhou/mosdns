package domain_mapping

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

func answerIPs(q *query_context.Context) []string {
	var ips []string
	for _, rr := range q.R().Answer {
		switch rr := rr.(type) {
		case *dns.A:
			ips = append(ips, rr.A.String())
		case *dns.AAAA:
			ips = append(ips, rr.AAAA.String())
		}
	}
	return ips
}

func TestAllocationStablePerFamilyAndCopy(t *testing.T) {
	p, _ := testPlugin(t, Args{Allocation: AllocationArgs{Enable: true}})
	q := testContext(t, "one.test", "192.168.1.1", dns.TypeA,
		"one.test. 60 IN A 203.0.113.2", "one.test. 60 IN A 203.0.113.1",
		"one.test. 60 IN AAAA 2001:db8::2", "one.test. 60 IN AAAA 2001:db8::1")
	original := q.R()
	before := original.String()
	p.record(q)
	if ips := answerIPs(q); len(ips) != 2 || ips[0] != "203.0.113.1" || ips[1] != "2001:db8::1" {
		t.Fatalf("selection: %v", ips)
	}
	if original == q.R() || before != original.String() {
		t.Fatal("input response was not copied")
	}
	q = testContext(t, "one.test", "192.168.1.2", dns.TypeA, "one.test. 60 IN A 203.0.113.0", "one.test. 60 IN A 203.0.113.1")
	p.record(q)
	if ips := answerIPs(q); len(ips) != 1 || ips[0] != "203.0.113.1" {
		t.Fatalf("existing lease not reused: %v", ips)
	}
	q = testContext(t, "two.test", "192.168.1.2", dns.TypeA, "two.test. 60 IN A 203.0.113.1", "two.test. 60 IN A 203.0.113.2")
	p.record(q)
	if ips := answerIPs(q); len(ips) != 1 || ips[0] != "203.0.113.2" {
		t.Fatalf("shared address allocated: %v", ips)
	}
}

func TestAllocationExhaustionKeepsAndTracksOriginal(t *testing.T) {
	p, _ := testPlugin(t, Args{Allocation: AllocationArgs{Enable: true}})
	for _, domain := range []string{"one.test", "two.test", "three.test"} {
		q := testContext(t, domain, "192.168.1.1", dns.TypeA,
			fmt.Sprintf("%s. 60 IN A 203.0.113.1", domain), fmt.Sprintf("%s. 60 IN A 203.0.113.2", domain))
		before := q.R().String()
		p.record(q)
		if domain == "three.test" && (q.R().String() != before || p.Snapshot().Exhausted != 1) {
			t.Fatal("exhaustion did not preserve original answer")
		}
	}
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		if p.alloc.leases[leaseKey{domain: "three.test", ip: netip.MustParseAddr(ip)}] == nil {
			t.Fatalf("fallback address %s not occupied", ip)
		}
	}
}

func TestAllocationOldLeaseAndCapacity(t *testing.T) {
	p, now := testPlugin(t, Args{Size: 1, Allocation: AllocationArgs{Enable: true, Size: 2}})
	p.record(testContext(t, "one.test", "", dns.TypeA, "one.test. 60 IN A 203.0.113.1"))
	*now = now.Add(time.Second)
	p.record(testContext(t, "one.test", "", dns.TypeA, "one.test. 10 IN A 203.0.113.2"))
	q := testContext(t, "two.test", "", dns.TypeA, "two.test. 30 IN A 203.0.113.3", "two.test. 30 IN A 203.0.113.4")
	p.record(q)
	if len(q.R().Answer) != 2 || len(p.alloc.leases) != 2 || !p.alloc.blockedUntil.Equal(now.Add(30*time.Second)) {
		t.Fatal("capacity must not evict active leases")
	}
	*now = now.Add(11 * time.Second)
	q = testContext(t, "three.test", "", dns.TypeA, "three.test. 1 IN A 203.0.113.3", "three.test. 1 IN A 203.0.113.4")
	p.record(q)
	if len(q.R().Answer) != 2 {
		t.Fatal("untracked fallback address allocated before expiry")
	}
	if p.alloc.leases[leaseKey{domain: "one.test", ip: netip.MustParseAddr("203.0.113.1")}] == nil {
		t.Fatal("old address lease released when candidates changed")
	}
}

func TestAllocationSkipsDNSSECAndCNAME(t *testing.T) {
	for _, kind := range []string{"do", "ad", "rrsig", "cname"} {
		t.Run(kind, func(t *testing.T) {
			p, _ := testPlugin(t, Args{Allocation: AllocationArgs{Enable: true}})
			q := testContext(t, "one.test", "", dns.TypeA, "one.test. 60 IN A 203.0.113.1", "one.test. 60 IN A 203.0.113.2")
			switch kind {
			case "do":
				msg := q.Q().Copy()
				msg.IsEdns0().SetDo()
				replacement := query_context.NewContext(msg)
				replacement.SetResponse(q.R())
				q = replacement
			case "ad":
				q.R().AuthenticatedData = true
			case "rrsig":
				q.R().Extra = append(q.R().Extra, &dns.RRSIG{Hdr: dns.RR_Header{Name: "one.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET}})
			case "cname":
				q.R().Answer = append(q.R().Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: "one.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "two.test."})
			}
			before := q.R().String()
			p.record(q)
			if q.R().String() != before || p.Snapshot().Unsafe != 1 {
				t.Fatal("unsafe answer was changed")
			}
		})
	}
}

func TestHintsRevokeAllocationEligibility(t *testing.T) {
	p, now := testPlugin(t, Args{Allocation: AllocationArgs{Enable: true}})
	p.record(testContext(t, "one.test", "", dns.TypeA, "one.test. 60 IN A 203.0.113.1", "one.test. 60 IN A 203.0.113.2"))
	p.record(testContext(t, "one.test", "", dns.TypeHTTPS, "one.test. 20 IN HTTPS 1 . ipv4hint=203.0.113.2"))
	q := testContext(t, "one.test", "", dns.TypeA, "one.test. 60 IN A 203.0.113.1", "one.test. 60 IN A 203.0.113.2")
	p.record(q)
	if len(q.R().Answer) != 2 {
		t.Fatal("known hints did not revoke selection")
	}
	q = testContext(t, "two.test", "", dns.TypeA, "two.test. 60 IN A 203.0.113.2", "two.test. 60 IN A 203.0.113.3")
	p.record(q)
	if ips := answerIPs(q); len(ips) != 1 || ips[0] != "203.0.113.3" {
		t.Fatalf("hint address not occupied: %v", ips)
	}
	*now = now.Add(20 * time.Second)
	q = testContext(t, "one.test", "", dns.TypeA, "one.test. 60 IN A 203.0.113.1", "one.test. 60 IN A 203.0.113.2")
	p.record(q)
	if len(q.R().Answer) != 1 {
		t.Fatal("expired hint marker still prevents allocation")
	}
}

func TestBindingsWithoutHintsRevokeAllocationEligibility(t *testing.T) {
	for _, record := range []string{
		`one.test. 20 IN HTTPS 1 endpoint.test. alpn="h2,h3" ech=AQIDBA==`,
		`one.test. 20 IN HTTPS 0 endpoint.test.`,
		`one.test. 20 IN SVCB 1 endpoint.test. alpn="h2"`,
		`one.test. 20 IN SVCB 0 endpoint.test.`,
	} {
		t.Run(record, func(t *testing.T) {
			p, now := testPlugin(t, Args{Allocation: AllocationArgs{Enable: true}})
			p.record(testContext(t, "one.test", "", dns.TypeA, "one.test. 60 IN A 203.0.113.1", "one.test. 60 IN A 203.0.113.2"))
			bindingRR, err := dns.NewRR(record)
			if err != nil {
				t.Fatal(err)
			}
			binding := testContext(t, "one.test", "", bindingRR.Header().Rrtype, record)
			before := binding.R().String()
			p.record(binding)
			if binding.R().String() != before {
				t.Fatal("service binding was modified")
			}
			q := testContext(t, "one.test", "", dns.TypeA, "one.test. 60 IN A 203.0.113.1", "one.test. 60 IN A 203.0.113.2")
			p.record(q)
			if len(q.R().Answer) != 2 {
				t.Fatal("binding without hints did not disable allocation")
			}
			*now = now.Add(20 * time.Second)
			q = testContext(t, "one.test", "", dns.TypeA, "one.test. 60 IN A 203.0.113.1", "one.test. 60 IN A 203.0.113.2")
			p.record(q)
			if len(q.R().Answer) != 1 {
				t.Fatal("expired service association still prevents allocation")
			}
		})
	}
}

func TestAllocationUsesMinimumDuplicateAddressTTL(t *testing.T) {
	p, now := testPlugin(t, Args{Allocation: AllocationArgs{Enable: true}})
	q := testContext(t, "one.test", "", dns.TypeA,
		"one.test. 100 IN A 203.0.113.1", "one.test. 20 IN A 203.0.113.1", "one.test. 60 IN A 203.0.113.2")
	p.record(q)
	if len(q.R().Answer) != 1 || q.R().Answer[0].Header().Ttl != 20 {
		t.Fatalf("duplicate RR TTL was extended: %v", q.R())
	}
	if got := lookup(p, "203.0.113.1", ""); !got.ExpiresAt.Equal(now.Add(20 * time.Second)) {
		t.Fatalf("selected address mapping has wrong TTL: %+v", got)
	}
	if lease := p.alloc.leases[leaseKey{domain: "one.test", ip: netip.MustParseAddr("203.0.113.1")}]; lease == nil || !lease.expiresAt.Equal(now.Add(20*time.Second)) {
		t.Fatalf("selected address lease has wrong TTL: %+v", lease)
	}
}

func TestConcurrentAllocation(t *testing.T) {
	const count = 32
	p, _ := testPlugin(t, Args{Allocation: AllocationArgs{Enable: true}})
	var wg sync.WaitGroup
	results := make(chan string, count)
	for i := 0; i < count; i++ {
		domain := fmt.Sprintf("domain%d.test", i)
		var records []string
		for address := 1; address <= count; address++ {
			records = append(records, fmt.Sprintf("%s. 60 IN A 203.0.113.%d", domain, address))
		}
		q := testContext(t, domain, "192.168.1.1", dns.TypeA, records...)
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.record(q)
			ips := answerIPs(q)
			if len(ips) != 1 {
				t.Errorf("allocated %d addresses", len(ips))
				return
			}
			results <- ips[0]
		}()
	}
	wg.Wait()
	close(results)
	seen := make(map[string]bool)
	for ip := range results {
		if seen[ip] {
			t.Fatalf("concurrent duplicate allocation: %s", ip)
		}
		seen[ip] = true
	}
	if len(seen) != count {
		t.Fatalf("only %d allocations succeeded", len(seen))
	}
}

func TestPendingAllocationsReserveBeforeEncodingAndReleaseOnFailure(t *testing.T) {
	p, _ := testPlugin(t, Args{Allocation: AllocationArgs{Enable: true}})
	makeQuery := func(domain string) *query_context.Context {
		return testContext(t, domain, "192.168.1.1", dns.TypeA,
			fmt.Sprintf("%s. 60 IN A 203.0.113.1", domain), fmt.Sprintf("%s. 60 IN A 203.0.113.2", domain))
	}
	one, two := makeQuery("one.test"), makeQuery("two.test")
	finishOne, finishTwo := p.prepare(one), p.prepare(two)
	if ips := answerIPs(one); len(ips) != 1 || ips[0] != "203.0.113.1" {
		t.Fatalf("first selection: %v", ips)
	}
	if ips := answerIPs(two); len(ips) != 1 || ips[0] != "203.0.113.2" {
		t.Fatalf("concurrent pending reservation was ignored: %v", ips)
	}
	if stats := p.Snapshot(); stats.Leases != 0 || stats.Observations != 0 || stats.Allocated != 0 {
		t.Fatalf("unencoded responses already committed: %+v", stats)
	}
	finishOne(nil)
	three := makeQuery("three.test")
	finishThree := p.prepare(three)
	if ips := answerIPs(three); len(ips) != 1 || ips[0] != "203.0.113.1" {
		t.Fatalf("failed encoding leaked reservation: %v", ips)
	}
	finishTwo(two.R())
	finishThree(three.R())
	if stats := p.Snapshot(); stats.Leases != 2 || stats.Observations != 2 || stats.Allocated != 2 {
		t.Fatalf("finalized responses not committed: %+v", stats)
	}
	for _, l := range p.alloc.leases {
		if l.pending != 0 {
			t.Fatal("pending reference leaked after finalization")
		}
	}
}

func TestPendingOverflowBlocksSelectionUntilActualResponse(t *testing.T) {
	p, now := testPlugin(t, Args{Allocation: AllocationArgs{Enable: true, Size: 1}})
	one := testContext(t, "one.test", "", dns.TypeA, "one.test. 60 IN A 203.0.113.1")
	finishOne := p.prepare(one)
	// This unsafe response must retain both actual addresses, but there is no
	// room to track either while the first response is pending.
	overflow := testContext(t, "overflow.test", "", dns.TypeA,
		"overflow.test. 30 IN CNAME endpoint.test.", "endpoint.test. 30 IN A 203.0.113.2", "endpoint.test. 30 IN A 203.0.113.3")
	finishOverflow := p.prepare(overflow)
	finishOne(nil)
	if len(p.alloc.leases) != 0 || p.alloc.pendingOverflow != 1 || !p.alloc.blockedUntil.IsZero() {
		t.Fatal("overflow prematurely committed or pending references leaked")
	}
	three := testContext(t, "three.test", "", dns.TypeA, "three.test. 60 IN A 203.0.113.2", "three.test. 60 IN A 203.0.113.3")
	finishThree := p.prepare(three)
	if len(three.R().Answer) != 2 {
		t.Fatal("allocation ignored untracked pending addresses")
	}
	finishThree(nil)
	finishOverflow(overflow.R())
	if p.alloc.pendingOverflow != 0 || len(p.alloc.leases) != 1 || !p.alloc.blockedUntil.Equal(now.Add(30*time.Second)) {
		t.Fatal("actual overflow response was not conservatively committed")
	}
}

func TestExpiredCommittedLeaseRetainsPendingReservation(t *testing.T) {
	p, now := testPlugin(t, Args{Allocation: AllocationArgs{Enable: true}})
	p.record(testContext(t, "one.test", "", dns.TypeA, "one.test. 1 IN A 203.0.113.1"))
	one := testContext(t, "one.test", "", dns.TypeA, "one.test. 60 IN A 203.0.113.1")
	finishOne := p.prepare(one)
	*now = now.Add(2 * time.Second)
	two := testContext(t, "two.test", "", dns.TypeA, "two.test. 60 IN A 203.0.113.1", "two.test. 60 IN A 203.0.113.2")
	finishTwo := p.prepare(two)
	if ips := answerIPs(two); len(ips) != 1 || ips[0] != "203.0.113.2" {
		t.Fatalf("expiry removed an active pending reservation: %v", ips)
	}
	finishOne(one.R())
	finishTwo(nil)
	if l := p.alloc.leases[leaseKey{domain: "one.test", ip: netip.MustParseAddr("203.0.113.1")}]; l == nil || l.pending != 0 || !l.expiresAt.Equal(now.Add(60*time.Second)) {
		t.Fatalf("pending lease was not promoted after old expiry: %+v", l)
	}
}
