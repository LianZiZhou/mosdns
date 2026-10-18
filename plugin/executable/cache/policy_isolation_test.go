package cache

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func policyQuery(client string) *query_context.Context {
	q := new(dns.Msg)
	q.SetQuestion("policy.example.", dns.TypeA)
	c := query_context.NewContext(q)
	c.ServerMeta.ClientAddr = netip.MustParseAddr(client)
	return c
}

func policyAnswer(q *dns.Msg, ip string, ttl uint32) *dns.Msg {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip).To4(),
	}}
	return r
}

func policyNext(ip string, calls *atomic.Int32) sequence.ChainWalker {
	return sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
		// This represents the usual has_resp/accept gate in a policy sequence.
		if q.R() == nil {
			calls.Add(1)
			q.SetResponse(policyAnswer(q.Q(), ip, 60))
		}
		return nil
	})}}, nil)
}

func TestPolicyCachesIsolateAnswersAndDumps(t *testing.T) {
	var caches [2]*Cache
	var calls [2]atomic.Int32
	ips := []string{"192.0.2.10", "192.0.2.20"}
	for i := range caches {
		caches[i] = NewCache(&Args{Size: 64}, Opts{})
		t.Cleanup(func() { _ = caches[i].Close() })
	}
	for round := 0; round < 2; round++ {
		for i, c := range caches {
			q := policyQuery("192.168.1.10")
			if round == 1 {
				// Another client in the same policy can reuse its policy cache.
				q.ServerMeta.ClientAddr = netip.MustParseAddr("192.168.1.11")
			}
			if err := c.Exec(context.Background(), q, policyNext(ips[i], &calls[i])); err != nil {
				t.Fatal(err)
			}
			if got := q.R().Answer[0].(*dns.A).A.String(); got != ips[i] {
				t.Fatalf("policy %d round %d: got %s, want %s", i, round, got, ips[i])
			}
		}
	}
	for i, c := range caches {
		if got := calls[i].Load(); got != 1 {
			t.Fatalf("policy %d upstream called %d times, want 1", i, got)
		}
		var dump bytes.Buffer
		if _, err := c.writeDump(&dump); err != nil {
			t.Fatal(err)
		}
		restored := NewCache(&Args{Size: 64}, Opts{})
		t.Cleanup(func() { _ = restored.Close() })
		if _, err := restored.readDump(&dump); err != nil {
			t.Fatal(err)
		}
		q := policyQuery("192.168.1.12")
		if err := restored.Exec(context.Background(), q, policyNext("203.0.113.99", &calls[i])); err != nil {
			t.Fatal(err)
		}
		if got := q.R().Answer[0].(*dns.A).A.String(); got != ips[i] {
			t.Fatalf("restored policy %d: got %s, want %s", i, got, ips[i])
		}
	}
}

func TestPolicyLazyRefreshKeepsClientAndDoesNotMergeAcrossPolicies(t *testing.T) {
	started := make(chan netip.Addr, 2)
	release := make(chan struct{})
	finished := make(chan struct{}, 2)
	clients := []string{"192.168.1.10", "192.168.1.20"}
	for i, client := range clients {
		c := NewCache(&Args{Size: 64, LazyCacheTTL: 3600}, Opts{})
		t.Cleanup(func() { _ = c.Close() })
		q := policyQuery(client)
		r := policyAnswer(q.Q(), "192.0.2.1", 1)
		stored := time.Now().Add(-time.Minute)
		c.backend.Store(key(getMsgKey(q.Q())), &item{resp: r, storedTime: stored, expirationTime: stored.Add(time.Second)}, time.Now().Add(time.Hour))
		ip := []string{"192.0.2.10", "192.0.2.20"}[i]
		next := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, refresh *query_context.Context) error {
			if refresh.R() != nil {
				return nil
			}
			started <- refresh.ServerMeta.ClientAddr
			<-release
			refresh.SetResponse(policyAnswer(refresh.Q(), ip, 60))
			finished <- struct{}{}
			return nil
		})}}, nil)
		if err := c.Exec(context.Background(), q, next); err != nil {
			t.Fatal(err)
		}
		if q.R() == nil || q.R().Answer[0].Header().Ttl != expiredMsgTtl {
			t.Fatal("expected an immediate lazy response")
		}
		// A subsequent caller mutation must not change the copied refresh identity.
		q.ServerMeta.ClientAddr = netip.MustParseAddr("192.168.1.99")
	}
	seen := map[netip.Addr]bool{}
	for range clients {
		select {
		case client := <-started:
			seen[client] = true
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("policy refreshes were lost or merged")
		}
	}
	close(release)
	for _, client := range clients {
		if !seen[netip.MustParseAddr(client)] {
			t.Errorf("refresh lost client %s", client)
		}
	}
	for range clients {
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Fatal("refresh did not finish")
		}
	}
}
