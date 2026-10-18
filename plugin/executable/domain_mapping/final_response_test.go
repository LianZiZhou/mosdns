package domain_mapping

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/pkg/server_handler"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func TestTruncationIntroducesUnsentMapping(t *testing.T) {
	p, _ := testPlugin(t, Args{}) // default allocation=false
	client := "192.168.1.1"
	ip := "203.0.113.100"
	p.record(testContext(t, "previous.test", client, dns.TypeA, "previous.test. 60 IN A "+ip))
	entry := sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
		tail := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
			r := new(dns.Msg)
			r.SetReply(q.Q())
			for i := 1; i <= 100; i++ {
				rr, _ := dns.NewRR(fmt.Sprintf("oversized.test. 60 IN A 203.0.113.%d", i))
				r.Answer = append(r.Answer, rr)
			}
			q.SetResponse(r)
			return nil
		})}}, nil)
		return p.Exec(ctx, q, tail)
	})
	h := server_handler.NewEntryHandler(server_handler.EntryHandlerOpts{Entry: entry})
	query := new(dns.Msg)
	query.SetQuestion("oversized.test.", dns.TypeA)
	wire := h.Handle(context.Background(), query, server.QueryMeta{FromUDP: true, ClientAddr: netip.MustParseAddr(client)}, func(m *dns.Msg) (*[]byte, error) { b, e := m.Pack(); return &b, e })
	if wire == nil {
		t.Fatal("no response")
	}
	response := new(dns.Msg)
	if err := response.Unpack(*wire); err != nil {
		t.Fatal(err)
	}
	for _, rr := range response.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.String() == ip {
			t.Fatal("fixture error: disputed address was sent")
		}
	}
	got := lookup(p, ip, client)
	t.Logf("wire len=%d TC=%v actual answer count=%d; disputed IP not sent; selected=%s conflict=%v", len(*wire), response.Truncated, len(response.Answer), got.Domain, got.Conflict)
	if got.Domain != "previous.test" {
		t.Errorf("unsent address overrides valid mapping: %+v", got)
	}
}

func TestPackingFailureIntroducesMapping(t *testing.T) {
	p, _ := testPlugin(t, Args{})
	client := "192.168.1.1"
	ip := "203.0.113.1"
	p.record(testContext(t, "previous.test", client, dns.TypeA, "previous.test. 60 IN A "+ip))
	entry := sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
		tail := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
			q.SetResponse(testContext(t, "unsent.test", client, dns.TypeA, "unsent.test. 60 IN A "+ip).R())
			return nil
		})}}, nil)
		return p.Exec(ctx, q, tail)
	})
	h := server_handler.NewEntryHandler(server_handler.EntryHandlerOpts{Entry: entry})
	query := new(dns.Msg)
	query.SetQuestion("unsent.test.", dns.TypeA)
	wire := h.Handle(context.Background(), query, server.QueryMeta{ClientAddr: netip.MustParseAddr(client)}, func(*dns.Msg) (*[]byte, error) { return nil, errors.New("injected pack failure") })
	if wire != nil {
		t.Fatal("pack failed but response returned")
	}
	got := lookup(p, ip, client)
	if got.Domain != "previous.test" {
		t.Errorf("failed response overrides valid mapping: %+v", got)
	}
}

func TestHTTPSRelatedAdditionalAddresses(t *testing.T) {
	for _, target := range []string{".", "endpoint.test."} {
		t.Run(target, func(t *testing.T) {
			p, _ := testPlugin(t, Args{Allocation: AllocationArgs{Enable: true}})
			client := "192.168.1.1"
			ip := "203.0.113.1"
			q := testContext(t, "origin.test", client, dns.TypeHTTPS, "origin.test. 60 IN HTTPS 1 "+target+" alpn=\"h3\"")
			owner := target
			if owner == "." {
				owner = "origin.test."
			}
			rr, err := dns.NewRR(owner + " 60 IN A " + ip)
			if err != nil {
				t.Fatal(err)
			}
			q.R().Extra = append(q.R().Extra, rr)
			p.record(q)
			got := lookup(p, ip, client)
			if got.Domain != "origin.test" {
				t.Errorf("reachable additional address missed: %+v", got)
			}
			next := testContext(t, "other.test", client, dns.TypeA, "other.test. 60 IN A 203.0.113.1", "other.test. 60 IN A 203.0.113.2")
			p.record(next)
			if ips := answerIPs(next); len(ips) != 1 || ips[0] != "203.0.113.2" {
				t.Errorf("already-returned address reused: selected=%v, stats=%+v", ips, p.Snapshot())
			}
		})
	}
}

func TestHTTPSAdditionalDefaultModeSelectsStaleDomain(t *testing.T) {
	p, _ := testPlugin(t, Args{})
	client := "192.168.1.1"
	ip := "203.0.113.1"
	p.record(testContext(t, "previous.test", client, dns.TypeA, "previous.test. 60 IN A "+ip))
	q := testContext(t, "origin.test", client, dns.TypeHTTPS, "origin.test. 60 IN HTTPS 1 endpoint.test. alpn=\"h3\" ech=AQIDBA==")
	rr, _ := dns.NewRR("endpoint.test. 60 IN A " + ip)
	q.R().Extra = append(q.R().Extra, rr)
	p.record(q)
	got := lookup(p, ip, client)
	if got.Domain != "origin.test" || !got.Conflict {
		t.Errorf("actual latest HTTPS target ignored; stale mapping wins without conflict: %+v", got)
	}
}

func TestHTTPSAliasAdditionalHintsMissing(t *testing.T) {
	p, _ := testPlugin(t, Args{})
	client := "192.168.1.1"
	ip := "203.0.113.1"
	q := testContext(t, "origin.test", client, dns.TypeHTTPS, "origin.test. 60 IN HTTPS 0 endpoint.test.")
	rr, _ := dns.NewRR("endpoint.test. 60 IN HTTPS 1 . alpn=\"h3\" ipv4hint=" + ip)
	q.R().Extra = append(q.R().Extra, rr)
	p.record(q)
	got := lookup(p, ip, client)
	if got.Domain != "origin.test" {
		t.Errorf("reachable Additional HTTPS hints not observed: %+v", got)
	}
}

func TestServiceAdditionalTTLAndTypeBoundaries(t *testing.T) {
	for _, kind := range []uint16{dns.TypeHTTPS, dns.TypeSVCB} {
		t.Run(dns.TypeToString[kind], func(t *testing.T) {
			p, now := testPlugin(t, Args{})
			name := dns.TypeToString[kind]
			wrongName := "SVCB"
			if kind == dns.TypeSVCB {
				wrongName = "HTTPS"
			}
			q := testContext(t, "origin.test", "192.168.1.1", kind,
				"origin.test. 60 IN CNAME alias.test.", "alias.test. 20 IN "+name+" 0 service.test.")
			for _, text := range []string{
				"service.test. 10 IN " + name + " 1 endpoint.test. alpn=\"h3\"",
				"endpoint.test. 5 IN CNAME final.test.",
				"final.test. 100 IN A 203.0.113.1",
				"final.test. 2 IN AAAA 2001:db8::1",
				"unrelated.test. 60 IN A 203.0.113.2",
				"service.test. 60 IN " + wrongName + " 1 . ipv4hint=203.0.113.3",
				"unrelated.test. 60 IN " + name + " 1 . ipv4hint=203.0.113.4",
			} {
				rr, err := dns.NewRR(text)
				if err != nil {
					t.Fatal(err)
				}
				q.R().Extra = append(q.R().Extra, rr)
			}
			p.record(q)
			for ip, ttl := range map[string]time.Duration{"203.0.113.1": 5 * time.Second, "2001:db8::1": 2 * time.Second} {
				got := lookup(p, ip, "192.168.1.1")
				if got.Domain != "origin.test" || got.ExpiresAt == nil || !got.ExpiresAt.Equal(now.Add(ttl)) {
					t.Errorf("wrong reachable Additional TTL for %s: %+v", ip, got)
				}
			}
			for _, ip := range []string{"203.0.113.2", "203.0.113.3", "203.0.113.4"} {
				if got := lookup(p, ip, ""); got.Status != "miss" {
					t.Errorf("unrelated or cross-type binding leaked for %s: %+v", ip, got)
				}
			}
		})
	}
}

func TestAliasModeAdditionalAddressFallbackAndMixedMode(t *testing.T) {
	p, now := testPlugin(t, Args{})
	q := testContext(t, "origin.test", "", dns.TypeHTTPS,
		"origin.test. 20 IN HTTPS 0 endpoint.test.",
		// When AliasMode is present, clients ignore ServiceMode records in
		// the same RRset, including their targets and hints.
		"origin.test. 60 IN HTTPS 1 ignored.test. ipv4hint=203.0.113.3")
	for _, text := range []string{
		"endpoint.test. 5 IN CNAME final.test.",
		"final.test. 100 IN A 203.0.113.1",
		"ignored.test. 60 IN A 203.0.113.2",
	} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		q.R().Extra = append(q.R().Extra, rr)
	}
	p.record(q)
	got := lookup(p, "203.0.113.1", "")
	if got.Domain != "origin.test" || got.ExpiresAt == nil || !got.ExpiresAt.Equal(now.Add(5*time.Second)) {
		t.Fatalf("AliasMode address fallback lost: %+v", got)
	}
	for _, ip := range []string{"203.0.113.2", "203.0.113.3"} {
		if got := lookup(p, ip, ""); got.Status != "miss" {
			t.Fatalf("ignored ServiceMode record leaked: %+v", got)
		}
	}
}

func TestAliasModeFallbackUsesOnlyFinalTarget(t *testing.T) {
	p, _ := testPlugin(t, Args{})
	q := testContext(t, "origin.test", "", dns.TypeHTTPS, "origin.test. 60 IN HTTPS 0 intermediate.test.")
	for _, text := range []string{
		"intermediate.test. 60 IN CNAME alias.test.",
		"alias.test. 60 IN HTTPS 0 final.test.",
		"final.test. 60 IN A 203.0.113.1",
		"alias.test. 60 IN A 203.0.113.2",
	} {
		rr, _ := dns.NewRR(text)
		q.R().Extra = append(q.R().Extra, rr)
	}
	p.record(q)
	if got := lookup(p, "203.0.113.1", ""); got.Domain != "origin.test" {
		t.Fatalf("final fallback endpoint missed: %+v", got)
	}
	if got := lookup(p, "203.0.113.2", ""); got.Status != "miss" {
		t.Fatalf("intermediate alias incorrectly used as fallback: %+v", got)
	}
}

func TestHandlerReleasesPendingAllocationOnFailureOrTruncation(t *testing.T) {
	for _, failure := range []string{"pack", "truncation"} {
		t.Run(failure, func(t *testing.T) {
			p, _ := testPlugin(t, Args{Allocation: AllocationArgs{Enable: true, Size: 2}})
			entry := sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
				tail := sequence.NewChainWalker([]*sequence.ChainNode{{E: sequence.ExecutableFunc(func(_ context.Context, q *query_context.Context) error {
					r := testContext(t, "origin.test", "", dns.TypeA, "origin.test. 60 IN CNAME endpoint.test.").R()
					for i := 1; i <= 100; i++ {
						rr, _ := dns.NewRR(fmt.Sprintf("endpoint.test. 60 IN A 203.0.113.%d", i))
						r.Answer = append(r.Answer, rr)
					}
					q.SetResponse(r)
					return nil
				})}}, nil)
				return p.Exec(ctx, q, tail)
			})
			h := server_handler.NewEntryHandler(server_handler.EntryHandlerOpts{Entry: entry})
			query := new(dns.Msg)
			query.SetQuestion("origin.test.", dns.TypeA)
			h.Handle(context.Background(), query, server.QueryMeta{FromUDP: failure == "truncation"}, func(m *dns.Msg) (*[]byte, error) {
				if len(p.alloc.leases) != 2 || p.alloc.pendingOverflow != 1 {
					t.Fatal("expected bounded reservations and pending overflow before encoding")
				}
				if failure == "pack" {
					return nil, errors.New("injected pack failure")
				}
				if !m.Truncated {
					t.Fatal("fixture did not trigger truncation")
				}
				b, err := m.Pack()
				return &b, err
			})
			if stats := p.Snapshot(); stats.Observations != 0 || stats.Leases != 0 || !stats.BlockedUntil.IsZero() {
				t.Fatalf("failed/truncated response was committed: %+v", stats)
			}
			if len(p.alloc.leases) != 0 || p.alloc.pendingOverflow != 0 {
				t.Fatal("pending allocation leaked after finalization")
			}
		})
	}
}
