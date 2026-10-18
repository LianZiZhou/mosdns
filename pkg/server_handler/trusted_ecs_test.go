package server_handler_test

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/pkg/server_handler"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	_ "github.com/IrineSistiana/mosdns/v5/plugin/matcher/client_ip"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func ecs(ip string, bits uint8) *dns.EDNS0_SUBNET {
	addr := netip.MustParseAddr(ip)
	family := uint16(1)
	if addr.Is6() {
		family = 2
	}
	return &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: family, SourceNetmask: bits, Address: net.IP(addr.AsSlice())}
}

func query(options ...dns.EDNS0) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	if options != nil {
		q.SetEdns0(1232, false)
		q.IsEdns0().Option = options
	}
	return q
}

func pack(m *dns.Msg) (*[]byte, error) {
	b, err := m.Pack()
	return &b, err
}

func TestTrustedECSBeforeEntry(t *testing.T) {
	peer := netip.MustParseAddr("127.0.0.1")
	withScope := ecs("192.168.1.10", 32)
	withScope.SourceScope = 32
	badFamily := ecs("192.168.1.10", 32)
	badFamily.Family = 2
	badAddr := ecs("192.168.1.10", 32)
	badAddr.Address = net.IP{192, 168, 1}
	for _, tt := range []struct {
		name     string
		q        *dns.Msg
		peer     netip.Addr
		disabled bool
		want     string
	}{
		{"ipv4", query(ecs("192.168.1.10", 32)), peer, false, "192.168.1.10"},
		{"ipv6", query(ecs("fd00::1234", 128)), peer, false, "fd00::1234"},
		{"mapped_peer", query(ecs("192.168.1.10", 32)), netip.MustParseAddr("::ffff:127.0.0.1"), false, "192.168.1.10"},
		{"disabled", query(ecs("192.168.1.10", 32)), peer, true, ""},
		{"untrusted", query(ecs("192.168.1.10", 32)), netip.MustParseAddr("192.0.2.1"), false, ""},
		{"missing_peer", query(ecs("192.168.1.10", 32)), netip.Addr{}, false, ""},
		{"no_opt", query(), peer, false, ""},
		{"no_ecs", query(&dns.EDNS0_NSID{Code: dns.EDNS0NSID}), peer, false, ""},
		{"ipv4_subnet", query(ecs("192.168.1.0", 24)), peer, false, ""},
		{"ipv6_subnet", query(ecs("fd00::", 64)), peer, false, ""},
		{"duplicate", query(ecs("192.168.1.10", 32), ecs("192.168.1.11", 32)), peer, false, ""},
		{"nonzero_scope", query(withScope), peer, false, ""},
		{"family_mismatch", query(badFamily), peer, false, ""},
		{"short_address", query(badAddr), peer, false, ""},
		{"wrong_option_type", query(&dns.EDNS0_LOCAL{Code: dns.EDNS0SUBNET}), peer, false, ""},
		{"unspecified", query(ecs("0.0.0.0", 32)), peer, false, ""},
		{"multicast", query(ecs("ff02::1", 128)), peer, false, ""},
		{"broadcast", query(ecs("255.255.255.255", 32)), peer, false, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			original := netip.MustParseAddr("127.0.0.1")
			want := original
			if tt.want != "" {
				want = netip.MustParseAddr(tt.want)
			}
			var captured *query_context.Context
			opts := server_handler.EntryHandlerOpts{Entry: sequence.ExecutableFunc(func(_ context.Context, qc *query_context.Context) error {
				captured = qc.Copy()
				if len(qc.QOpt().Option) != 0 {
					t.Error("client ECS unexpectedly forwarded to upstream query")
				}
				r := new(dns.Msg)
				r.SetReply(qc.Q())
				qc.SetResponse(r)
				return nil
			})}
			if !tt.disabled {
				opts.TrustedECS = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
			}
			h := server_handler.NewEntryHandler(opts)
			result := h.Handle(context.Background(), tt.q, server.QueryMeta{PeerAddr: tt.peer, ClientAddr: original}, pack)
			if result == nil || captured == nil {
				t.Fatal("query did not reach entry")
			}
			if captured.ServerMeta.ClientAddr != want {
				t.Errorf("client = %v, want %v", captured.ServerMeta.ClientAddr, want)
			}
			if captured.ServerMeta.PeerAddr != tt.peer {
				t.Errorf("transport peer changed: %v", captured.ServerMeta.PeerAddr)
			}
			if captured.ServerMeta.ClientAddrFromECS != (tt.want != "") {
				t.Errorf("wrong ECS source marker: %+v", captured.ServerMeta)
			}
			enc := zapcore.NewMapObjectEncoder()
			if err := captured.MarshalLogObject(enc); err != nil {
				t.Fatal(err)
			}
			if enc.Fields["client"] != want.String() {
				t.Errorf("wrong client log field: %v", enc.Fields)
			}
			if tt.want != "" && enc.Fields["client_source"] != "ecs" {
				t.Errorf("missing ECS source in log: %v", enc.Fields)
			}
		})
	}
}

func TestNonINETQueryDoesNotRestoreECS(t *testing.T) {
	q := query(ecs("192.168.1.10", 32))
	q.Question[0].Qclass = dns.ClassCHAOS
	h := server_handler.NewEntryHandler(server_handler.EntryHandlerOpts{
		TrustedECS: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		Entry: sequence.ExecutableFunc(func(_ context.Context, qc *query_context.Context) error {
			if qc.ServerMeta.ClientAddrFromECS {
				t.Error("ECS restored for non-IN query")
			}
			return nil
		}),
	})
	h.Handle(context.Background(), q, server.QueryMeta{PeerAddr: netip.MustParseAddr("127.0.0.1")}, pack)
}

func TestTrustedECSClientIPRuleMatchesSameUpstream(t *testing.T) {
	plugins := map[string]any{}
	m := coremain.NewTestMosdnsWithPlugins(plugins)
	for tag, ip := range map[string]string{"client_upstream": "198.51.100.10", "default_upstream": "198.51.100.20"} {
		plugins[tag] = sequence.ExecutableFunc(func(_ context.Context, qc *query_context.Context) error {
			r := new(dns.Msg)
			r.SetReply(qc.Q())
			r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)}}
			qc.SetResponse(r)
			return nil
		})
	}
	s, err := sequence.NewSequence(sequence.NewBQ(m, zap.NewNop()), []sequence.RuleArgs{
		{Matches: []string{"client_ip 192.168.1.0/24"}, Exec: "$client_upstream"},
		{Matches: []string{"client_ip 192.168.1.0/24"}, Exec: "accept"},
		{Exec: "$default_upstream"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := server_handler.NewEntryHandler(server_handler.EntryHandlerOpts{Entry: s, TrustedECS: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	for _, tt := range []struct {
		name string
		q    *dns.Msg
		peer string
		want string
	}{
		{"direct", query(), "192.168.1.10", "198.51.100.10"},
		{"dnsmasq_ecs", query(ecs("192.168.1.10", 32)), "127.0.0.1", "198.51.100.10"},
		{"different_client", query(ecs("192.168.2.10", 32)), "127.0.0.1", "198.51.100.20"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			peer := netip.MustParseAddr(tt.peer)
			b := h.Handle(context.Background(), tt.q, server.QueryMeta{PeerAddr: peer, ClientAddr: peer}, pack)
			if b == nil {
				t.Fatal("no response")
			}
			r := new(dns.Msg)
			if err := r.Unpack(*b); err != nil {
				t.Fatal(err)
			}
			if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != tt.want {
				t.Fatalf("wrong upstream response: %v", r)
			}
		})
	}
}

func TestHTTPHeaderCannotAuthorizeECS(t *testing.T) {
	for _, tt := range []struct {
		name, remote, header, want string
		restored                   bool
	}{
		{"forged_trusted_header", "192.0.2.1:1234", "127.0.0.1", "127.0.0.1", false},
		{"trusted_peer", "127.0.0.1:1234", "192.0.2.1", "192.168.1.10", true},
		{"unix_peer", "@dns-proxy", "127.0.0.1", "127.0.0.1", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var got server.QueryMeta
			h := server_handler.NewEntryHandler(server_handler.EntryHandlerOpts{
				TrustedECS: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
				Entry:      sequence.ExecutableFunc(func(_ context.Context, qc *query_context.Context) error { got = qc.ServerMeta; return nil }),
			})
			hh := server.NewHttpHandler(h, server.HttpHandlerOpts{GetSrcIPFromHeader: "X-Forwarded-For"})
			b, err := query(ecs("192.168.1.10", 32)).Pack()
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "http://localhost/dns-query", bytes.NewReader(b))
			req.RemoteAddr = tt.remote
			req.Header.Set("Content-Type", "application/dns-message")
			req.Header.Set("X-Forwarded-For", tt.header)
			r := httptest.NewRecorder()
			hh.ServeHTTP(r, req)
			if r.Code != http.StatusOK {
				t.Fatalf("status %d", r.Code)
			}
			if got.ClientAddr.String() != tt.want || got.ClientAddrFromECS != tt.restored {
				t.Fatalf("wrong metadata: %+v", got)
			}
			peer, _ := netip.ParseAddrPort(tt.remote)
			if got.PeerAddr != peer.Addr() {
				t.Fatalf("HTTP header replaced transport peer: %+v", got)
			}
		})
	}
}
