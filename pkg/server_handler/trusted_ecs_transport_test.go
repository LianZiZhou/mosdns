package server_handler_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/pkg/server_handler"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func TestTransportPeerRestoresECS(t *testing.T) {
	serverTLS, clientTLS := testTLS(t)
	for _, transport := range []string{"udp", "tcp", "tcp-tls", "quic"} {
		t.Run(transport, func(t *testing.T) {
			metadata := make(chan server.QueryMeta, 1)
			h := server_handler.NewEntryHandler(server_handler.EntryHandlerOpts{
				TrustedECS: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
				Entry: sequence.ExecutableFunc(func(_ context.Context, qc *query_context.Context) error {
					metadata <- qc.ServerMeta
					r := new(dns.Msg)
					r.SetReply(qc.Q())
					qc.SetResponse(r)
					return nil
				}),
			})
			q := query(ecs("192.168.1.10", 32))
			var address string
			serverStopped := make(chan error, 1)
			t.Cleanup(func() {
				select {
				case <-serverStopped:
				case <-time.After(5 * time.Second):
					t.Error("server did not stop after listener closed")
				}
			})
			switch transport {
			case "udp":
				conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
				if err != nil {
					t.Fatal(err)
				}
				address = conn.LocalAddr().String()
				t.Cleanup(func() { conn.Close() })
				go func() { serverStopped <- server.ServeUDP(conn, h, server.UDPServerOpts{}) }()
			case "tcp", "tcp-tls":
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				if transport == "tcp-tls" {
					listener = tls.NewListener(listener, serverTLS)
				}
				address = listener.Addr().String()
				t.Cleanup(func() { listener.Close() })
				go func() { serverStopped <- server.ServeTCP(listener, h, server.TCPServerOpts{}) }()
			case "quic":
				listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{})
				if err != nil {
					t.Fatal(err)
				}
				address = listener.Addr().String()
				t.Cleanup(func() { listener.Close() })
				go func() { serverStopped <- server.ServeDoQ(listener, h, server.DoQServerOpts{}) }()
			}
			if transport == "quic" {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				conn, err := quic.DialAddr(ctx, address, clientTLS, &quic.Config{})
				if err != nil {
					t.Fatal(err)
				}
				defer conn.CloseWithError(0, "")
				stream, err := conn.OpenStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				stream.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := dnsutils.WriteMsgToTCP(stream, q); err != nil {
					t.Fatal(err)
				}
				stream.Close()
				r, _, err := dnsutils.ReadMsgFromTCP(stream)
				if err != nil {
					t.Fatal(err)
				}
				if r.Rcode != dns.RcodeSuccess {
					t.Fatalf("rcode %d", r.Rcode)
				}
			} else {
				client := &dns.Client{Net: transport, Timeout: 5 * time.Second, TLSConfig: clientTLS}
				r, _, err := client.Exchange(q, address)
				if err != nil {
					t.Fatal(err)
				}
				if r.Rcode != dns.RcodeSuccess {
					t.Fatalf("rcode %d", r.Rcode)
				}
			}
			select {
			case got := <-metadata:
				if got.PeerAddr.Unmap() != netip.MustParseAddr("127.0.0.1") || got.ClientAddr != netip.MustParseAddr("192.168.1.10") || !got.ClientAddrFromECS {
					t.Fatalf("wrong client metadata over %s: %+v", transport, got)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("entry did not receive query")
			}
		})
	}
}

func testTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"doq"}},
		&tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"doq"}}
}
