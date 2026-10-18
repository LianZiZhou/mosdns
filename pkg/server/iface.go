package server

import (
	"context"
	"net/netip"

	"github.com/miekg/dns"
)

// Handler handles incoming request q and MUST ALWAYS return a response.
// Handler MUST handle dns errors by itself and return a proper error responses.
// e.g. Return a SERVFAIL if something goes wrong.
// If Handle() returns a nil resp, caller will
// udp: do nothing.
// tcp/dot: close the connection immediately.
// doh: send a 500 response.
// doq: close the stream immediately.
type Handler interface {
	Handle(ctx context.Context, q *dns.Msg, meta QueryMeta, packMsgPayload func(m *dns.Msg) (*[]byte, error)) (respPayload *[]byte)
}

type QueryMeta struct {
	FromUDP bool

	// PeerAddr is the transport peer, never an address from a request header or ECS.
	PeerAddr netip.Addr
	// ClientAddr is the effective client identity used by all plugins.
	ClientAddr netip.Addr
	// ClientAddrFromECS reports whether trusted, full-length ECS restored ClientAddr.
	ClientAddrFromECS bool

	// Optional
	ServerName string
	UrlPath    string
}
