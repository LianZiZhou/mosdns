package server_handler

import (
	"net/netip"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// restoreClientIdentity runs before plugins see ServerMeta. It only consults
// PeerAddr for trust: HTTP forwarding headers must never authorize ECS.
func (h *EntryHandler) restoreClientIdentity(qCtx *query_context.Context) {
	if len(h.opts.TrustedECS) == 0 {
		return
	}
	peer := qCtx.ServerMeta.PeerAddr.Unmap()
	trusted := false
	for _, prefix := range h.opts.TrustedECS {
		if prefix.Contains(peer) {
			trusted = true
			break
		}
	}
	if !trusted {
		h.opts.Logger.Debug("ecs client identity ignored", qCtx.InfoField(), zap.String("reason", "untrusted_peer"))
		return
	}
	addr, reason := fullECSAddress(qCtx)
	if reason != "" {
		h.opts.Logger.Debug("ecs client identity ignored", qCtx.InfoField(), zap.String("reason", reason))
		return
	}
	qCtx.ServerMeta.ClientAddr = addr
	qCtx.ServerMeta.ClientAddrFromECS = true
}

func fullECSAddress(qCtx *query_context.Context) (netip.Addr, string) {
	if qCtx.QQuestion().Qclass != dns.ClassINET {
		return netip.Addr{}, "non_in_query"
	}
	opt := qCtx.ClientOpt()
	if opt == nil {
		return netip.Addr{}, "missing_ecs"
	}
	var ecs *dns.EDNS0_SUBNET
	for _, option := range opt.Option {
		if option.Option() != dns.EDNS0SUBNET {
			continue
		}
		if ecs != nil {
			return netip.Addr{}, "duplicate_ecs"
		}
		var ok bool
		ecs, ok = option.(*dns.EDNS0_SUBNET)
		if !ok || ecs == nil {
			return netip.Addr{}, "invalid_ecs"
		}
	}
	if ecs == nil {
		return netip.Addr{}, "missing_ecs"
	}
	if ecs.SourceScope != 0 {
		return netip.Addr{}, "nonzero_scope"
	}
	addr, ok := netip.AddrFromSlice(ecs.Address)
	if !ok {
		return netip.Addr{}, "invalid_address"
	}
	switch ecs.Family {
	case 1:
		if ecs.SourceNetmask != 32 || !addr.Unmap().Is4() {
			return netip.Addr{}, "invalid_ipv4_ecs"
		}
		addr = addr.Unmap()
	case 2:
		if ecs.SourceNetmask != 128 || !addr.Is6() || addr.Is4In6() {
			return netip.Addr{}, "invalid_ipv6_ecs"
		}
	default:
		return netip.Addr{}, "invalid_family"
	}
	if addr.IsUnspecified() || addr.IsMulticast() || addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, "invalid_client_address"
	}
	return addr, ""
}
