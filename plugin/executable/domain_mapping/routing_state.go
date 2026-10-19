package domain_mapping

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/miekg/dns"
)

type stateRecentDomain struct {
	Domain     string    `json:"domain"`
	ObservedAt time.Time `json:"observed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type stateRoutingHint struct {
	Client         string              `json:"client"`
	IP             string              `json:"ip"`
	Domain         string              `json:"domain"`
	Source         string              `json:"source"`
	ObservedAt     time.Time           `json:"observed_at"`
	DNSExpiresAt   time.Time           `json:"dns_expires_at"`
	Recent         []stateRecentDomain `json:"recent"`
	TruncatedUntil time.Time           `json:"truncated_until,omitempty"`
}

// Capture the actual bounded hint cache in LRU order. Rebuilding it from the
// ownership index on every restart would undo evictions and resurrect stale
// routing identities. Only the first migration may seed hints from old records.
func (p *DomainMapping) routingSnapshot() []stateRoutingHint {
	result := make([]stateRoutingHint, 0, len(p.routes.entries))
	now := p.now()
	for e := p.routes.order.Front(); e != nil; e = e.Next() {
		h := e.Value.(*routingHint)
		h.prune(now)
		r := stateRoutingHint{Client: h.key.client.String(), IP: h.key.ip.String(), Domain: h.domain, Source: h.source, ObservedAt: h.observedAt, DNSExpiresAt: h.dnsExpiresAt, TruncatedUntil: h.truncatedUntil}
		for domain, fact := range h.recent {
			r.Recent = append(r.Recent, stateRecentDomain{Domain: domain, ObservedAt: fact.observedAt, ExpiresAt: fact.expiresAt})
		}
		sort.Slice(r.Recent, func(i, j int) bool { return r.Recent[i].Domain < r.Recent[j].Domain })
		result = append(result, r)
	}
	return result
}

func stateDomainValid(domain string) bool {
	if domain == "" || len(domain) > 253 || canonicalName(domain) != domain {
		return false
	}
	_, ok := dns.IsDomainName(domain)
	return ok
}

func (p *DomainMapping) restoreRouting(records []stateRoutingHint) error {
	if len(records) > 1048576 {
		return fmt.Errorf("too many routing hints")
	}
	p.routes.init(p.args.Routing.Size)
	seen := make(map[lookupKey]bool, len(records))
	for _, r := range records {
		client, err := parseStateClient(r.Client)
		if err != nil {
			return fmt.Errorf("invalid routing client: %w", err)
		}
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || ip.Zone() != "" || !stateDomainValid(r.Domain) || len(r.Source) > 64 || r.ObservedAt.IsZero() || r.DNSExpiresAt.IsZero() || r.DNSExpiresAt.Before(r.ObservedAt) || len(r.Recent) > maxRecentDomains || r.TruncatedUntil.After(r.ObservedAt.Add(24*time.Hour)) {
			return fmt.Errorf("invalid persisted routing hint")
		}
		key := lookupKey{client: client, ip: ip.Unmap()}
		if seen[key] {
			return fmt.Errorf("duplicate persisted routing key")
		}
		seen[key] = true
		h := &routingHint{key: key, domain: r.Domain, source: r.Source, observedAt: r.ObservedAt, dnsExpiresAt: r.DNSExpiresAt, truncatedUntil: r.TruncatedUntil, recent: make(map[string]recentDomain)}
		for _, recent := range r.Recent {
			window := recent.ExpiresAt.Sub(recent.ObservedAt)
			if !stateDomainValid(recent.Domain) || recent.ObservedAt.IsZero() || recent.ObservedAt.After(r.ObservedAt) || window < 5*time.Minute || window > 24*time.Hour {
				return fmt.Errorf("invalid persisted recent routing evidence")
			}
			if _, duplicate := h.recent[recent.Domain]; duplicate {
				return fmt.Errorf("duplicate persisted recent domain")
			}
			h.recent[recent.Domain] = recentDomain{observedAt: recent.ObservedAt, expiresAt: recent.ExpiresAt}
		}
		if len(p.routes.entries) >= p.routes.size {
			old := p.routes.order.Front().Value.(*routingHint)
			delete(p.routes.entries, old.key)
			p.routes.order.Remove(old.order)
			p.routes.evictions++
		}
		h.order = p.routes.order.PushBack(h)
		p.routes.entries[key] = h
	}
	return nil
}
