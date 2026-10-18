package domain_mapping

import (
	"context"
	"net/http"
	"net/netip"
	"sort"
	"time"
)

const maxV2Domains = 1024

// LookupResultV2 distinguishes routing policy candidates from a detected host.
// Total is a lower bound when Complete is false (lost owners cannot be counted).
type LookupResultV2 struct {
	Version       int        `json:"version"`
	Status        string     `json:"status"`
	IP            string     `json:"ip"`
	Scope         string     `json:"scope"`
	Domain        string     `json:"domain,omitempty"`
	Domains       []string   `json:"domains"`
	Complete      bool       `json:"complete"`
	Total         int        `json:"total"`
	Generation    uint64     `json:"generation"`
	Reason        string     `json:"reason,omitempty"`
	Source        string     `json:"source,omitempty"`
	ObservedAt    *time.Time `json:"observed_at,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	DNSExpiresAt  *time.Time `json:"dns_expires_at,omitempty"`
	DNSStale      bool       `json:"dns_stale,omitempty"`
	RetentionMode string     `json:"retention_mode,omitempty"`
}

func (p *DomainMapping) LookupV2Context(ctx context.Context, ip, client netip.Addr) (LookupResultV2, error) {
	ip, client = ip.Unmap(), client.Unmap()
	if err := p.lockCurrent(ctx); err != nil {
		return LookupResultV2{}, err
	}
	defer p.mu.Unlock()
	result := LookupResultV2{Version: 2, Status: "miss", IP: ip.String(), Scope: "global", Domains: []string{}, Complete: true, Generation: p.generation + p.index.sequence}
	key := lookupKey{client: client, ip: ip}
	if client.IsValid() {
		result.Scope = "client"
	}
	b := p.index.buckets[key]
	names := make(map[string]bool)
	if b != nil {
		result.Total = len(b.domains)
		for d := range b.domains {
			if len(names) >= maxV2Domains {
				break
			}
			names[d] = true
		}
		if result.Total > maxV2Domains {
			result.Complete = false
			result.Reason = "candidate_limit"
		}
	}
	if p.clients != nil {
		if b != nil && p.now().Before(p.clients.incompleteUntil) {
			result.Complete = false
			result.Reason = "state_recovery"
		}
		// An alias may arrive after its target was already cached. Checking the
		// name dependency here avoids requiring another target DNS request.
		if b != nil {
			for d := range names {
				if p.clients.guard.has(client, netip.Addr{}, "uncertain:"+d) {
					result.Complete = false
					result.Reason = "alias_dependency"
					break
				}
			}
		}
		if p.clients.guard.has(client, ip, "") {
			result.Complete = false
			result.Reason = "unknown_exposure"
		}
		// A new pending owner suppresses uniqueness before encoding completes.
		// A repeat reply for an already retained owner adds no uncertainty.
		if pending := p.clients.pending[key]; len(pending) > 0 {
			for d := range pending {
				if b == nil || b.domains[d] == 0 {
					result.Total++
					result.Complete = false
					if result.Reason == "" {
						result.Reason = "response_pending"
					}
				}
				if len(names) < maxV2Domains {
					names[d] = true
				}
			}
		}
	} else {
		// Legacy modes have no durable eviction/unknown-exposure tracking.
		// v1 remains usable, but v2 must not certify this history as complete.
		result.Complete = false
		result.Reason = "history_untracked"
	}
	for d := range names {
		result.Domains = append(result.Domains, d)
	}
	sort.Strings(result.Domains)
	if len(result.Domains) > 0 || !result.Complete {
		result.Status = "ambiguous"
		if result.Complete && result.Total == 1 {
			result.Status = "hit"
			result.Domain = result.Domains[0]
		}
		if result.Reason == "" && result.Status == "ambiguous" {
			result.Reason = "shared_address"
		}
		if b != nil {
			o := b.order.Back().Value.(*observation)
			now := p.now()
			c := p.index.retentionCandidate(o, now)
			result.Source = c.Source
			result.ObservedAt = &c.ObservedAt
			result.ExpiresAt = &c.ExpiresAt
			result.DNSExpiresAt = c.DNSExpiresAt
			result.DNSStale = c.DNSStale
			result.RetentionMode = c.RetentionMode
			// Keep the whole address bucket hot, never make an arbitrary
			// ambiguity winner newer DNS evidence by selecting it on access.
			visited := 0
			for e := b.order.Front(); e != nil && visited < maxV2Domains; e = e.Next() {
				if visited%128 == 0 {
					if err := ctx.Err(); err != nil {
						return LookupResultV2{}, err
					}
				}
				entry := e.Value.(*observation)
				if client.IsValid() {
					if p.index.touchRoute(entry, now) {
						p.stats.RetentionRenewals++
					}
				} else {
					p.index.order.MoveToBack(entry.order)
				}
				p.stats.RetentionTouches++
				visited++
			}
		} else {
			expires := p.now().Add(time.Minute)
			result.ExpiresAt = &expires
		}
	}
	if err := ctx.Err(); err != nil {
		return LookupResultV2{}, err
	}
	return result, nil
}

func (p *DomainMapping) serveV2(w http.ResponseWriter, req *http.Request) {
	ctx, done, ok := p.beginAPI(w, req)
	if !ok {
		return
	}
	defer done()
	query := req.URL.Query()
	if len(query["ip"]) != 1 {
		http.Error(w, "invalid ip parameter", http.StatusBadRequest)
		return
	}
	ip, err := netip.ParseAddr(query.Get("ip"))
	if err != nil || ip.Zone() != "" {
		http.Error(w, "invalid ip parameter", http.StatusBadRequest)
		return
	}
	var client netip.Addr
	if vals, present := query["client"]; present {
		if len(vals) != 1 {
			http.Error(w, "invalid client parameter", http.StatusBadRequest)
			return
		}
		client, err = netip.ParseAddr(vals[0])
		if err != nil || client.Zone() != "" {
			http.Error(w, "invalid client parameter", http.StatusBadRequest)
			return
		}
	}
	result, err := p.LookupV2Context(ctx, ip, client)
	if err != nil {
		p.apiError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	p.writeAPIJSON(w, result)
}
