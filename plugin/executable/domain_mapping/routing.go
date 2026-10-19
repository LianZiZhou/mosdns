package domain_mapping

import (
	"container/list"
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"time"
)

const (
	defaultRoutingSize = 4096
	maxRecentDomains   = 32
)

// RoutingArgs controls the small, single-value DNS hint LRU, independently of
// allocation history. Like Mihomo's native redir-host map, a hint survives its
// DNS TTL until replaced or evicted. It is a hint, never an ownership proof.
type RoutingArgs struct {
	Size int `yaml:"size"`
}

func (a *RoutingArgs) normalize() error {
	if a.Size < 0 || a.Size > 1048576 {
		return fmt.Errorf("domain_mapping routing size must be between 0 and 1048576")
	}
	if a.Size == 0 {
		a.Size = defaultRoutingSize
	}
	return nil
}

type recentDomain struct {
	observedAt time.Time
	expiresAt  time.Time
}

type routingHint struct {
	key          lookupKey
	domain       string
	source       string
	observedAt   time.Time
	dnsExpiresAt time.Time
	recent       map[string]recentDomain
	// A discarded name can still be relevant until its evidence expires.
	// Do not present a truncated set as complete on a later lookup.
	truncatedUntil time.Time
	order          *list.Element
}

type routingCache struct {
	size      int
	entries   map[lookupKey]*routingHint
	order     list.List
	evictions uint64
	touches   uint64
	sequence  uint64
}

func (c *routingCache) init(size int) {
	*c = routingCache{size: size, entries: make(map[lookupKey]*routingHint)}
}

func recentWindow(ttl time.Duration) time.Duration {
	// uint32 DNS TTLs fit comfortably in a duration even after multiplying
	// by ten; cap first to avoid accepting overflow from corrupt state.
	if ttl >= 24*time.Hour/10 {
		return 24 * time.Hour
	}
	return max(5*time.Minute, ttl*10)
}

func (h *routingHint) prune(now time.Time) {
	for domain, evidence := range h.recent {
		if !now.Before(evidence.expiresAt) {
			delete(h.recent, domain)
		}
	}
}

// observe always accepts the actual next finalized DNS response, even when the
// wall clock moved backwards since a persisted observation. Replay alone uses
// timestamps to order legacy records; wall time must never pin a live identity.
func (c *routingCache) observe(key lookupKey, domain, source string, observedAt, dnsExpiresAt time.Time) {
	c.observeOrdered(key, domain, source, observedAt, dnsExpiresAt, false)
}

func (c *routingCache) observeOrdered(key lookupKey, domain, source string, observedAt, dnsExpiresAt time.Time, replay bool) {
	c.sequence++
	h := c.entries[key]
	if h == nil {
		if len(c.entries) >= c.size {
			old := c.order.Front().Value.(*routingHint)
			delete(c.entries, old.key)
			c.order.Remove(old.order)
			c.evictions++
		}
		h = &routingHint{key: key, recent: make(map[string]recentDomain)}
		h.order = c.order.PushBack(h)
		c.entries[key] = h
	}
	if !replay && observedAt.Before(h.observedAt) {
		// Future-dated facts belong to an invalid clock epoch. Keeping their
		// deadlines would extend conflicts beyond the configured horizon.
		clear(h.recent)
		h.truncatedUntil = time.Time{}
	}
	if !replay || !observedAt.Before(h.observedAt) {
		h.domain, h.source = domain, source
		h.observedAt, h.dnsExpiresAt = observedAt, dnsExpiresAt
		c.order.MoveToBack(h.order)
	}
	h.prune(observedAt)
	evidence := recentDomain{observedAt: observedAt, expiresAt: observedAt.Add(recentWindow(dnsExpiresAt.Sub(observedAt)))}
	if old, exists := h.recent[domain]; exists {
		if !replay || !observedAt.Before(old.observedAt) {
			h.recent[domain] = evidence
		}
		return
	}
	if len(h.recent) >= maxRecentDomains {
		// Retain the latest observed names, with a deterministic tie-break.
		oldestDomain := ""
		var oldest recentDomain
		for name, entry := range h.recent {
			if oldestDomain == "" || entry.observedAt.Before(oldest.observedAt) || (entry.observedAt.Equal(oldest.observedAt) && name < oldestDomain) {
				oldestDomain, oldest = name, entry
			}
		}
		if observedAt.Before(oldest.observedAt) {
			h.truncatedUntil = maxTime(h.truncatedUntil, evidence.expiresAt)
			return
		}
		h.truncatedUntil = maxTime(h.truncatedUntil, oldest.expiresAt)
		delete(h.recent, oldestDomain)
	}
	h.recent[domain] = evidence
}

// restoreRoutingHint deliberately ignores retained expiry/LRU activity. Old
// state may contain years of historical candidates; only actual DNS times can
// restore the last hint and the bounded recent evidence window.
func (p *DomainMapping) restoreRoutingHint(r stateRecord, client, ip netip.Addr) {
	key := lookupKey{client: client, ip: ip}
	if p.routes.entries[key] == nil && len(p.routes.entries) >= p.routes.size {
		// A snapshot is sorted by DNS time, but an overlapping WAL can replay
		// older records afterwards. It must not evict a newer restored hint.
		oldest := p.routes.order.Front().Value.(*routingHint)
		if r.ObservedAt.Before(oldest.observedAt) {
			return
		}
	}
	p.routes.observeOrdered(key, r.Domain, r.Source, r.ObservedAt, r.DNSExpiresAt, true)
}

// LookupResultV3 separates a best-effort DNS hint, bounded recent facts and
// allocation recovery. CandidatesComplete describes only truncation of the
// recent set, never completeness of all possible domain owners of this IP.
type LookupResultV3 struct {
	Version              int        `json:"version"`
	Status               string     `json:"status"`
	IP                   string     `json:"ip"`
	Scope                string     `json:"scope"`
	Domain               string     `json:"domain,omitempty"`
	Source               string     `json:"source,omitempty"`
	ObservedAt           *time.Time `json:"observed_at,omitempty"`
	DNSExpiresAt         *time.Time `json:"dns_expires_at,omitempty"`
	DNSStale             bool       `json:"dns_stale,omitempty"`
	RetentionMode        string     `json:"retention_mode"`
	Domains              []string   `json:"domains"`
	CandidatesComplete   bool       `json:"candidates_complete"`
	Reason               string     `json:"reason,omitempty"`
	Generation           uint64     `json:"generation"`
	AllocationRecovering bool       `json:"allocation_recovering"`
}

func (p *DomainMapping) LookupV3Context(ctx context.Context, ip, client netip.Addr) (LookupResultV3, error) {
	ip, client = ip.Unmap(), client.Unmap()
	// No historical-index expiry work is needed on the v3 routing hot path.
	if err := p.mu.LockContext(ctx); err != nil {
		return LookupResultV3{}, err
	}
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return LookupResultV3{}, err
	}
	result := LookupResultV3{Version: 3, Status: "miss", IP: ip.String(), Scope: "global", RetentionMode: retentionLRU, Domains: []string{}, CandidatesComplete: true, Generation: p.generation + p.routes.sequence}
	if client.IsValid() {
		result.Scope = "client"
	}
	now := p.now()
	if err := ctx.Err(); err != nil {
		return LookupResultV3{}, err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return LookupResultV3{}, context.DeadlineExceeded
	}
	if p.clients != nil {
		result.AllocationRecovering = now.Before(p.clients.guardUntil) || now.Before(p.clients.incompleteUntil) || (p.state != nil && p.state.failed.Load())
	}
	// No fallback across clients: a small LRU miss is ordinary missing evidence.
	if h := p.routes.entries[lookupKey{client: client, ip: ip}]; h != nil {
		if h.observedAt.After(now) {
			// A restored future timestamp is not current DNS evidence after a
			// clock correction. Do not keep it hot until wall time catches up.
			delete(p.routes.entries, h.key)
			p.routes.order.Remove(h.order)
			p.routes.evictions++
			return result, ctx.Err()
		}
		h.prune(now)
		result.Status, result.Domain, result.Source = "hit", h.domain, h.source
		observedAt, dnsExpiresAt := h.observedAt, h.dnsExpiresAt
		result.ObservedAt, result.DNSExpiresAt = &observedAt, &dnsExpiresAt
		result.DNSStale = !now.Before(dnsExpiresAt)
		for domain := range h.recent {
			result.Domains = append(result.Domains, domain)
		}
		sort.Strings(result.Domains)
		result.CandidatesComplete = !now.Before(h.truncatedUntil)
		if !result.CandidatesComplete {
			result.Reason = "candidate_limit"
		}
		// Access changes only this single hint's capacity priority. It never
		// touches the historical index or extends any domain's DNS evidence.
		p.routes.order.MoveToBack(h.order)
		p.routes.touches++
	}
	return result, ctx.Err()
}

func (p *DomainMapping) serveV3(w http.ResponseWriter, req *http.Request) {
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
	result, err := p.LookupV3Context(ctx, ip, client)
	if err != nil {
		p.apiError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	p.writeAPIJSON(w, result)
}
