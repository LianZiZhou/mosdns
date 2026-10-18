// Package domain_mapping records the DNS answers actually returned to clients.
// Place this recursive plugin outside all caches and fallback branches.
package domain_mapping

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
)

const PluginType = "domain_mapping"

type Args struct {
	Size       int            `yaml:"size"`
	Allocation AllocationArgs `yaml:"allocation"`
}

type AllocationArgs struct {
	Enable bool `yaml:"enable"`
	Size   int  `yaml:"size"`
}

type Candidate struct {
	Domain     string    `json:"domain"`
	Source     string    `json:"source"`
	ObservedAt time.Time `json:"observed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type LookupResult struct {
	Version    int         `json:"version"`
	Status     string      `json:"status"`
	IP         string      `json:"ip"`
	Domain     string      `json:"domain,omitempty"`
	Scope      string      `json:"scope"`
	Source     string      `json:"source,omitempty"`
	ObservedAt *time.Time  `json:"observed_at,omitempty"`
	ExpiresAt  *time.Time  `json:"expires_at,omitempty"`
	Conflict   bool        `json:"conflict"`
	Candidates []Candidate `json:"candidates"`
}

type Stats struct {
	Observations      int       `json:"observations"`
	ObservationEvicts uint64    `json:"observation_evictions"`
	AllocationEnabled bool      `json:"allocation_enabled"`
	Leases            int       `json:"leases"`
	Allocated         uint64    `json:"allocated"`
	Unsafe            uint64    `json:"allocation_unsafe"`
	Exhausted         uint64    `json:"allocation_exhausted"`
	Capacity          uint64    `json:"allocation_capacity"`
	BlockedUntil      time.Time `json:"allocation_blocked_until"`
}

type DomainMapping struct {
	mu    sync.Mutex
	args  Args
	now   func() time.Time
	index observationIndex
	alloc allocator
	stats Stats
}

var _ sequence.RecursiveExecutable = (*DomainMapping)(nil)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) {
	p, err := New(*args.(*Args))
	if err != nil {
		return nil, err
	}
	bp.RegAPI(p.API())
	return p, nil
}

func New(args Args) (*DomainMapping, error) {
	if args.Size < 0 || args.Allocation.Size < 0 {
		return nil, fmt.Errorf("domain_mapping sizes must not be negative")
	}
	if args.Size == 0 {
		args.Size = 65536
	}
	if args.Allocation.Size == 0 {
		args.Allocation.Size = args.Size
	}
	p := &DomainMapping{args: args, now: time.Now}
	p.index.init(args.Size)
	p.alloc.init(args.Allocation.Size)
	p.stats.AllocationEnabled = args.Allocation.Enable
	return p, nil
}

func (p *DomainMapping) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	if err := next.ExecNext(ctx, qCtx); err != nil {
		return err
	}
	p.record(qCtx)
	return nil
}

func (p *DomainMapping) record(qCtx *query_context.Context) {
	r := qCtx.R()
	if r == nil || r.Rcode != dns.RcodeSuccess || r.Truncated {
		return
	}
	domain := canonicalName(qCtx.QQuestion().Name)
	if domain == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.index.expire(now)
	if p.args.Allocation.Enable {
		p.alloc.expire(now)
		if replacement := p.allocate(qCtx, domain, now); replacement != nil {
			// SetResponse also takes ownership of the upstream OPT. Preserve it
			// when replacing a response whose OPT was already separated out.
			if opt := qCtx.UpstreamOpt(); opt != nil {
				replacement.Extra = append(replacement.Extra, dns.Copy(opt))
			}
			qCtx.SetResponse(replacement)
			r = replacement
		}
	}
	evidence, serviceTTL := responseEvidence(domain, r)
	if p.args.Allocation.Enable && serviceTTL > 0 {
		// Any observed HTTPS/SVCB association can bypass A/AAAA selection,
		// including AliasMode or ServiceMode without explicit address hints.
		p.rememberLease(leaseKey{domain: domain}, now.Add(time.Duration(serviceTTL)*time.Second))
	}
	for _, e := range evidence {
		if e.ttl == 0 {
			continue
		}
		expires := now.Add(time.Duration(e.ttl) * time.Second)
		p.stats.ObservationEvicts += p.index.put(qCtx.ServerMeta.ClientAddr.Unmap(), e.ip, Candidate{
			Domain: domain, Source: e.source, ObservedAt: now, ExpiresAt: expires,
		})
		if p.args.Allocation.Enable {
			p.rememberLease(leaseKey{domain: domain, ip: e.ip}, expires)
		}
	}
}

func (p *DomainMapping) Lookup(ip, client netip.Addr) LookupResult {
	ip, client = ip.Unmap(), client.Unmap()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.index.expire(p.now())
	result := LookupResult{Version: 1, Status: "miss", IP: ip.String(), Scope: "global", Candidates: []Candidate{}}
	if client.IsValid() {
		result.Candidates = p.index.candidates(lookupKey{client: client, ip: ip})
		if len(result.Candidates) > 0 {
			result.Scope = "client"
		}
	}
	if len(result.Candidates) == 0 {
		result.Candidates = p.index.candidates(lookupKey{ip: ip})
	}
	if len(result.Candidates) > 0 {
		selected := result.Candidates[0]
		result.Status, result.Domain, result.Source = "hit", selected.Domain, selected.Source
		result.ObservedAt, result.ExpiresAt = &selected.ObservedAt, &selected.ExpiresAt
		result.Conflict = len(result.Candidates) > 1
	}
	return result
}

func (p *DomainMapping) Snapshot() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.index.expire(now)
	p.alloc.expire(now)
	s := p.stats
	s.Observations, s.Leases = len(p.index.records), len(p.alloc.leases)
	if now.Before(p.alloc.blockedUntil) {
		s.BlockedUntil = p.alloc.blockedUntil
	}
	return s
}

func (p *DomainMapping) API() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/v1/lookup", p.ServeHTTP)
	r.Get("/v1/stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(p.Snapshot())
	})
	return r
}

func (p *DomainMapping) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if len(req.URL.Query()["ip"]) != 1 {
		http.Error(w, "invalid ip parameter", http.StatusBadRequest)
		return
	}
	ip, err := netip.ParseAddr(req.URL.Query().Get("ip"))
	if err != nil || ip.Zone() != "" {
		http.Error(w, "invalid ip parameter", http.StatusBadRequest)
		return
	}
	var client netip.Addr
	if values, present := req.URL.Query()["client"]; present {
		if len(values) != 1 {
			http.Error(w, "invalid client parameter", http.StatusBadRequest)
			return
		}
		client, err = netip.ParseAddr(values[0])
		if err != nil || client.Zone() != "" {
			http.Error(w, "invalid client parameter", http.StatusBadRequest)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(p.Lookup(ip, client))
}
