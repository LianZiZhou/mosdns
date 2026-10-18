// Package domain_mapping records successfully encoded DNS answers.
// Place this recursive plugin outside all caches and fallback branches.
package domain_mapping

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
	"golang.org/x/sync/semaphore"
)

const PluginType = "domain_mapping"

type Args struct {
	Size       int            `yaml:"size"`
	Allocation AllocationArgs `yaml:"allocation"`
	API        APIArgs        `yaml:"api"`
}

type APIArgs struct {
	MaxConcurrent int `yaml:"max_concurrent"`
	Timeout       int `yaml:"timeout"` // milliseconds; zero uses 1000
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
	APIActive         int64     `json:"api_active"`
	APIRejected       uint64    `json:"api_rejected"`
	APITimeouts       uint64    `json:"api_timeouts"`
}

type DomainMapping struct {
	mu          contextMutex
	args        Args
	now         func() time.Time
	index       observationIndex
	alloc       allocator
	stats       Stats
	apiSlots    *semaphore.Weighted
	apiActive   atomic.Int64
	apiRejected atomic.Uint64
	apiTimeouts atomic.Uint64
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
	if args.API.MaxConcurrent < 0 || args.API.Timeout < 0 || int64(args.API.Timeout) > int64((1<<63-1)/time.Millisecond) {
		return nil, fmt.Errorf("domain_mapping api limits must be non-negative and timeout must fit a duration")
	}
	if args.API.MaxConcurrent == 0 {
		args.API.MaxConcurrent = 128
	}
	if args.API.Timeout == 0 {
		args.API.Timeout = 1000
	}
	if args.Size == 0 {
		args.Size = 65536
	}
	if args.Allocation.Size == 0 {
		args.Allocation.Size = args.Size
	}
	p := &DomainMapping{args: args, now: time.Now, mu: newContextMutex(), apiSlots: semaphore.NewWeighted(int64(args.API.MaxConcurrent))}
	p.index.init(args.Size)
	p.alloc.init(args.Allocation.Size)
	p.stats.AllocationEnabled = args.Allocation.Enable
	return p, nil
}

func (p *DomainMapping) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	if err := next.ExecNext(ctx, qCtx); err != nil {
		return err
	}
	finalize := p.prepare(qCtx)
	if finalize != nil {
		qCtx.OnResponseFinalized(finalize)
	}
	return nil
}

func (p *DomainMapping) prepare(qCtx *query_context.Context) func(*dns.Msg) {
	r := qCtx.R()
	if r == nil || r.Rcode != dns.RcodeSuccess || r.Truncated {
		return nil
	}
	domain := canonicalName(qCtx.QQuestion().Name)
	if domain == "" {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	var reserved reservation
	allocated := false
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
			allocated = true
		}
		// Reserve every planned address, including unscreened fallback
		// responses. Concurrent selection must see these until encoding
		// either commits the final response or releases the reservation.
		reserved = p.alloc.reserve(domain, r)
	}
	client := qCtx.ServerMeta.ClientAddr.Unmap()
	return func(response *dns.Msg) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.args.Allocation.Enable {
			p.alloc.release(reserved)
		}
		if response == nil || response.Rcode != dns.RcodeSuccess || response.Truncated {
			return
		}
		// A truncated reply is deliberately not evidence. A subsequent TCP
		// retry will register its complete, successfully encoded response.
		if allocated {
			p.stats.Allocated++
		}
		p.observe(domain, client, response, p.now())
	}
}

// observe is called under p.mu only for the final encoded response.
func (p *DomainMapping) observe(domain string, client netip.Addr, r *dns.Msg, now time.Time) {
	// DNS updates must not drain an entire expired index while holding the
	// response-finalization lock. put also reclaims expired capacity first.
	p.index.expireBatch(now, observationExpiryBatch)
	p.alloc.expire(now)
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
		p.stats.ObservationEvicts += p.index.put(client, e.ip, Candidate{
			Domain: domain, Source: e.source, ObservedAt: now, ExpiresAt: expires,
		})
		if p.args.Allocation.Enable {
			p.rememberLease(leaseKey{domain: domain, ip: e.ip}, expires)
		}
	}
}

func (p *DomainMapping) Lookup(ip, client netip.Addr) LookupResult {
	result, _ := p.lookupContext(context.Background(), ip, client, false)
	return result
}

// LookupRouteContext returns only routing evidence, without constructing the
// diagnostic candidate list. It observes cancellation during lock/expiry work.
func (p *DomainMapping) LookupRouteContext(ctx context.Context, ip, client netip.Addr) (LookupResult, error) {
	return p.lookupContext(ctx, ip, client, true)
}

// lockCurrent leaves mu locked only on success. Cleanup releases the lock after
// each bounded batch so DNS response registration can make progress as well.
func (p *DomainMapping) lockCurrent(ctx context.Context) error {
	for {
		if err := p.mu.LockContext(ctx); err != nil {
			return err
		}
		if p.index.expireBatch(p.now(), observationExpiryBatch) {
			return nil
		}
		p.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		runtime.Gosched()
	}
}

func (p *DomainMapping) lookupContext(ctx context.Context, ip, client netip.Addr, routeOnly bool) (LookupResult, error) {
	ip, client = ip.Unmap(), client.Unmap()
	if err := p.lockCurrent(ctx); err != nil {
		return LookupResult{}, err
	}
	defer p.mu.Unlock()
	result := LookupResult{Version: 1, Status: "miss", IP: ip.String(), Scope: "global", Candidates: []Candidate{}}
	var selected Candidate
	var found bool
	if routeOnly {
		if client.IsValid() {
			selected, result.Conflict, found = p.index.route(lookupKey{client: client, ip: ip})
			if found {
				result.Scope = "client"
			}
		}
		if !found {
			selected, result.Conflict, found = p.index.route(lookupKey{ip: ip})
		}
	} else {
		var err error
		if client.IsValid() {
			result.Candidates, err = p.index.candidatesContext(ctx, lookupKey{client: client, ip: ip})
			if err != nil {
				return LookupResult{}, err
			}
			if len(result.Candidates) > 0 {
				result.Scope = "client"
			}
		}
		if len(result.Candidates) == 0 {
			result.Candidates, err = p.index.candidatesContext(ctx, lookupKey{ip: ip})
			if err != nil {
				return LookupResult{}, err
			}
		}
		if len(result.Candidates) > 0 {
			selected, found = result.Candidates[0], true
			result.Conflict = len(result.Candidates) > 1
		}
	}
	if found {
		result.Status, result.Domain, result.Source = "hit", selected.Domain, selected.Source
		result.ObservedAt, result.ExpiresAt = &selected.ObservedAt, &selected.ExpiresAt
	}
	if err := ctx.Err(); err != nil {
		return LookupResult{}, err
	}
	return result, nil
}

func (p *DomainMapping) Snapshot() Stats {
	s, _ := p.snapshotContext(context.Background())
	return s
}

func (p *DomainMapping) snapshotContext(ctx context.Context) (Stats, error) {
	if err := p.lockCurrent(ctx); err != nil {
		return Stats{}, err
	}
	defer p.mu.Unlock()
	now := p.now()
	p.alloc.expire(now)
	s := p.stats
	s.Observations, s.Leases = len(p.index.records), len(p.alloc.expiry)
	if now.Before(p.alloc.blockedUntil) {
		s.BlockedUntil = p.alloc.blockedUntil
	}
	s.APIActive, s.APIRejected, s.APITimeouts = p.apiActive.Load(), p.apiRejected.Load(), p.apiTimeouts.Load()
	return s, ctx.Err()
}

func (p *DomainMapping) API() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/v1/lookup", p.ServeHTTP)
	r.Get("/v1/stats", func(w http.ResponseWriter, req *http.Request) {
		ctx, done, ok := p.beginAPI(w, req)
		if !ok {
			return
		}
		defer done()
		stats, err := p.snapshotContext(ctx)
		if err != nil {
			p.apiError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		p.writeAPIJSON(w, stats)
	})
	return r
}

func (p *DomainMapping) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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
	if values, present := query["client"]; present {
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
	routeOnly := false
	if views, present := query["view"]; present {
		if len(views) != 1 || (views[0] != "route" && views[0] != "full") {
			http.Error(w, "invalid view parameter", http.StatusBadRequest)
			return
		}
		routeOnly = views[0] == "route"
	}
	result, err := p.lookupContext(ctx, ip, client, routeOnly)
	if err != nil {
		p.apiError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if routeOnly {
		// Shadow the field only on this opt-in wire view. The default v1 and
		// exported LookupResult JSON contract keep their candidate arrays.
		p.writeAPIJSON(w, struct {
			LookupResult
			Candidates []Candidate `json:"candidates,omitempty"`
		}{LookupResult: result})
	} else {
		p.writeAPIJSON(w, result)
	}
}

func (p *DomainMapping) beginAPI(w http.ResponseWriter, req *http.Request) (context.Context, func(), bool) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(req.Context(), time.Duration(p.args.API.Timeout)*time.Millisecond)
	deadline, _ := ctx.Deadline()
	// A context cannot interrupt ResponseWriter.Write or net/http's automatic
	// draining of an unread request body, even on GET. Keep both deadlines
	// installed through the server's final flush and body.Close, including
	// rejections. net/http resets them before reusing the connection.
	// ResponseRecorder and non-network writers may not support deadlines.
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline)
	if err := ctx.Err(); err != nil {
		cancel()
		p.apiError(w, err)
		return nil, nil, false
	}
	if !p.apiSlots.TryAcquire(1) {
		cancel()
		p.apiRejected.Add(1)
		http.Error(w, "domain_mapping API is overloaded", http.StatusServiceUnavailable)
		return nil, nil, false
	}
	p.apiActive.Add(1)
	return ctx, func() { cancel(); p.apiActive.Add(-1); p.apiSlots.Release(1) }, true
}

func (p *DomainMapping) writeAPIJSON(w http.ResponseWriter, value any) {
	if err := json.NewEncoder(w).Encode(value); os.IsTimeout(err) {
		// Headers may already be on the wire; do not append an error response.
		// A timeout in the server's final buffered flush is outside the handler
		// and cannot be counted here.
		p.apiTimeouts.Add(1)
	}
}

func (p *DomainMapping) apiError(w http.ResponseWriter, err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		p.apiTimeouts.Add(1)
	}
	http.Error(w, "domain_mapping query unavailable: "+err.Error(), http.StatusServiceUnavailable)
}
