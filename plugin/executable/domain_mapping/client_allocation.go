package domain_mapping

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

const exposureGuardBytes = 8 << 20

// The non-decaying guard may have false positives, never false negatives. Losing
// detailed LRU ownership therefore cannot turn a previously used address free.
type exposureGuard []byte

func (g exposureGuard) positions(client, ip netip.Addr, domain string) [4]uint64 {
	var raw [32]byte
	if client.IsValid() {
		a := client.Unmap().As16()
		copy(raw[:16], a[:])
	}
	if ip.IsValid() {
		a := ip.Unmap().As16()
		copy(raw[16:], a[:])
	}
	h := sha256.New()
	_, _ = h.Write(raw[:])
	_, _ = h.Write([]byte(domain))
	sum := h.Sum(nil)
	a, b := binary.LittleEndian.Uint64(sum[:8]), binary.LittleEndian.Uint64(sum[8:16])|1
	n := uint64(len(g)) * 8
	return [4]uint64{a % n, (a + b) % n, (a + 2*b) % n, (a + 3*b) % n}
}
func (g exposureGuard) add(client, ip netip.Addr, domain string) {
	for _, bit := range g.positions(client, ip, domain) {
		g[bit>>3] |= 1 << uint(bit&7)
	}
}
func (g exposureGuard) has(client, ip netip.Addr, domain string) bool {
	for _, bit := range g.positions(client, ip, domain) {
		if g[bit>>3]&(1<<uint(bit&7)) == 0 {
			return false
		}
	}
	return true
}

type clientAllocator struct {
	pending      map[lookupKey]map[string]int
	pendingCount int
	size         int
	guard        exposureGuard
	guardUntil   time.Time
	// Unlike migration allocation guards, lost WAL ownership also invalidates
	// uniqueness of already populated buckets until the recovery horizon.
	incompleteUntil time.Time
	recovery        bool
	closing         bool
	late            bool
	inflight        sync.WaitGroup
	taints          []stateKey
	journalReady    bool
}

func newClientAllocator(size int) *clientAllocator {
	return &clientAllocator{pending: make(map[lookupKey]map[string]int), size: size, guard: make(exposureGuard, exposureGuardBytes)}
}

func (p *DomainMapping) forgetObservation(o *observation) {
	if p.clients == nil {
		return
	}
	p.clients.guard.add(o.key.client, o.key.ip, "")
	p.clients.guard.add(netip.Addr{}, o.key.ip, "")
	if p.clients.journalReady && len(p.clients.taints) < 4096 {
		p.clients.taints = append(p.clients.taints, stateKey{Client: o.key.client.String(), IP: o.key.ip.String()})
	}
	p.generation++
}

func (p *DomainMapping) clientCompatible(key lookupKey, domain string, now time.Time) (occupied, compatible bool) {
	a := p.clients
	if a.guard.has(key.client, key.ip, "") {
		return true, false
	}
	owners := make(map[string]bool)
	if b := p.index.buckets[key]; b != nil {
		if len(b.domains) > maxV2Domains {
			return true, false
		}
		for d := range b.domains {
			owners[d] = true
		}
	}
	for d := range a.pending[key] {
		owners[d] = true
	}
	if len(owners) == 0 {
		return false, !now.Before(a.guardUntil) && !now.Before(a.incompleteUntil)
	}
	share, epoch := p.policy.token(domain, key.client, now)
	for d := range owners {
		if a.guard.has(key.client, netip.Addr{}, "uncertain:"+d) {
			return true, false
		}
		if d == domain {
			continue
		}
		if now.Before(a.incompleteUntil) {
			return true, false
		}
		other, otherEpoch := p.policy.token(d, key.client, now)
		if !share || !other || epoch == "" || epoch != otherEpoch {
			return true, false
		}
	}
	return true, true
}

func (p *DomainMapping) allocateClient(q *query_context.Context, domain string, client netip.Addr, now time.Time) *dns.Msg {
	a := p.clients
	if !client.IsValid() || !allocationSafe(q, domain) || a.guard.has(client, netip.Addr{}, domain) {
		p.stats.Unsafe++
		return nil
	}
	p.policy.token(domain, client, now)
	evidence, _ := responseEvidence(domain, q.R())
	var families [2][]netip.Addr
	ttls := make(map[netip.Addr]uint32)
	for _, e := range evidence {
		if old, ok := ttls[e.ip]; !ok {
			family := 0
			if e.ip.Is6() {
				family = 1
			}
			families[family] = append(families[family], e.ip)
			ttls[e.ip] = e.ttl
		} else {
			ttls[e.ip] = min(old, e.ttl)
		}
	}
	selected := make(map[netip.Addr]bool)
	changed := false
	for _, ips := range families {
		if len(ips) == 0 {
			continue
		}
		sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
		var own, shared, free netip.Addr
		for _, ip := range ips {
			key := lookupKey{client: client, ip: ip}
			occupied, compatible := p.clientCompatible(key, domain, now)
			if !compatible {
				continue
			}
			b := p.index.buckets[key]
			if (b != nil && b.domains[domain] > 0) || a.pending[key][domain] > 0 {
				if !own.IsValid() {
					own = ip
				}
			} else if occupied {
				if !shared.IsValid() {
					shared = ip
				}
			} else if !free.IsValid() {
				free = ip
			}
		}
		chosen := own
		if !chosen.IsValid() {
			chosen = shared
		}
		if !chosen.IsValid() {
			chosen = free
		}
		if !chosen.IsValid() {
			// Exhaustion affects this address family only. Preserve ALL its
			// original alternatives, and reserve/record every returned address.
			p.stats.Exhausted++
			for _, ip := range ips {
				selected[ip] = true
			}
			continue
		}
		selected[chosen] = true
		if len(ips) > 1 {
			changed = true
		}
	}
	if !changed {
		return nil
	}
	r := q.R().Copy()
	r.Answer = nil
	for _, rr := range q.R().Answer {
		var ip netip.Addr
		switch v := rr.(type) {
		case *dns.A:
			ip, _ = netip.AddrFromSlice(v.A)
		case *dns.AAAA:
			ip, _ = netip.AddrFromSlice(v.AAAA)
		}
		ip = ip.Unmap()
		if selected[ip] {
			copy := dns.Copy(rr)
			copy.Header().Ttl = min(copy.Header().Ttl, ttls[ip])
			r.Answer = append(r.Answer, copy)
			selected[ip] = false
		}
	}
	return r
}

func (p *DomainMapping) reserveClient(client netip.Addr, domain string, r *dns.Msg) []lookupKey {
	evidence, _ := responseEvidence(domain, r)
	seen := make(map[lookupKey]bool, len(evidence))
	keys := make([]lookupKey, 0, len(evidence))
	for _, e := range evidence {
		key := lookupKey{client: client, ip: e.ip}
		if seen[key] {
			continue
		}
		seen[key] = true
		owners := p.clients.pending[key]
		if owners == nil {
			owners = make(map[string]int)
			p.clients.pending[key] = owners
		}
		if owners[domain] == 0 && p.clients.pendingCount >= p.clients.size {
			p.clients.guard.add(client, e.ip, "")
			p.clients.guard.add(netip.Addr{}, e.ip, "")
			p.stats.Capacity++
			if len(owners) == 0 {
				delete(p.clients.pending, key)
			}
			continue
		}
		if owners[domain] == 0 {
			p.clients.pendingCount++
		}
		owners[domain]++
		keys = append(keys, key)
	}
	p.generation++
	return keys
}
func (p *DomainMapping) releaseClient(domain string, keys []lookupKey) {
	for _, key := range keys {
		owners := p.clients.pending[key]
		owners[domain]--
		if owners[domain] == 0 {
			delete(owners, domain)
			p.clients.pendingCount--
		}
		if len(owners) == 0 {
			delete(p.clients.pending, key)
		}
	}
	p.generation++
}

func (p *DomainMapping) prepareClient(q *query_context.Context) func(*dns.Msg) {
	r := q.R()
	if r == nil || r.Rcode != dns.RcodeSuccess || r.Truncated {
		return nil
	}
	domain := canonicalName(q.QQuestion().Name)
	if domain == "" {
		return nil
	}
	client := q.ServerMeta.ClientAddr.Unmap()
	p.mu.Lock()
	if p.clients.closing {
		p.clients.late = true
		p.mu.Unlock()
		// Shutdown normally follows ingress shutdown. A late caller must not
		// make a just-written clean checkpoint silently incomplete.
		if err := p.state.markDirty(); err != nil {
			failed := new(dns.Msg)
			failed.SetRcode(q.Q(), dns.RcodeServerFailure)
			q.SetResponse(failed)
		}
		return nil
	}
	allocated := false
	if replacement := p.allocateClient(q, domain, client, p.now()); replacement != nil {
		if opt := q.UpstreamOpt(); opt != nil {
			replacement.Extra = append(replacement.Extra, dns.Copy(opt))
		}
		q.SetResponse(replacement)
		r = replacement
		allocated = true
	}
	keys := p.reserveClient(client, domain, r)
	p.clients.inflight.Add(1)
	p.mu.Unlock()
	return func(response *dns.Msg) {
		defer p.clients.inflight.Done()
		p.mu.Lock()
		defer p.mu.Unlock()
		p.releaseClient(domain, keys)
		if response == nil || response.Rcode != dns.RcodeSuccess || response.Truncated {
			return
		}
		if allocated {
			p.stats.Allocated++
		}
		now := p.now()
		p.observe(domain, client, response, now)
		p.generation++
		// Complex alias/service topologies are preserved, and their known
		// names/addresses remain explicitly uncertain rather than exclusive.
		names, topologyUncertain := uncertainResponseNames(domain, response)
		for _, name := range names {
			p.clients.guard.add(client, netip.Addr{}, name)
			if topologyUncertain {
				p.clients.guard.add(client, netip.Addr{}, "uncertain:"+name)
				p.clients.guard.add(netip.Addr{}, netip.Addr{}, "uncertain:"+name)
			}
		}
		evidence, _ := responseEvidence(domain, response)
		uncertain := topologyUncertain || p.clients.guard.has(client, netip.Addr{}, "uncertain:"+domain)
		for _, e := range evidence {
			if uncertain {
				p.clients.guard.add(client, e.ip, "")
				p.clients.guard.add(netip.Addr{}, e.ip, "")
			}
		}
		event := stateEventFor(domain, client, evidence, names, uncertain, now)
		event.Taints = p.clients.taints
		p.clients.taints = nil
		p.state.enqueue(event)
	}
}

// Only reachable aliases/service targets are associated with this query.
// Conservatively retaining those names also covers later target-only answers.
func uncertainResponseNames(domain string, r *dns.Msg) ([]string, bool) {
	reachable := map[string]bool{domain: true}
	association, uncertain := false, false
	records := r.Answer
	if len(r.Question) == 1 && (r.Question[0].Qtype == dns.TypeHTTPS || r.Question[0].Qtype == dns.TypeSVCB) {
		records = append(append([]dns.RR(nil), r.Answer...), r.Extra...)
	}
	for changed := true; changed; {
		changed = false
		for _, rr := range records {
			if rr.Header().Class != dns.ClassINET || !reachable[canonicalName(rr.Header().Name)] {
				continue
			}
			var target string
			switch v := rr.(type) {
			case *dns.CNAME:
				target = v.Target
				uncertain = true
			case *dns.HTTPS:
				target = v.Target
				if v.Priority == 0 {
					uncertain = true
				}
			case *dns.SVCB:
				target = v.Target
				if v.Priority == 0 {
					uncertain = true
				}
			default:
				continue
			}
			association = true
			target = canonicalName(target)
			if target == "" {
				target = domain
			}
			if target != domain {
				uncertain = true
			}
			if !reachable[target] {
				reachable[target] = true
				changed = true
			}
		}
	}
	if !association {
		return nil, false
	}
	names := make([]string, 0, len(reachable))
	for name := range reachable {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, uncertain
}
