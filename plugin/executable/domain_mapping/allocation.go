package domain_mapping

import (
	"container/heap"
	"net/netip"
	"sort"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

type leaseKey struct {
	domain string
	ip     netip.Addr
}

type lease struct {
	key       leaseKey
	expiresAt time.Time
	heapPos   int
	pending   int
}

type reservation struct {
	keys     []leaseKey
	overflow bool
}

type leaseHeap []*lease

func (h leaseHeap) Len() int           { return len(h) }
func (h leaseHeap) Less(i, j int) bool { return h[i].expiresAt.Before(h[j].expiresAt) }
func (h leaseHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapPos, h[j].heapPos = i, j
}
func (h *leaseHeap) Push(v any) {
	l := v.(*lease)
	l.heapPos = len(*h)
	*h = append(*h, l)
}
func (h *leaseHeap) Pop() any {
	old := *h
	l := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	return l
}

// All answers returned to clients occupy their addresses, including answers
// that could not be filtered. Active leases are never evicted to make room.
type allocator struct {
	size         int
	leases       map[leaseKey]*lease
	owners       map[netip.Addr]map[string]*lease
	expiry       leaseHeap
	blockedUntil time.Time
	// Untracked pending responses temporarily block all allocation. Their
	// actual TTL is committed only if final response encoding succeeds.
	pendingOverflow int
}

func (a *allocator) init(size int) {
	a.size = size
	a.leases = make(map[leaseKey]*lease)
	a.owners = make(map[netip.Addr]map[string]*lease)
}

func (a *allocator) expire(now time.Time) {
	for len(a.expiry) > 0 && !now.Before(a.expiry[0].expiresAt) {
		l := heap.Pop(&a.expiry).(*lease)
		l.expiresAt = time.Time{}
		if l.pending == 0 {
			a.remove(l)
		}
	}
}

func (a *allocator) remove(l *lease) {
	delete(a.leases, l.key)
	delete(a.owners[l.key.ip], l.key.domain)
	if len(a.owners[l.key.ip]) == 0 {
		delete(a.owners, l.key.ip)
	}
}

func (a *allocator) add(key leaseKey) *lease {
	l := &lease{key: key}
	a.leases[key] = l
	if a.owners[key.ip] == nil {
		a.owners[key.ip] = make(map[string]*lease)
	}
	a.owners[key.ip][key.domain] = l
	return l
}

func (a *allocator) reserve(domain string, response *dns.Msg) reservation {
	evidence, serviceTTL := responseEvidence(domain, response)
	keys := make(map[leaseKey]struct{}, len(evidence)+1)
	if serviceTTL > 0 {
		keys[leaseKey{domain: domain}] = struct{}{}
	}
	for _, e := range evidence {
		if e.ttl > 0 {
			keys[leaseKey{domain: domain, ip: e.ip}] = struct{}{}
		}
	}
	var reserved reservation
	for key := range keys {
		l := a.leases[key]
		if l == nil {
			if len(a.leases) >= a.size {
				reserved.overflow = true
				continue
			}
			l = a.add(key)
		}
		l.pending++
		reserved.keys = append(reserved.keys, key)
	}
	if reserved.overflow {
		a.pendingOverflow++
	}
	return reserved
}

func (a *allocator) release(reserved reservation) {
	for _, key := range reserved.keys {
		l := a.leases[key]
		l.pending--
		if l.pending == 0 && l.expiresAt.IsZero() {
			a.remove(l)
		}
	}
	if reserved.overflow {
		a.pendingOverflow--
	}
}

func (p *DomainMapping) rememberLease(key leaseKey, expires time.Time) {
	a := &p.alloc
	if existing := a.leases[key]; existing != nil {
		if existing.expiresAt.IsZero() {
			existing.expiresAt = expires
			heap.Push(&a.expiry, existing)
		} else if existing.expiresAt.Before(expires) {
			existing.expiresAt = expires
			heap.Fix(&a.expiry, existing.heapPos)
		}
		return
	}
	if len(a.leases) >= a.size {
		// We cannot forget a returned address and then call it available.
		// Conservatively disable selection until every untracked answer has
		// expired. Continued overload may extend this interval.
		if a.blockedUntil.Before(expires) {
			a.blockedUntil = expires
		}
		p.stats.Capacity++
		return
	}
	l := a.add(key)
	l.expiresAt = expires
	heap.Push(&a.expiry, l)
}

func (p *DomainMapping) allocate(qCtx *query_context.Context, domain string, now time.Time) *dns.Msg {
	r := qCtx.R()
	if !allocationSafe(qCtx, domain) || p.alloc.leases[leaseKey{domain: domain}] != nil {
		p.stats.Unsafe++
		return nil
	}
	if now.Before(p.alloc.blockedUntil) || p.alloc.pendingOverflow > 0 {
		p.stats.Capacity++
		return nil
	}
	var families [2][]netip.Addr
	addressTTLs := make(map[netip.Addr]uint32)
	evidence, _ := responseEvidence(domain, r)
	for _, e := range evidence {
		if e.ttl == 0 {
			p.stats.Unsafe++
			return nil
		}
		family := 0
		if e.ip.Is6() {
			family = 1
		}
		families[family] = append(families[family], e.ip)
		if old, seen := addressTTLs[e.ip]; !seen || e.ttl < old {
			addressTTLs[e.ip] = e.ttl
		}
	}
	selected := make(map[netip.Addr]bool)
	needed := 0
	for _, candidates := range families {
		if len(candidates) == 0 {
			continue
		}
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].Less(candidates[j]) })
		var chosen netip.Addr
		// Prefer an address already returned for this domain. Only sole
		// ownership qualifies: a fallback may have made a lease shared.
		for _, ip := range candidates {
			owners := p.alloc.owners[ip]
			if len(owners) == 1 && owners[domain] != nil {
				chosen = ip
				break
			}
		}
		if !chosen.IsValid() {
			for _, ip := range candidates {
				if len(p.alloc.owners[ip]) == 0 {
					chosen = ip
					needed++
					break
				}
			}
		}
		if !chosen.IsValid() {
			p.stats.Exhausted++
			return nil
		}
		selected[chosen] = true
	}
	if len(selected) == 0 {
		return nil
	}
	if len(p.alloc.leases)+needed > p.alloc.size {
		p.stats.Capacity++
		return nil
	}
	copy := r.Copy()
	copy.Answer = copy.Answer[:0]
	for _, rr := range r.Answer {
		var addr netip.Addr
		switch rr := rr.(type) {
		case *dns.A:
			addr, _ = netip.AddrFromSlice(rr.A)
		case *dns.AAAA:
			addr, _ = netip.AddrFromSlice(rr.AAAA)
		}
		addr = addr.Unmap()
		if selected[addr] {
			selectedRR := dns.Copy(rr)
			selectedRR.Header().Ttl = min(selectedRR.Header().Ttl, addressTTLs[addr])
			copy.Answer = append(copy.Answer, selectedRR)
			selected[addr] = false
		}
	}
	return copy
}

func allocationSafe(qCtx *query_context.Context, domain string) bool {
	r := qCtx.R()
	q := qCtx.QQuestion()
	if q.Qclass != dns.ClassINET || (q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA) || r.AuthenticatedData || r.CheckingDisabled || qCtx.Q().AuthenticatedData || qCtx.Q().CheckingDisabled {
		return false
	}
	if opt := qCtx.ClientOpt(); opt != nil && opt.Do() {
		return false
	}
	if qCtx.QOpt().Do() {
		return false
	}
	return plainResponseSafe(domain, r)
}

func plainResponseSafe(domain string, r *dns.Msg) bool {
	if r == nil || r.Rcode != dns.RcodeSuccess || r.Truncated || r.AuthenticatedData || r.CheckingDisabled {
		return false
	}
	for _, section := range [][]dns.RR{r.Answer, r.Ns, r.Extra} {
		for _, rr := range section {
			switch rr.(type) {
			case *dns.CNAME, *dns.RRSIG, *dns.HTTPS, *dns.SVCB:
				return false
			}
		}
	}
	for _, rr := range r.Answer {
		h := rr.Header()
		if canonicalName(h.Name) != domain || h.Class != dns.ClassINET {
			return false
		}
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
		default:
			return false
		}
	}
	return true
}
