package domain_mapping

import (
	"math"
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

func canonicalName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

type evidence struct {
	ip     netip.Addr
	ttl    uint32
	source string
}

// responseEvidence follows only records reachable from the original question.
// For HTTPS/SVCB questions, related Additional records are usable evidence
// (RFC 9460 sections 4.2 and 5). ServiceMode targets lead to address resolution;
// AliasMode targets continue resolution of the same service-binding RR type.
// Unrelated additional records must never become evidence for the question.
// The second result is the lifetime of any reachable HTTPS/SVCB association,
// including bindings without hints and AliasMode records.
func responseEvidence(domain string, r *dns.Msg) ([]evidence, uint32) {
	var bindingType uint16
	if len(r.Question) == 1 && (r.Question[0].Qtype == dns.TypeHTTPS || r.Question[0].Qtype == dns.TypeSVCB) {
		bindingType = r.Question[0].Qtype
	}
	bindings := make(map[string]uint32)
	addresses := make(map[string]uint32)
	aliasAddresses := make(map[string]uint32)
	records := r.Answer
	if bindingType != 0 {
		bindings[domain] = math.MaxUint32
		records = append(append(make([]dns.RR, 0, len(r.Answer)+len(r.Extra)), r.Answer...), r.Extra...)
	} else {
		addresses[domain] = math.MaxUint32
	}
	bindingOf := func(rr dns.RR) (*dns.SVCB, string) {
		switch rr := rr.(type) {
		case *dns.HTTPS:
			if bindingType == dns.TypeHTTPS {
				return &rr.SVCB, "https_hint"
			}
		case *dns.SVCB:
			if bindingType == dns.TypeSVCB {
				return rr, "svcb_hint"
			}
		}
		return nil, ""
	}
	aliasOwners := make(map[string]bool)
	cnameOwners := make(map[string]bool)
	for _, rr := range records {
		if _, ok := rr.(*dns.CNAME); ok && rr.Header().Class == dns.ClassINET {
			cnameOwners[canonicalName(rr.Header().Name)] = true
		}
		if binding, _ := bindingOf(rr); binding != nil && binding.Priority == 0 && rr.Header().Class == dns.ClassINET {
			aliasOwners[canonicalName(rr.Header().Name)] = true
		}
	}
	update := func(reachable map[string]uint32, name string, ttl uint32) bool {
		if name == "" {
			return false
		}
		if old, seen := reachable[name]; !seen || ttl < old {
			reachable[name] = ttl
			return true
		}
		return false
	}
	for changed := true; changed; {
		changed = false
		for _, rr := range records {
			hdr := rr.Header()
			if hdr.Class != dns.ClassINET {
				continue
			}
			owner := canonicalName(hdr.Name)
			if alias, ok := rr.(*dns.CNAME); ok {
				for _, reachable := range []map[string]uint32{addresses, bindings, aliasAddresses} {
					if parentTTL, ok := reachable[owner]; ok {
						changed = update(reachable, canonicalName(alias.Target), min(parentTTL, hdr.Ttl)) || changed
					}
				}
				continue
			}
			binding, _ := bindingOf(rr)
			parentTTL, reachable := bindings[owner]
			if binding == nil || !reachable || (binding.Priority > 0 && aliasOwners[owner]) {
				continue
			}
			target, ttl := canonicalName(binding.Target), min(parentTTL, hdr.Ttl)
			if binding.Priority == 0 {
				changed = update(bindings, target, ttl) || changed
				// SVCB-optional clients also use the final AliasMode target's
				// addresses as a fallback endpoint (RFC 9460 section 3).
				changed = update(aliasAddresses, target, ttl) || changed
			} else {
				if binding.Target == "." {
					target = owner
				}
				changed = update(addresses, target, ttl) || changed
			}
		}
	}
	for name, ttl := range aliasAddresses {
		// Only the final AliasMode/CNAME target is a fallback endpoint;
		// addresses for an intermediate alias are not used by the client.
		if !aliasOwners[name] && !cnameOwners[name] {
			update(addresses, name, ttl)
		}
	}
	var result []evidence
	var serviceTTL uint32
	positions := make(map[struct {
		ip     netip.Addr
		source string
	}]int)
	appendIP := func(ip net.IP, ttl uint32, source string) {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			addr = addr.Unmap()
			key := struct {
				ip     netip.Addr
				source string
			}{addr, source}
			if position, duplicate := positions[key]; duplicate {
				result[position].ttl = min(result[position].ttl, ttl)
				return
			}
			positions[key] = len(result)
			result = append(result, evidence{ip: addr, ttl: ttl, source: source})
		}
	}
	for _, rr := range records {
		hdr := rr.Header()
		if hdr.Class != dns.ClassINET {
			continue
		}
		owner := canonicalName(hdr.Name)
		if chainTTL, reachable := addresses[owner]; reachable {
			ttl := min(hdr.Ttl, chainTTL)
			switch rr := rr.(type) {
			case *dns.A:
				appendIP(rr.A, ttl, "a")
			case *dns.AAAA:
				appendIP(rr.AAAA, ttl, "aaaa")
			}
		}
		binding, source := bindingOf(rr)
		chainTTL, reachable := bindings[owner]
		if binding == nil || !reachable || (binding.Priority > 0 && aliasOwners[owner]) {
			continue
		}
		ttl := min(hdr.Ttl, chainTTL)
		serviceTTL = max(serviceTTL, ttl)
		if binding.Priority == 0 {
			continue // AliasMode has no usable service parameters.
		}
		for _, value := range binding.Value {
			switch value := value.(type) {
			case *dns.SVCBIPv4Hint:
				for _, ip := range value.Hint {
					appendIP(ip, ttl, source)
				}
			case *dns.SVCBIPv6Hint:
				for _, ip := range value.Hint {
					appendIP(ip, ttl, source)
				}
			}
		}
	}
	return result, serviceTTL
}
