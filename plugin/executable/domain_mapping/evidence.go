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

// responseEvidence follows only CNAMEs and SVCB/HTTPS aliases reachable from
// the original question.
// Unrelated additional records must never become evidence for the question.
// The second result is the lifetime of any reachable HTTPS/SVCB association,
// including bindings without hints and AliasMode records.
func responseEvidence(domain string, r *dns.Msg) ([]evidence, uint32) {
	ttls := map[string]uint32{domain: math.MaxUint32}
	for changed := true; changed; {
		changed = false
		for _, rr := range r.Answer {
			var targetName string
			switch rr := rr.(type) {
			case *dns.CNAME:
				targetName = rr.Target
			case *dns.HTTPS:
				if rr.Priority == 0 {
					targetName = rr.Target
				}
			case *dns.SVCB:
				if rr.Priority == 0 {
					targetName = rr.Target
				}
			}
			hdr := rr.Header()
			if targetName == "" || targetName == "." || hdr.Class != dns.ClassINET {
				continue
			}
			parentTTL, reachable := ttls[canonicalName(hdr.Name)]
			if !reachable {
				continue
			}
			target, ttl := canonicalName(targetName), min(parentTTL, hdr.Ttl)
			if old, seen := ttls[target]; !seen || ttl < old {
				ttls[target] = ttl
				changed = true
			}
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
	for _, rr := range r.Answer {
		hdr := rr.Header()
		chainTTL, reachable := ttls[canonicalName(hdr.Name)]
		if !reachable || hdr.Class != dns.ClassINET {
			continue
		}
		ttl := min(hdr.Ttl, chainTTL)
		var binding *dns.SVCB
		var source string
		switch rr := rr.(type) {
		case *dns.A:
			appendIP(rr.A, ttl, "a")
		case *dns.AAAA:
			appendIP(rr.AAAA, ttl, "aaaa")
		case *dns.HTTPS:
			binding, source = &rr.SVCB, "https_hint"
		case *dns.SVCB:
			binding, source = rr, "svcb_hint"
		}
		if binding == nil {
			continue
		}
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
