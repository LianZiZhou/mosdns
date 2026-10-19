package domain_mapping

import (
	"container/list"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/miekg/dns"
)

// An allocation preference records a successfully returned singleton family,
// independently of every domain that may later expose its IP. It is not a
// claim that the address is exclusive and is never used as a routing identity.
type preferenceKey struct {
	client netip.Addr
	domain string
	ipv6   bool
}

type allocationPreference struct {
	key        preferenceKey
	ip         netip.Addr
	observedAt time.Time
	order      *list.Element
}

type preferenceCache struct {
	size    int
	entries map[preferenceKey]*allocationPreference
	order   list.List
}

type statePreference struct {
	Client     string    `json:"client"`
	Domain     string    `json:"domain"`
	IP         string    `json:"ip"`
	ObservedAt time.Time `json:"observed_at"`
}

func (c *preferenceCache) init(size int) {
	*c = preferenceCache{size: size, entries: make(map[preferenceKey]*allocationPreference)}
}

func (c *preferenceCache) get(key preferenceKey) netip.Addr {
	if entry := c.entries[key]; entry != nil {
		c.order.MoveToBack(entry.order)
		return entry.ip
	}
	return netip.Addr{}
}

func (c *preferenceCache) put(key preferenceKey, ip netip.Addr, observedAt time.Time) {
	if entry := c.entries[key]; entry != nil {
		entry.ip, entry.observedAt = ip, observedAt
		c.order.MoveToBack(entry.order)
		return
	}
	if len(c.entries) >= c.size {
		old := c.order.Front().Value.(*allocationPreference)
		delete(c.entries, old.key)
		c.order.Remove(old.order)
	}
	entry := &allocationPreference{key: key, ip: ip, observedAt: observedAt}
	entry.order = c.order.PushBack(entry)
	c.entries[key] = entry
}

// Do not learn from the unscreened multi-address fallback. Only actual encoded
// singleton families can become stable preferences; failed encoding cannot.
func (p *DomainMapping) rememberClientPreferences(client netip.Addr, domain string, response *dns.Msg, now time.Time) []statePreference {
	if !client.IsValid() || !plainResponseSafe(domain, response) {
		return nil
	}
	var families [2]map[netip.Addr]bool
	evidence, _ := responseEvidence(domain, response)
	for _, e := range evidence {
		family := 0
		if e.ip.Is6() {
			family = 1
		}
		if families[family] == nil {
			families[family] = make(map[netip.Addr]bool)
		}
		families[family][e.ip] = true
	}
	var persisted []statePreference
	for family, ips := range families {
		if len(ips) != 1 {
			continue
		}
		for ip := range ips {
			key := preferenceKey{client: client, domain: domain, ipv6: family == 1}
			if p.clients != nil && p.clients.guard.has(client, netip.Addr{}, domain) {
				old := p.preferences.entries[key]
				if old == nil || old.ip != ip {
					continue
				}
			}
			p.preferences.put(key, ip, now)
			persisted = append(persisted, statePreference{Client: client.String(), Domain: domain, IP: ip.String(), ObservedAt: now})
		}
	}
	return persisted
}

func (p *DomainMapping) preferenceSnapshot() []statePreference {
	result := make([]statePreference, 0, len(p.preferences.entries))
	for entry := p.preferences.order.Front(); entry != nil; entry = entry.Next() {
		v := entry.Value.(*allocationPreference)
		result = append(result, statePreference{Client: v.key.client.String(), Domain: v.key.domain, IP: v.ip.String(), ObservedAt: v.observedAt})
	}
	return result
}

func (p *DomainMapping) restorePreferences(records []statePreference) error {
	if len(records) > 1048576 {
		return fmt.Errorf("too many allocation preferences")
	}
	// Limits can shrink between restarts. Keep preferences with the newest
	// actual DNS observations, rather than arbitrary JSON/map order.
	sort.SliceStable(records, func(i, j int) bool { return records[i].ObservedAt.Before(records[j].ObservedAt) })
	for _, record := range records {
		client, err := parseStateClient(record.Client)
		if err != nil || !client.IsValid() {
			return fmt.Errorf("invalid allocation preference client")
		}
		ip, err := netip.ParseAddr(record.IP)
		if err != nil || ip.Zone() != "" || record.ObservedAt.IsZero() || len(record.Domain) > 253 || canonicalName(record.Domain) != record.Domain || record.Domain == "" {
			return fmt.Errorf("invalid allocation preference")
		}
		if _, ok := dns.IsDomainName(record.Domain); !ok {
			return fmt.Errorf("invalid allocation preference domain")
		}
		ip = ip.Unmap()
		key := preferenceKey{client: client, domain: record.Domain, ipv6: ip.Is6()}
		if old := p.preferences.entries[key]; old != nil && old.observedAt.After(record.ObservedAt) {
			continue
		}
		p.preferences.put(key, ip, record.ObservedAt)
	}
	return nil
}
