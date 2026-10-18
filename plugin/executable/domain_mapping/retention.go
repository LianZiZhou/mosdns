package domain_mapping

import (
	"fmt"
	"time"
)

const (
	retentionTTL     = "ttl"
	retentionSliding = "sliding"
	retentionLRU     = "lru"
)

// RetentionArgs controls routing evidence independently of the DNS cache TTL.
// Window limits are seconds. LRU retains evidence until capacity eviction;
// its window is the renewable lease advertised to API consumers.
type RetentionArgs struct {
	Mode          string `yaml:"mode"`
	TTLMultiplier int    `yaml:"ttl_multiplier"`
	MinWindow     int    `yaml:"min_window"`
	MaxWindow     int    `yaml:"max_window"`
}

func (r *RetentionArgs) normalize() error {
	if r.Mode == "" {
		r.Mode = retentionTTL
	}
	if r.Mode != retentionTTL && r.Mode != retentionSliding && r.Mode != retentionLRU {
		return fmt.Errorf("domain_mapping retention mode must be ttl, sliding, or lru")
	}
	const maxSeconds = int64((1<<63 - 1) / time.Second)
	if r.TTLMultiplier < 0 || r.MinWindow < 0 || r.MaxWindow < 0 || int64(r.MinWindow) > maxSeconds || int64(r.MaxWindow) > maxSeconds {
		return fmt.Errorf("domain_mapping retention limits must be non-negative and windows must fit a duration")
	}
	// Even the minimum base TTL must fit a duration. Larger DNS TTLs use
	// saturating multiplication in window before applying the maximum.
	if int64(r.TTLMultiplier) > maxSeconds {
		return fmt.Errorf("domain_mapping retention ttl_multiplier must fit a duration")
	}
	if r.TTLMultiplier == 0 {
		r.TTLMultiplier = 10
	}
	if r.MinWindow == 0 {
		r.MinWindow = 300
	}
	if r.MaxWindow == 0 {
		r.MaxWindow = 86400
	}
	if r.MinWindow > r.MaxWindow {
		return fmt.Errorf("domain_mapping retention min_window must not exceed max_window")
	}
	return nil
}

func (r RetentionArgs) extended() bool { return r.Mode == retentionSliding || r.Mode == retentionLRU }

func (r RetentionArgs) window(baseTTL time.Duration) time.Duration {
	baseTTL = max(baseTTL, time.Second)
	// Saturate before multiplication. DNS TTL values are safe already,
	// and this also keeps internal callers safe from duration overflow.
	maximum := time.Duration(r.MaxWindow) * time.Second
	multiplier := time.Duration(r.TTLMultiplier)
	if baseTTL > maximum/multiplier {
		return maximum
	}
	return max(baseTTL*multiplier, time.Duration(r.MinWindow)*time.Second)
}

// retentionCandidate only changes a copy. Diagnostic/global lookups may
// advertise a current lease for LRU evidence, but never extend its owner's
// lease or change its DNS observation ordering.
func (s *observationIndex) retentionCandidate(o *observation, now time.Time) Candidate {
	candidate := o.Candidate
	if !s.retention.extended() {
		return candidate
	}
	if candidate.DNSExpiresAt != nil {
		// Public Lookup callers own their returned timestamps. Never
		// expose a pointer into retained observation state.
		dnsExpires := *candidate.DNSExpiresAt
		candidate.DNSExpiresAt = &dnsExpires
		candidate.DNSStale = !now.Before(dnsExpires)
	}
	if s.retention.Mode == retentionLRU {
		// A global/diagnostic response just before the stored lease ends
		// must still have enough lifetime to survive API transit. This
		// per-response lease never changes the owner's retained state.
		candidate.ExpiresAt = maxTime(candidate.ExpiresAt, now.Add(s.retention.window(o.baseTTL)))
	}
	return candidate
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// touchRoute updates access/lease state only. DNS selection order, sequence,
// observed_at and DNS expiry remain evidence of actual DNS responses.
func (s *observationIndex) touchRoute(o *observation, now time.Time) (renewed bool) {
	if !s.retention.extended() {
		return false
	}
	s.order.MoveToBack(o.order)
	expires := now.Add(s.retention.window(o.baseTTL))
	if expires.After(o.ExpiresAt) {
		o.ExpiresAt = expires
		s.fixExpiry(o)
		return true
	}
	return false
}
