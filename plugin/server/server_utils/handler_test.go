package server_utils

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseTrustedECS(t *testing.T) {
	prefixes, err := parseTrustedECS([]string{"127.0.0.1/32", "::1/128", "192.168.1.1/24", "::ffff:192.0.2.0/120"})
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"127.0.0.1/32", "::1/128", "192.168.1.0/24", "192.0.2.0/24"} {
		if prefixes[i] != netip.MustParsePrefix(want) {
			t.Errorf("prefix %d: got %v, want %s", i, prefixes[i], want)
		}
	}
	for _, value := range []string{"", "localhost", "127.0.0.1", "127.0.0.1/33", "::ffff:192.0.2.1/64"} {
		// CIDRs must fail before looking up an entry (nil BP is deliberate).
		if _, err := NewHandler(nil, "entry", value); err == nil || !strings.Contains(err.Error(), "trusted_ecs") {
			t.Errorf("invalid CIDR %q was not rejected: %v", value, err)
		}
	}
	if p, err := parseTrustedECS(nil); err != nil || len(p) != 0 {
		t.Fatalf("empty trust list: %v %v", p, err)
	}
}
