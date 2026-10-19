package domain_mapping

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func TestStableClientPreferencesPreventThreeDomainTwoIPSpread(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	const client, a, b = "192.168.6.180", "203.0.113.1", "203.0.113.2"
	for _, step := range []struct {
		domain string
		want   []string
	}{
		{"gemini.test", []string{a}},
		{"gstatic.test", []string{b}},
		{"third.test", []string{a, b}},
		{"gemini.test", []string{a}},
		{"gstatic.test", []string{b}},
	} {
		q := clientPool(t, step.domain, client, 300, a, b)
		p.record(q)
		if got := answerAddresses(q); !reflect.DeepEqual(got, step.want) {
			t.Fatalf("%s propagated across the pool: got %v want %v", step.domain, got, step.want)
		}
	}
	if len(p.preferences.entries) != 2 {
		t.Fatal("exhausted multi-address fallback invented an exclusive preference")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(p.args)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	for domain, want := range map[string]string{"gemini.test": a, "gstatic.test": b} {
		q := clientPool(t, domain, client, 300, a, b)
		restarted.record(q)
		if got := answerAddresses(q); !reflect.DeepEqual(got, []string{want}) {
			t.Fatalf("restart lost stable %s assignment: %v", domain, got)
		}
	}
}

func TestStablePreferenceDoesNotInventAddressesOrModifySignedAnswers(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	const client = "192.168.6.180"
	p.record(clientPool(t, "gemini.test", client, 300, "203.0.113.1", "203.0.113.2"))
	q := clientPool(t, "gemini.test", client, 300, "203.0.113.2", "203.0.113.3")
	p.record(q)
	if got := answerAddresses(q); !reflect.DeepEqual(got, []string{"203.0.113.2"}) {
		t.Fatalf("unavailable old preference was reused: %v", got)
	}
	q = clientPool(t, "gemini.test", client, 300, "203.0.113.2", "203.0.113.3")
	q.R().AuthenticatedData = true
	before := q.R().String()
	p.record(q)
	if q.R().String() != before {
		t.Fatal("preference overrode signed response preservation")
	}
	key := preferenceKey{client: netip.MustParseAddr(client), domain: "gemini.test"}
	if got := p.preferences.get(key); got.String() != "203.0.113.2" {
		t.Fatal("unfilterable fallback replaced a stable preference")
	}
}

func TestPreferenceFailedEncodingAndBoundedIndependentCapacity(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	q := clientPool(t, "failed.test", "192.168.6.180", 300, "203.0.113.1", "203.0.113.2")
	finish := p.prepare(q)
	finish(nil)
	if len(p.preferences.entries) != 0 || len(p.routes.entries) != 0 {
		t.Fatal("failed encoding committed preference or routing hint")
	}
	var prefs preferenceCache
	prefs.init(2)
	client, ip := netip.MustParseAddr("192.168.6.180"), netip.MustParseAddr("203.0.113.1")
	first := preferenceKey{client: client, domain: "first.test"}
	second := preferenceKey{client: client, domain: "second.test"}
	third := preferenceKey{client: client, domain: "third.test"}
	prefs.put(first, ip, time.Now())
	prefs.put(second, ip, time.Now())
	prefs.get(first)
	prefs.put(third, ip, time.Now())
	if len(prefs.entries) != 2 || prefs.get(second).IsValid() || !prefs.get(first).IsValid() {
		t.Fatal("preference cache is unbounded or does not preserve its own LRU")
	}
}

func TestLegacyHistoryDoesNotInventStablePreferences(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	const client = "192.168.6.180"
	now := time.Now()
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		err := p.restoreRecord(stateRecord{Client: client, IP: ip, Domain: "historical.test", Source: "a", ObservedAt: now, DNSExpiresAt: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(p.preferences.entries) != 0 {
		t.Fatal("legacy multi-address history was promoted to a stable assignment")
	}
	if got := v3Lookup(t, p, "203.0.113.1", client); got.Domain != "historical.test" {
		t.Fatal("legacy actual DNS observation could not provide a routing hint")
	}
}
