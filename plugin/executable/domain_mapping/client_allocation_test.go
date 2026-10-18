package domain_mapping

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/miekg/dns"
)

func newClientTestPlugin(t *testing.T, size int) *DomainMapping {
	t.Helper()
	dir := t.TempDir()
	importPath := filepath.Join(dir, "import.json")
	if err := os.WriteFile(importPath, []byte(`{"version":1,"history_complete":true,"records":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := New(Args{Size: size, Retention: RetentionArgs{Mode: "lru"}, Allocation: AllocationArgs{Enable: true, ClientScope: true, StateFile: filepath.Join(dir, "state"), ImportFile: importPath}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}
func clientPool(t *testing.T, domain, client string, ttl int, ips ...string) *query_context.Context {
	t.Helper()
	records := make([]string, 0, len(ips))
	for _, ip := range ips {
		typ := "A"
		if strings.Contains(ip, ":") {
			typ = "AAAA"
		}
		records = append(records, fmt.Sprintf("%s. %d IN %s %s", domain, ttl, typ, ip))
	}
	return testContext(t, domain, client, dns.TypeA, records...)
}
func answerAddresses(q *query_context.Context) []string {
	var ips []string
	for _, rr := range q.R().Answer {
		switch r := rr.(type) {
		case *dns.A:
			ips = append(ips, r.A.String())
		case *dns.AAAA:
			ips = append(ips, r.AAAA.String())
		}
	}
	return ips
}
func v2Lookup(t *testing.T, p *DomainMapping, ip, client string) LookupResultV2 {
	t.Helper()
	var c netip.Addr
	if client != "" {
		c = netip.MustParseAddr(client)
	}
	r, err := p.LookupV2Context(context.Background(), netip.MustParseAddr(ip), c)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func installToken(p *DomainMapping, domain, client, class, epoch string, share bool) {
	p.policy.mu.Lock()
	defer p.policy.mu.Unlock()
	p.policy.args.Endpoint = "http://not-used.invalid"
	p.policy.epoch = epoch
	k := policyKey{domain, client}
	token := &policyToken{key: k, class: class, share: share, epoch: epoch, until: time.Now().Add(time.Minute)}
	if old := p.policy.cache[k]; old != nil {
		p.policy.order.Remove(old.order)
	}
	token.order = p.policy.order.PushBack(token)
	p.policy.cache[k] = token
}

func TestClientScopedIsolationReuseAndExhaustion(t *testing.T) {
	p := newClientTestPlugin(t, 128)
	client := "192.168.6.180"
	pool := []string{"203.0.113.1", "203.0.113.2"}
	gemini := clientPool(t, "gemini.google.com", client, 300, pool...)
	p.record(gemini)
	gstatic := clientPool(t, "gemini.gstatic.com", client, 300, pool...)
	p.record(gstatic)
	if !reflect.DeepEqual(answerAddresses(gemini), pool[:1]) || !reflect.DeepEqual(answerAddresses(gstatic), pool[1:]) {
		t.Fatalf("addresses not isolated: %v / %v", answerAddresses(gemini), answerAddresses(gstatic))
	}
	other := clientPool(t, "unrelated.test", "192.168.6.181", 300, pool...)
	p.record(other)
	if !reflect.DeepEqual(answerAddresses(other), pool[:1]) {
		t.Fatal("another client consumed address space")
	}
	reordered := clientPool(t, "gemini.gstatic.com", client, 5, pool[1], pool[0])
	p.record(reordered)
	if !reflect.DeepEqual(answerAddresses(reordered), pool[1:]) {
		t.Fatal("stable ownership churned on answer reorder")
	}
	third := clientPool(t, "third.test", client, 300, pool...)
	p.record(third)
	if !reflect.DeepEqual(answerAddresses(third), pool) {
		t.Fatal("exhaustion did not return original answer")
	}
	for _, ip := range pool {
		got := v2Lookup(t, p, ip, client)
		if got.Status != "ambiguous" || !got.Complete || got.Total != 2 || got.Domain != "" {
			t.Fatalf("fallback did not downgrade all exposed addresses: %+v", got)
		}
	}
	if got := v2Lookup(t, p, pool[0], "192.168.6.181"); got.Status != "hit" || got.Domain != "unrelated.test" {
		t.Fatalf("client-scoped history leaked: %+v", got)
	}
}

func TestClientScopedExactSharingMatrix(t *testing.T) {
	for _, tc := range []struct {
		name, a, b                 string
		shareA, shareB, wantShared bool
	}{
		{"unmatched_proxy_default", "unmatched", "unmatched", true, true, true},
		{"direct_proxy_default", "direct", "direct", false, false, false},
		{"direct_and_unmatched_proxy_default", "direct", "unmatched", false, true, false},
		{"direct_direct_default", "direct", "direct", true, true, true},
		{"direct_and_unmatched_direct_default", "direct", "unmatched", true, true, true},
		{"same_proxy_group_is_isolated", "isolated", "isolated", false, false, false},
		{"unknown_is_not_unmatched", "unknown", "unmatched", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newClientTestPlugin(t, 64)
			client := "192.168.6.180"
			installToken(p, "a.test", client, tc.a, "epoch", tc.shareA)
			installToken(p, "b.test", client, tc.b, "epoch", tc.shareB)
			a := clientPool(t, "a.test", client, 60, "203.0.113.1", "203.0.113.2")
			p.record(a)
			b := clientPool(t, "b.test", client, 60, "203.0.113.1", "203.0.113.2")
			p.record(b)
			shared := answerAddresses(a)[0] == answerAddresses(b)[0]
			if shared != tc.wantShared {
				t.Fatalf("sharing=%v want %v", shared, tc.wantShared)
			}
		})
	}
}

func TestClientScopedExpiredPolicyCannotShare(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	client := "192.168.6.180"
	installToken(p, "a.test", client, "unmatched", "old", true)
	a := clientPool(t, "a.test", client, 60, "203.0.113.1", "203.0.113.2")
	p.record(a)
	installToken(p, "b.test", client, "unmatched", "new", true)
	b := clientPool(t, "b.test", client, 60, "203.0.113.1", "203.0.113.2")
	p.record(b)
	if answerAddresses(b)[0] != "203.0.113.2" {
		t.Fatal("old owner epoch admitted sharing")
	}
}

func TestClientScopedConcurrentReservationsAndCancel(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	client := "192.168.6.180"
	a := clientPool(t, "a.test", client, 0, "203.0.113.1", "203.0.113.2")
	finishA := p.prepare(a)
	b := clientPool(t, "b.test", client, 0, "203.0.113.1", "203.0.113.2")
	finishB := p.prepare(b)
	if answerAddresses(a)[0] == answerAddresses(b)[0] {
		t.Fatal("pending reservations assigned same address")
	}
	if got := v2Lookup(t, p, "203.0.113.1", client); got.Complete || got.Status != "ambiguous" {
		t.Fatalf("pending reply reported unique: %+v", got)
	}
	finishA(nil)
	finishB(b.R())
	if got := v2Lookup(t, p, "203.0.113.1", client); got.Status != "miss" {
		t.Fatalf("failed encoding created evidence: %+v", got)
	}
	if got := v2Lookup(t, p, "203.0.113.2", client); got.Status != "hit" || got.Domain != "b.test" {
		t.Fatalf("TTL zero lost ownership: %+v", got)
	}
	c := clientPool(t, "c.test", client, 0, "203.0.113.1", "203.0.113.2")
	p.record(c)
	if answerAddresses(c)[0] != "203.0.113.1" {
		t.Fatal("cancel did not release reservation")
	}
}

func TestClientScopedConcurrentPoolHasNoDuplicateExclusiveAnswers(t *testing.T) {
	p := newClientTestPlugin(t, 256)
	var wg sync.WaitGroup
	results := make(chan []string, 8)
	gate := make(chan struct{})
	var prepared sync.WaitGroup
	prepared.Add(8)
	for i := 0; i < 8; i++ {
		q := clientPool(t, fmt.Sprintf("d%d.test", i), "192.168.6.180", 5, "203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4", "203.0.113.5", "203.0.113.6", "203.0.113.7", "203.0.113.8")
		wg.Add(1)
		go func() {
			defer wg.Done()
			done := p.prepare(q)
			results <- answerAddresses(q)
			prepared.Done()
			<-gate
			done(q.R())
		}()
	}
	prepared.Wait()
	close(gate)
	wg.Wait()
	close(results)
	seen := map[string]bool{}
	for ips := range results {
		if len(ips) != 1 || seen[ips[0]] {
			t.Fatalf("duplicate/non-exclusive answer: %v", ips)
		}
		seen[ips[0]] = true
	}
}

func TestClientScopedEvictionNeverMakesHistoryUnique(t *testing.T) {
	p := newClientTestPlugin(t, 1)
	client := "192.168.6.180"
	p.record(clientPool(t, "old.test", client, 300, "203.0.113.1"))
	p.record(clientPool(t, "new.test", client, 300, "203.0.113.2"))
	if got := v2Lookup(t, p, "203.0.113.1", client); got.Status != "ambiguous" || got.Complete || got.Domain != "" {
		t.Fatalf("forgotten owner became a clean miss: %+v", got)
	}
	q := clientPool(t, "third.test", client, 300, "203.0.113.1", "203.0.113.3")
	p.record(q)
	if !reflect.DeepEqual(answerAddresses(q), []string{"203.0.113.3"}) {
		t.Fatal("evicted address was reallocated as unused")
	}
}

func TestClientScopedFamilyExhaustionIsIndependent(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	client := "192.168.6.180"
	p.record(clientPool(t, "old.test", client, 300, "203.0.113.1", "203.0.113.2"))
	// Expose the other IPv4 candidate via an unfilterable signed answer.
	q := clientPool(t, "old.test", client, 300, "203.0.113.1", "203.0.113.2")
	q.R().AuthenticatedData = true
	p.record(q)
	q = clientPool(t, "new.test", client, 300, "203.0.113.1", "203.0.113.2", "2001:db8::1", "2001:db8::2")
	p.record(q)
	if got := answerAddresses(q); !reflect.DeepEqual(got, []string{"203.0.113.1", "203.0.113.2", "2001:db8::1"}) {
		t.Fatalf("family exhaustion polluted unrelated family: %v", got)
	}
}

func TestClientScopedDNSSECAndAliasesPreserved(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	client := "192.168.6.180"
	q := clientPool(t, "signed.test", client, 300, "203.0.113.1", "203.0.113.2")
	q.R().AuthenticatedData = true
	before := q.R().String()
	p.record(q)
	if q.R().String() != before {
		t.Fatal("signed response changed")
	}
	q = testContext(t, "alias.test", client, dns.TypeA, "alias.test. 60 IN CNAME canonical.test.", "canonical.test. 60 IN A 203.0.113.3", "canonical.test. 60 IN A 203.0.113.4")
	before = q.R().String()
	p.record(q)
	if q.R().String() != before {
		t.Fatal("unsupported alias modified")
	}
	if got := v2Lookup(t, p, "203.0.113.3", client); got.Complete || got.Status != "ambiguous" {
		t.Fatalf("alias linkage presented exclusive: %+v", got)
	}
	q = clientPool(t, "canonical.test", client, 0, "203.0.113.5", "203.0.113.6")
	p.record(q)
	if len(q.R().Answer) != 2 {
		t.Fatal("later canonical lookup lost service uncertainty")
	}
	if got := v2Lookup(t, p, "203.0.113.5", client); got.Complete {
		t.Fatal("canonical target turned unique")
	}
}

func TestV2CompleteCandidateContractAndV1Compatibility(t *testing.T) {
	p := newClientTestPlugin(t, 2048)
	client := "192.168.6.180"
	ip := "203.0.113.1"
	for i := 0; i < 40; i++ {
		p.record(clientPool(t, fmt.Sprintf("domain-%03d.test", i), client, 60, ip))
	}
	got := v2Lookup(t, p, ip, client)
	if got.Status != "ambiguous" || !got.Complete || got.Total != 40 || len(got.Domains) != 40 || got.Domain != "" {
		t.Fatalf("v2 inherited diagnostics cap: %+v", got)
	}
	v1 := lookup(p, ip, client)
	if v1.Status != "hit" || len(v1.Candidates) != 32 || v1.Domain != "domain-039.test" {
		t.Fatalf("v1 wire behavior changed: %+v", v1)
	}
	for i := 40; i < 1025; i++ {
		p.record(clientPool(t, fmt.Sprintf("domain-%04d.test", i), client, 60, ip))
	}
	got = v2Lookup(t, p, ip, client)
	if got.Complete || got.Total != 1025 || len(got.Domains) != 1024 || got.Domain != "" {
		t.Fatalf("candidate limit not explicit: total=%d count=%d complete=%v", got.Total, len(got.Domains), got.Complete)
	}
	r := httptest.NewRecorder()
	p.API().ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/v2/lookup?ip="+ip+"&client="+client, nil))
	if r.Code != 200 || r.Body.Len() > 1<<20 {
		t.Fatalf("bad v2 HTTP result %d/%d", r.Code, r.Body.Len())
	}
	if got := v2Lookup(t, p, ip, "192.168.6.181"); got.Status != "miss" {
		t.Fatal("v2 inferred ownership from another client")
	}
}

func TestClientStateCleanRestartPreservesExposureAndTaint(t *testing.T) {
	p := newClientTestPlugin(t, 2)
	client := "192.168.6.180"
	p.record(clientPool(t, "a.test", client, 300, "203.0.113.1"))
	p.record(clientPool(t, "b.test", client, 300, "203.0.113.2"))
	p.record(clientPool(t, "c.test", client, 300, "203.0.113.3"))
	args := p.args
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(args.Allocation.StateFile + ".dirty"); !os.IsNotExist(err) {
		t.Fatal("clean close retained dirty marker")
	}
	q, err := New(args)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if q.clients.guardUntil.After(time.Now()) {
		t.Fatal("clean restart incorrectly activated startup guard")
	}
	if got := v2Lookup(t, q, "203.0.113.1", client); got.Status != "ambiguous" || got.Complete {
		t.Fatalf("restart forgot taint: %+v", got)
	}
	if got := v2Lookup(t, q, "203.0.113.3", client); got.Domain != "c.test" || !got.Complete {
		t.Fatalf("restart forgot complete owner: %+v", got)
	}
}

func TestClientStateMissingCorruptAndPartialImportGuard(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "partial_import", "missing_import"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			statePath := filepath.Join(dir, "state")
			args := Args{Retention: RetentionArgs{Mode: "lru"}, Allocation: AllocationArgs{Enable: true, ClientScope: true, StateFile: statePath, StartupGuard: 86400}}
			if kind == "corrupt" {
				_ = os.WriteFile(statePath, []byte("bad state"), 0600)
			}
			if kind == "missing_import" {
				args.Allocation.ImportFile = filepath.Join(dir, "gone-import.json")
			}
			if kind == "partial_import" {
				args.Allocation.ImportFile = filepath.Join(dir, "import.json")
				snapshot := stateSnapshot{Version: 1, HistoryComplete: false, Records: []stateRecord{{Client: "192.168.6.180", IP: "203.0.113.1", Domain: "legacy.test", Source: "a", ObservedAt: time.Now().Add(-time.Minute), DNSExpiresAt: time.Now(), ExpiresAt: time.Now()}}}
				body, _ := json.Marshal(snapshot)
				_ = os.WriteFile(args.Allocation.ImportFile, body, 0600)
			}
			p, err := New(args)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if !p.clients.guardUntil.After(time.Now().Add(23 * time.Hour)) {
				t.Fatal("lost history did not activate guard")
			}
			if got := v2Lookup(t, p, "203.0.113.9", "192.168.6.180"); got.Status != "miss" {
				t.Fatal("guard forced every unknown IP into proxy fallback")
			}
			if kind == "partial_import" {
				got := v2Lookup(t, p, "203.0.113.1", "192.168.6.180")
				if got.Domain != "legacy.test" || !got.Complete {
					t.Fatalf("retained candidate set unnecessarily tainted: %+v", got)
				}
			}
			q := clientPool(t, "new.test", "192.168.6.180", 300, "203.0.113.8", "203.0.113.9")
			p.record(q)
			if len(q.R().Answer) != 2 {
				t.Fatal("startup guard allocated unseen addresses")
			}
			p.mu.Lock()
			p.clients.guardUntil = time.Now().Add(-time.Second)
			p.clients.incompleteUntil = time.Now().Add(-time.Second)
			p.mu.Unlock()
			q = clientPool(t, "fresh.test", "192.168.6.180", 300, "203.0.113.10", "203.0.113.11")
			p.record(q)
			if len(q.R().Answer) != 1 {
				t.Fatal("expired migration guard permanently disabled allocation")
			}
		})
	}
}

func TestClientStateDirtyRestartAndTruncatedWAL(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	args := p.args
	p.record(clientPool(t, "kept.test", "192.168.6.180", 300, "203.0.113.1"))
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.state.markDirty(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(args.Allocation.StateFile+".wal", []byte{0, 0, 2}, 0600); err != nil {
		t.Fatal(err)
	}
	q, err := New(args)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if !q.clients.guardUntil.After(time.Now()) {
		t.Fatal("dirty/truncated WAL startup was treated clean")
	}
	if got := v2Lookup(t, q, "203.0.113.1", "192.168.6.180"); got.Domain != "" || got.Complete || len(got.Domains) != 1 || got.Domains[0] != "kept.test" {
		t.Fatalf("WAL recovery falsely certified ownership: %+v", got)
	}
	until := q.clients.incompleteUntil
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := New(args)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !r.clients.incompleteUntil.Equal(until) {
		t.Fatal("clean restart changed recovery horizon")
	}
	if got := v2Lookup(t, r, "203.0.113.1", "192.168.6.180"); got.Complete {
		t.Fatal("clean restart erased lost ownership")
	}
}

func TestClientScopedSameNameHTTPSPreservesECHWithoutFalseAmbiguity(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	client := "192.168.6.180"
	q := testContext(t, "service.test", client, dns.TypeHTTPS, `service.test. 300 IN HTTPS 1 . alpn="h3" ipv4hint=203.0.113.1,203.0.113.2 ech=AQID`)
	before := q.R().String()
	p.record(q)
	if q.R().String() != before {
		t.Fatal("HTTPS/ECH answer changed")
	}
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		got := v2Lookup(t, p, ip, client)
		if got.Domain != "service.test" || !got.Complete {
			t.Fatalf("same-name service incorrectly unknown: %+v", got)
		}
	}
	a := clientPool(t, "service.test", client, 300, "203.0.113.1", "203.0.113.2")
	p.record(a)
	if len(a.R().Answer) != 2 {
		t.Fatal("associated service A response was trimmed")
	}
	if got := v2Lookup(t, p, "203.0.113.1", client); !got.Complete {
		t.Fatal("same-name service tainted subsequent A answer")
	}
}

func TestV2PendingExistingOwnerRemainsComplete(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	client := "192.168.6.180"
	ip := "203.0.113.1"
	p.record(clientPool(t, "known.test", client, 300, ip))
	repeat := clientPool(t, "known.test", client, 300, ip)
	finish := p.prepare(repeat)
	if got := v2Lookup(t, p, ip, client); got.Status != "hit" || !got.Complete || got.Domain != "known.test" {
		t.Fatalf("repeat pending owner made an incomplete set: %+v", got)
	}
	finish(repeat.R())
	fresh := clientPool(t, "new.test", client, 300, ip)
	finish = p.prepare(fresh)
	if got := v2Lookup(t, p, ip, client); got.Status != "ambiguous" || got.Complete || got.Total != 2 {
		t.Fatalf("new pending owner was not guarded: %+v", got)
	}
	finish(fresh.R())
	if got := v2Lookup(t, p, ip, client); !got.Complete || got.Total != 2 {
		t.Fatalf("committed pending owner did not become complete: %+v", got)
	}
}

func TestV2LegacyModeCannotCertifyCompleteHistory(t *testing.T) {
	p, _ := testPlugin(t, Args{})
	p.record(testContext(t, "legacy.test", "192.168.6.180", dns.TypeA, "legacy.test. 300 IN A 203.0.113.1"))
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		got := v2Lookup(t, p, ip, "192.168.6.180")
		if got.Status != "ambiguous" || got.Complete || got.Domain != "" || got.Reason != "history_untracked" {
			t.Fatalf("untracked legacy history certified: %+v", got)
		}
	}
	if got := lookup(p, "203.0.113.1", "192.168.6.180"); got.Domain != "legacy.test" {
		t.Fatal("v1 compatibility changed")
	}
}
