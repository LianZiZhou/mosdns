package domain_mapping

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

func TestAuditDirtyLostLastOwnerCannotCertifyUnique(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	client := "192.168.6.180"
	p.record(clientPool(t, "old.test", client, 300, "203.0.113.1"))
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	// A later process can expose another owner before its asynchronous WAL
	// reaches disk. The persistent observable state is an old checkpoint and
	// the durable dirty marker; no information about that last owner survives.
	if err := os.WriteFile(p.args.Allocation.StateFile+".dirty", []byte("unclean\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(p.args)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got := v2Lookup(t, reopened, "203.0.113.1", client)
	if got.Complete && got.Status == "hit" {
		t.Fatalf("dirty recovery certified old singleton despite potentially lost last owner: %+v; recovery=%v guard=%v", got, reopened.clients.recovery, reopened.clients.guardUntil)
	}
}

func TestAuditCNAMEAfterCachedTargetCannotCertifyUnique(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	client := "192.168.6.180"
	p.record(clientPool(t, "target.test", client, 300, "203.0.113.1"))
	// The client already knows target.test's address, so this CNAME-only reply
	// can lead to a connection without a later A query for target.test.
	p.record(testContext(t, "alias.test", client, dns.TypeA, "alias.test. 300 IN CNAME target.test."))
	got := v2Lookup(t, p, "203.0.113.1", client)
	if got.Complete && got.Status == "hit" {
		t.Fatalf("CNAME association left cached target falsely unique: %+v", got)
	}
}

func TestAuditHTTPSAfterCachedTargetCannotCertifyUnique(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	client := "192.168.6.180"
	p.record(clientPool(t, "target.test", client, 300, "203.0.113.1"))
	p.record(testContext(t, "alias.test", client, dns.TypeHTTPS, "alias.test. 300 IN HTTPS 1 target.test. alpn=h2"))
	got := v2Lookup(t, p, "203.0.113.1", client)
	if got.Complete && got.Status == "hit" {
		t.Fatalf("HTTPS target association left cached target falsely unique: %+v", got)
	}
}

func TestAuditMalformedExistingImportRejected(t *testing.T) {
	dir := t.TempDir()
	importPath := filepath.Join(dir, "import.json")
	// Syntactically valid JSON with unsupported state schema is still malformed
	// input, and the documented import contract promises startup rejection.
	if err := os.WriteFile(importPath, []byte(`{"version":99,"history_complete":true,"records":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := New(Args{Retention: RetentionArgs{Mode: "lru"}, Allocation: AllocationArgs{Enable: true, ClientScope: true, StateFile: filepath.Join(dir, "state"), ImportFile: importPath}})
	if err == nil {
		p.Close()
		t.Fatal("malformed existing import was silently discarded and accepted")
	}
}

func TestAuditAliasUncertaintySurvivesCleanRestartAndSharing(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	client := "192.168.6.180"
	p.record(clientPool(t, "target.test", client, 300, "203.0.113.1"))
	p.record(testContext(t, "alias.test", client, dns.TypeA, "alias.test. 300 IN CNAME target.test."))
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	q, err := New(p.args)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	for _, scope := range []string{client, ""} {
		got := v2Lookup(t, q, "203.0.113.1", scope)
		if got.Complete || got.Domain != "" || got.Reason != "alias_dependency" {
			t.Fatalf("clean restart lost cached target dependency for scope %q: %+v", scope, got)
		}
	}
	installToken(q, "target.test", client, "unmatched", "epoch", true)
	installToken(q, "fresh.test", client, "unmatched", "epoch", true)
	fresh := clientPool(t, "fresh.test", client, 300, "203.0.113.1", "203.0.113.2")
	q.record(fresh)
	if !reflect.DeepEqual(answerAddresses(fresh), []string{"203.0.113.2"}) {
		t.Fatalf("classification reused uncertain cached target address: %v", answerAddresses(fresh))
	}
	again := clientPool(t, "target.test", client, 300, "203.0.113.1", "203.0.113.3")
	q.record(again)
	if len(answerAddresses(again)) != 2 {
		t.Fatalf("original target was trimmed after alias association: %v", answerAddresses(again))
	}
}

func TestAuditDirtyGuardSurvivesCleanRestartAndFreshDNS(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	client := "192.168.6.180"
	p.record(clientPool(t, "old.test", client, 300, "203.0.113.1"))
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.args.Allocation.StateFile+".dirty", []byte("unclean\n"), 0600); err != nil {
		t.Fatal(err)
	}
	recovered, err := New(p.args)
	if err != nil {
		t.Fatal(err)
	}
	until := recovered.clients.incompleteUntil
	recovered.record(clientPool(t, "old.test", client, 300, "203.0.113.1"))
	if got := v2Lookup(t, recovered, "203.0.113.1", client); got.Complete {
		t.Fatal("fresh DNS erased potentially lost owners")
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := New(p.args)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if !again.clients.incompleteUntil.Equal(until) {
		t.Fatal("clean restart shifted recovery cutoff")
	}
	if got := v2Lookup(t, again, "203.0.113.1", client); got.Complete || got.Domain != "" || got.Reason != "state_recovery" {
		t.Fatalf("clean restart erased dirty ownership uncertainty: %+v", got)
	}
}

func TestAuditDirtyKnownBucketCannotAdmitNewSharedOwner(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	client := "192.168.6.180"
	p.record(clientPool(t, "old.test", client, 300, "203.0.113.1"))
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.args.Allocation.StateFile+".dirty", []byte("unclean\n"), 0600); err != nil {
		t.Fatal(err)
	}
	recovered, err := New(p.args)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	installToken(recovered, "old.test", client, "unmatched", "epoch", true)
	installToken(recovered, "new.test", client, "unmatched", "epoch", true)
	q := clientPool(t, "new.test", client, 300, "203.0.113.1", "203.0.113.2")
	recovered.record(q)
	if len(answerAddresses(q)) != 2 {
		t.Fatalf("dirty known bucket admitted new sharing despite potentially lost isolated owner: %v", answerAddresses(q))
	}
}
