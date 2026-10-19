package domain_mapping

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func newShutdownState(t *testing.T) (*DomainMapping, *observer.ObservedLogs) {
	t.Helper()
	dir := t.TempDir()
	importPath := filepath.Join(dir, "import.json")
	if err := os.WriteFile(importPath, []byte(`{"version":1,"history_complete":true,"records":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zap.DebugLevel)
	p, err := newWithLogger(Args{
		Size: 64, Retention: RetentionArgs{Mode: "lru"},
		Allocation: AllocationArgs{Enable: true, ClientScope: true, StateFile: filepath.Join(dir, "state"), ImportFile: importPath},
	}, zap.New(core))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, logs
}

func TestStateFailedCheckpointRetainsDirtyAndCloseError(t *testing.T) {
	p, logs := newShutdownState(t)
	p.record(clientPool(t, "kept.test", "192.168.6.180", 300, "203.0.113.10"))
	// Make atomic snapshot replacement fail while the existing dirty marker
	// remains writable, simulating a filesystem/checkpoint failure.
	if err := os.Rename(p.state.path, p.state.path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p.state.path, 0700); err != nil {
		t.Fatal(err)
	}
	err := p.Close()
	if err == nil {
		t.Fatal("checkpoint failure discarded")
	}
	if next := p.Close(); next == nil || next.Error() != err.Error() {
		t.Fatalf("repeated Close lost original error: %v / %v", err, next)
	}
	if _, err := os.Stat(p.state.path + ".dirty"); err != nil {
		t.Fatalf("failed checkpoint removed recovery marker: %v", err)
	}
	if logs.FilterField(zap.String("reason", "shutdown_checkpoint_error")).Len() == 0 {
		t.Fatal("checkpoint failure lacked diagnostic reason")
	}
}

func TestStateLateResponseCannotPublishCleanCheckpoint(t *testing.T) {
	p, logs := newShutdownState(t)
	finish := p.prepare(clientPool(t, "pending.test", "192.168.6.180", 300, "203.0.113.10"))
	if finish == nil {
		t.Fatal("query did not register finalizer")
	}
	done := make(chan error, 1)
	go func() { done <- p.Close() }()
	deadline := time.Now().Add(time.Second)
	for {
		p.mu.Lock()
		closing := p.clients.closing
		p.mu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("close did not enter drain")
		}
		time.Sleep(time.Millisecond)
	}
	if late := p.prepare(clientPool(t, "late.test", "192.168.6.180", 300, "203.0.113.11")); late != nil {
		t.Fatal("late query registered an untracked finalizer")
	}
	finish(nil)
	if err := <-done; err == nil || !strings.Contains(err.Error(), "late response") {
		t.Fatalf("late response was reported clean: %v", err)
	}
	if _, err := os.Stat(p.state.path + ".dirty"); err != nil {
		t.Fatalf("late response lost dirty marker: %v", err)
	}
	if logs.FilterField(zap.String("reason", "late_close")).Len() == 0 {
		t.Fatal("late close lacked diagnostic reason")
	}
}

func TestStateOverflowAndRecoveryHaveExplicitReasons(t *testing.T) {
	p, logs := newShutdownState(t)
	store := &stateStore{p: p, queue: make(chan stateEvent, 1)}
	p.mu.Lock()
	store.enqueue(stateEvent{})
	store.enqueue(stateEvent{})
	guarded := p.clients.recovery && p.clients.incompleteUntil.After(time.Now())
	p.mu.Unlock()
	if !store.failed.Load() || !guarded || logs.FilterField(zap.String("reason", "queue_overflow")).Len() != 1 {
		t.Fatal("queue overflow failed to guard history and explain recovery")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.state.markDirty(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.state.path+".wal", []byte{0, 0, 2}, 0600); err != nil {
		t.Fatal(err)
	}
	restored, err := newWithLogger(p.args, p.logger)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	for _, reason := range []string{"dirty_marker", "wal_replay_error"} {
		if logs.FilterField(zap.String("reason", reason)).Len() == 0 {
			t.Fatalf("recovery lacked %s reason", reason)
		}
	}
}

func TestStateWALOverlapCannotResurrectEvictedRoutingOrPreferences(t *testing.T) {
	p := newClientTestPlugin(t, 64)
	p.args.Routing.Size = 1
	p.args.Allocation.Size = 1
	p.routes.init(1)
	p.preferences.init(1)
	const clientText = "192.168.6.180"
	client := netip.MustParseAddr(clientText)
	p.record(clientPool(t, "old.test", clientText, 300, "203.0.113.1"))
	oldHint := p.routes.entries[lookupKey{client: client, ip: netip.MustParseAddr("203.0.113.1")}]
	oldEvent := stateEventFor("old.test", client, []evidence{{ip: netip.MustParseAddr("203.0.113.1"), ttl: 300, source: "a"}}, nil, false, oldHint.observedAt)
	oldEvent.RoutingSequence = p.routes.sequence
	oldEvent.Preferences = p.preferenceSnapshot()
	p.record(clientPool(t, "current.test", clientText, 300, "203.0.113.2"))
	snapshot := p.state.snapshot()

	q := newClientTestPlugin(t, 64)
	q.args.Routing.Size = 1
	q.args.Allocation.Size = 1
	q.routes.init(1)
	q.preferences.init(1)
	if err := q.restoreSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	for _, event := range []stateEvent{oldEvent, func() stateEvent { e := oldEvent; e.RoutingSequence = 0; return e }()} {
		if err := q.applyStateEvent(event); err != nil {
			t.Fatal(err)
		}
		if got := v3Lookup(t, q, "203.0.113.1", clientText); got.Status != "miss" {
			t.Fatal("overlapping WAL resurrected an evicted routing identity")
		}
		if q.preferences.entries[preferenceKey{client: client, domain: "old.test"}] != nil {
			t.Fatal("overlapping WAL resurrected an evicted allocation preference")
		}
	}
	newTime := time.Now()
	fresh := stateEventFor("fresh.test", client, []evidence{{ip: netip.MustParseAddr("203.0.113.3"), ttl: 300, source: "a"}}, nil, false, newTime)
	fresh.RoutingSequence = snapshot.RoutingSequence + 1
	fresh.Preferences = []statePreference{{Client: clientText, Domain: "fresh.test", IP: "203.0.113.3", ObservedAt: newTime}}
	if err := q.applyStateEvent(fresh); err != nil {
		t.Fatal(err)
	}
	if got := v3Lookup(t, q, "203.0.113.3", clientText); got.Domain != "fresh.test" {
		t.Fatalf("fresh WAL event lost: %+v", got)
	}
	if q.preferences.entries[preferenceKey{client: client, domain: "fresh.test"}] == nil {
		t.Fatal("fresh WAL preference was not restored")
	}
}
