package coremain_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/domain_mapping"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/IrineSistiana/mosdns/v5/plugin/server/server_utils"
	"github.com/miekg/dns"
)

type shutdownEntryArgs struct {
	entered chan struct{}
	release <-chan struct{}
}

func TestServiceShutdownUnderLoadCheckpointsFinalDNSResponses(t *testing.T) {
	const workers = 32
	const pluginType = "shutdown_integration_entry"
	coremain.RegNewPluginFunc(pluginType, func(bp *coremain.BP, args any) (any, error) {
		a := args.(*shutdownEntryArgs)
		mapping := bp.M().GetPlugin("mapping").(*domain_mapping.DomainMapping)
		return sequence.ExecutableFunc(func(ctx context.Context, q *query_context.Context) error {
			a.entered <- struct{}{}
			select {
			case <-a.release:
			case <-ctx.Done():
				return ctx.Err()
			}
			r := new(dns.Msg)
			r.SetReply(q.Q())
			rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN A 203.0.113.10", q.QQuestion().Name))
			if err != nil {
				return err
			}
			r.Answer = []dns.RR{rr}
			q.SetResponse(r)
			return mapping.Exec(ctx, q, sequence.NewChainWalker(nil, nil))
		}), nil
	}, func() any { return new(shutdownEntryArgs) })
	defer coremain.DelPluginType(pluginType)
	dir := t.TempDir()
	importFile := filepath.Join(dir, "import.json")
	if err := os.WriteFile(importFile, []byte(`{"version":1,"history_complete":true,"records":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	args := &domain_mapping.Args{
		Size:       128,
		Retention:  domain_mapping.RetentionArgs{Mode: "lru"},
		Allocation: domain_mapping.AllocationArgs{Enable: true, ClientScope: true, StateFile: filepath.Join(dir, "state"), ImportFile: importFile},
	}
	entered, release := make(chan struct{}, workers), make(chan struct{})
	m, err := coremain.NewMosdns(&coremain.Config{
		Log: mlog.LogConfig{Level: "error"},
		Plugins: []coremain.PluginConfig{
			{Tag: "mapping", Type: "domain_mapping", Args: args},
			{Tag: "entry", Type: pluginType, Args: &shutdownEntryArgs{entered: entered, release: release}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := server_utils.NewHandler(coremain.NewBP("transport", m), "entry")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	client := netip.MustParseAddr("192.168.6.180")
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q := new(dns.Msg)
			q.SetQuestion(fmt.Sprintf("load-%d.test.", i), dns.TypeA)
			payload := h.Handle(context.Background(), q, server.QueryMeta{ClientAddr: client}, pool.PackBuffer)
			if payload == nil {
				t.Error("admitted query did not finish")
				return
			}
			pool.ReleaseBuf(payload)
		}()
	}
	for range workers {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("query failed to enter pipeline")
		}
	}
	m.CloseWithErr(nil)
	done := make(chan error, 1)
	go func() { done <- m.WaitClosed() }()
	select {
	case err := <-done:
		t.Fatalf("shutdown skipped in-flight responses: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(args.Allocation.StateFile + ".dirty"); !os.IsNotExist(err) {
		t.Fatalf("graceful shutdown retained dirty marker: %v", err)
	}
	restored, err := domain_mapping.New(*args)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	r, err := restored.LookupV2Context(context.Background(), netip.MustParseAddr("203.0.113.10"), client)
	if err != nil || !r.Complete || len(r.Domains) != workers {
		t.Fatalf("clean restart lost finalized exposures or entered recovery: %+v, %v", r, err)
	}
}
