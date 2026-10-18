package domain_mapping

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func policyTestArgs(t *testing.T, endpoint string) PolicyArgs {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	return PolicyArgs{Endpoint: endpoint, SecretFile: path, Timeout: 100, CacheSize: 2, BatchSize: 4, QueueSize: 8}
}

func TestPolicyAsyncBatchCredentialRotationAndReplacement(t *testing.T) {
	var calls atomic.Int64
	var want atomic.Value
	want.Store("Bearer first")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != want.Load().(string) {
			t.Error("wrong policy credential")
			http.Error(w, "unauthorized", 401)
			return
		}
		var req struct {
			Version int         `json:"version"`
			Queries []policyKey `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		out := policyResponse{Version: 1, Epoch: "epoch", ValidForMS: 5000}
		for _, q := range req.Queries {
			out.Results = append(out.Results, struct {
				Domain        string `json:"domain"`
				Client        string `json:"client"`
				Class         string `json:"class"`
				ShareEligible bool   `json:"share_eligible"`
			}{q.Domain, q.Client, "unmatched", true})
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	args := policyTestArgs(t, server.URL)
	args.CacheSize = 1
	p := newPolicyCache(args)
	defer p.close()
	client := netip.MustParseAddr("192.168.6.180")
	for i := 0; i < 20; i++ {
		p.token("first.test", client, time.Now())
	}
	deadline := time.Now().Add(time.Second)
	for {
		share, _ := p.token("first.test", client, time.Now())
		if share {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("async policy never became available")
		}
		time.Sleep(time.Millisecond)
	}
	if calls.Load() != 1 {
		t.Fatalf("duplicate classification requests: %d", calls.Load())
	}
	want.Store("Bearer second")
	if err := os.WriteFile(args.SecretFile, []byte("second\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Expiry refresh replaces the same key at a full cache, then a new key
	// exercises eviction without retaining an unbounded classification map.
	p.mu.Lock()
	p.cache[policyKey{"first.test", client.String()}].until = time.Now().Add(-time.Second)
	p.mu.Unlock()
	for _, domain := range []string{"first.test", "second.test"} {
		deadline = time.Now().Add(time.Second)
		for {
			share, _ := p.token(domain, client, time.Now())
			if share {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("credential rotation or replacement failed")
			}
			time.Sleep(time.Millisecond)
		}
	}
	if p.len() != 1 || calls.Load() != 3 {
		t.Fatalf("cache=%d requests=%d", p.len(), calls.Load())
	}
}

func TestPolicyFailuresNeverAuthorizeSharingOrBlockDNS(t *testing.T) {
	for _, kind := range []string{"unavailable", "scope", "invalid_share", "oversized", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "unavailable" {
					http.Error(w, "down", 503)
					return
				}
				if kind == "oversized" {
					_, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
					return
				}
				if kind == "timeout" {
					select {
					case <-r.Context().Done():
					case <-time.After(100 * time.Millisecond):
					}
					return
				}
				var req struct {
					Queries []policyKey `json:"queries"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				q := req.Queries[0]
				class := "unmatched"
				if kind == "scope" {
					q.Client = "192.168.6.181"
				}
				if kind == "invalid_share" {
					class = "unknown"
				}
				_, _ = fmt.Fprintf(w, `{"version":1,"epoch":"e","valid_for_ms":1000,"results":[{"domain":%q,"client":%q,"class":%q,"share_eligible":true}]}`, q.Domain, q.Client, class)
			}))
			defer server.Close()
			args := policyTestArgs(t, server.URL)
			args.BatchSize = 1
			args.Timeout = 20
			p := newPolicyCache(args)
			defer p.close()
			client := netip.MustParseAddr("192.168.6.180")
			start := time.Now()
			for i := 0; i < 100; i++ {
				if share, _ := p.token("a.test", client, time.Now()); share {
					t.Fatal("unknown policy authorized sharing")
				}
			}
			if time.Since(start) > 50*time.Millisecond {
				t.Fatal("local token lookup blocked on network")
			}
			deadline := time.Now().Add(time.Second)
			for p.len() == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if p.len() != 1 {
				t.Fatal("policy failure was not bounded/cached")
			}
			if share, _ := p.token("a.test", client, time.Now()); share {
				t.Fatal("failed policy authorized sharing")
			}
			p.mu.Lock()
			if len(p.queued) > args.QueueSize+args.BatchSize {
				t.Fatal("unbounded pending requests")
			}
			p.mu.Unlock()
		})
	}
}
