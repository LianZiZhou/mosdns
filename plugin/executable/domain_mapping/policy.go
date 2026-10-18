package domain_mapping

import (
	"bytes"
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// PolicyArgs configures an asynchronous authority; DNS never waits for its RPC.
// The credential is read for every batch, allowing atomic credential rotation.
type PolicyArgs struct {
	Endpoint   string `yaml:"endpoint"`
	SecretFile string `yaml:"secret_file"`
	Timeout    int    `yaml:"timeout"`
	CacheSize  int    `yaml:"cache_size"`
	BatchSize  int    `yaml:"batch_size"`
	QueueSize  int    `yaml:"queue_size"`
}

func (a *AllocationArgs) normalize() error {
	if a.ClientScope && !a.Enable {
		return fmt.Errorf("allocation.client_scope requires allocation.enable")
	}
	if !a.ClientScope {
		if a.StateFile != "" || a.ImportFile != "" || a.Policy.Endpoint != "" {
			return fmt.Errorf("allocation state and policy require client_scope")
		}
		return nil
	}
	if a.StateFile == "" {
		return fmt.Errorf("client-scoped allocation requires allocation.state_file")
	}
	if a.StartupGuard < 0 || a.StartupGuard > 30*86400 {
		return fmt.Errorf("allocation.startup_guard must be at most 30 days")
	}
	if a.StartupGuard == 0 {
		a.StartupGuard = 86400
	}
	p := &a.Policy
	if p.Timeout < 0 || p.Timeout > 60000 || p.CacheSize < 0 || p.CacheSize > 1048576 || p.BatchSize < 0 || p.BatchSize > 256 || p.QueueSize < 0 || p.QueueSize > 65536 {
		return fmt.Errorf("allocation.policy limits are outside supported bounds")
	}
	if p.Timeout == 0 {
		p.Timeout = 200
	}
	if p.CacheSize == 0 {
		p.CacheSize = 65536
	}
	if p.BatchSize == 0 {
		p.BatchSize = 64
	}
	if p.QueueSize == 0 {
		p.QueueSize = 4096
	}
	if p.Endpoint != "" {
		u, err := url.Parse(p.Endpoint)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.RawQuery != "" || p.SecretFile == "" {
			return fmt.Errorf("allocation.policy requires an http(s) endpoint and secret_file")
		}
	}
	return nil
}

type policyKey struct {
	Domain string `json:"domain"`
	Client string `json:"client"`
}
type policyToken struct {
	key   policyKey
	class string
	share bool
	epoch string
	until time.Time
	order *list.Element
}
type policyCache struct {
	mu     sync.Mutex
	args   PolicyArgs
	cache  map[policyKey]*policyToken
	order  list.List
	queued map[policyKey]bool
	queue  chan policyKey
	epoch  string
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	client *http.Client
}

func newPolicyCache(args PolicyArgs) *policyCache {
	ctx, cancel := context.WithCancel(context.Background())
	p := &policyCache{args: args, cache: make(map[policyKey]*policyToken), queued: make(map[policyKey]bool), queue: make(chan policyKey, args.QueueSize), ctx: ctx, cancel: cancel, done: make(chan struct{}), client: &http.Client{Timeout: time.Duration(args.Timeout) * time.Millisecond, Transport: &http.Transport{MaxIdleConns: 2, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1, IdleConnTimeout: 30 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	go p.run()
	return p
}
func (p *policyCache) len() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.cache) }

// token only reads a valid local result or queues one bounded, deduplicated job.
// All owners must have the SAME current epoch before sharing is admitted.
func (p *policyCache) token(domain string, client netip.Addr, now time.Time) (share bool, epoch string) {
	if p == nil || p.args.Endpoint == "" || !client.IsValid() {
		return false, ""
	}
	k := policyKey{domain, client.Unmap().String()}
	p.mu.Lock()
	defer p.mu.Unlock()
	if t := p.cache[k]; t != nil && now.Before(t.until) && t.epoch == p.epoch {
		p.order.MoveToBack(t.order)
		return t.share, t.epoch
	}
	if !p.queued[k] {
		select {
		case p.queue <- k:
			p.queued[k] = true
		default:
		}
	}
	return false, ""
}

func (p *policyCache) run() {
	defer close(p.done)
	for {
		var batch []policyKey
		select {
		case <-p.ctx.Done():
			return
		case k := <-p.queue:
			batch = append(batch, k)
		}
		// A small batching window coalesces bursts without delaying any DNS reply.
		timer := time.NewTimer(5 * time.Millisecond)
	collect:
		for len(batch) < p.args.BatchSize {
			select {
			case <-p.ctx.Done():
				timer.Stop()
				return
			case k := <-p.queue:
				batch = append(batch, k)
			case <-timer.C:
				break collect
			}
		}
		timer.Stop()
		p.fetch(batch)
	}
}

type policyResponse struct {
	Version    int    `json:"version"`
	Epoch      string `json:"epoch"`
	ValidForMS int    `json:"valid_for_ms"`
	Results    []struct {
		Domain        string `json:"domain"`
		Client        string `json:"client"`
		Class         string `json:"class"`
		ShareEligible bool   `json:"share_eligible"`
	} `json:"results"`
}

func (p *policyCache) fetch(batch []policyKey) {
	result, err := p.request(batch)
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if err == nil && result.Epoch != p.epoch {
		p.epoch = result.Epoch
		clear(p.cache)
		p.order.Init()
	}
	for i, k := range batch {
		delete(p.queued, k)
		t := policyToken{key: k, class: "unknown", epoch: p.epoch, until: now.Add(time.Second)}
		if err == nil {
			r := result.Results[i]
			t.class = r.Class
			t.share = r.ShareEligible && (r.Class == "unmatched" || r.Class == "direct")
			t.until = now.Add(time.Duration(min(result.ValidForMS, 5000)) * time.Millisecond)
		}
		if old := p.cache[k]; old != nil {
			p.order.Remove(old.order)
			delete(p.cache, k)
		}
		if len(p.cache) >= p.args.CacheSize {
			old := p.order.Front().Value.(*policyToken)
			delete(p.cache, old.key)
			p.order.Remove(old.order)
		}
		t.order = p.order.PushBack(&t)
		p.cache[k] = &t
	}
}

func (p *policyCache) request(batch []policyKey) (policyResponse, error) {
	var result policyResponse
	f, err := os.Open(p.args.SecretFile)
	if err != nil {
		return result, err
	}
	secret, err := io.ReadAll(io.LimitReader(f, 16385))
	_ = f.Close()
	if err != nil || len(secret) > 16384 {
		return result, fmt.Errorf("invalid policy credential file")
	}
	credential := strings.TrimSpace(string(secret))
	if credential == "" || strings.ContainsAny(credential, "\r\n") {
		return result, fmt.Errorf("invalid policy credential")
	}
	body, _ := json.Marshal(struct {
		Version int         `json:"version"`
		Queries []policyKey `json:"queries"`
	}{1, batch})
	ctx, cancel := context.WithTimeout(p.ctx, time.Duration(p.args.Timeout)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.args.Endpoint, bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("policy classification unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil || len(data) > 1<<20 {
		return result, fmt.Errorf("policy response too large")
	}
	if err = json.Unmarshal(data, &result); err != nil {
		return result, err
	}
	if result.Version != 1 || result.Epoch == "" || len(result.Epoch) > 256 || result.ValidForMS < 1 || result.ValidForMS > 300000 || len(result.Results) != len(batch) {
		return result, fmt.Errorf("invalid policy response")
	}
	for i, r := range result.Results {
		if r.Domain != batch[i].Domain || r.Client != batch[i].Client {
			return result, fmt.Errorf("policy response scope mismatch")
		}
		switch r.Class {
		case "unknown", "unmatched", "direct", "isolated":
		default:
			return result, fmt.Errorf("unknown policy class")
		}
		if r.ShareEligible && r.Class != "unmatched" && r.Class != "direct" {
			return result, fmt.Errorf("invalid policy sharing result")
		}
	}
	return result, nil
}

func (p *policyCache) close() { p.cancel(); <-p.done; p.client.CloseIdleConnections() }
