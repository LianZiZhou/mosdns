package domain_mapping

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/mlog"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	stateMagic   = "MDMAP2\n"
	maxStateFile = 64 << 20
	maxStateJSON = 256 << 20
	maxWALEvent  = 1 << 20
	maxWALFile   = 16 << 20
	compactWALAt = 4 << 20
)

type stateKey struct {
	Client string `json:"client"`
	IP     string `json:"ip"`
}
type stateRecord struct {
	Client       string    `json:"client"`
	IP           string    `json:"ip"`
	Domain       string    `json:"domain"`
	Source       string    `json:"source"`
	ObservedAt   time.Time `json:"observed_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	DNSExpiresAt time.Time `json:"dns_expires_at"`
	BaseTTL      int64     `json:"base_ttl,omitempty"`
	Sequence     uint64    `json:"sequence,omitempty"`
}
type stateSnapshot struct {
	Version           int                 `json:"version"`
	HistoryComplete   bool                `json:"history_complete"`
	GuardUntil        time.Time           `json:"guard_until,omitempty"`
	IncompleteUntil   time.Time           `json:"incomplete_until,omitempty"`
	Generation        uint64              `json:"generation,omitempty"`
	Guard             []byte              `json:"guard,omitempty"`
	Records           []stateRecord       `json:"records"`
	IncompleteBuckets []stateKey          `json:"incomplete_buckets,omitempty"`
	Preferences       []statePreference   `json:"preferences,omitempty"`
	RoutingHints      *[]stateRoutingHint `json:"routing_hints,omitempty"`
	RoutingSequence   uint64              `json:"routing_sequence,omitempty"`
}
type stateEvent struct {
	Records         []stateRecord     `json:"records"`
	Names           []string          `json:"names,omitempty"`
	Client          string            `json:"client,omitempty"`
	Uncertain       bool              `json:"uncertain,omitempty"`
	Taints          []stateKey        `json:"taints,omitempty"`
	Preferences     []statePreference `json:"preferences,omitempty"`
	RoutingSequence uint64            `json:"routing_sequence,omitempty"`
}
type stateStore struct {
	p         *DomainMapping
	path      string
	queue     chan stateEvent
	stop      chan struct{}
	done      chan struct{}
	failed    atomic.Bool
	closeOnce sync.Once
	file      *os.File
	bytes     int64
	markerMu  sync.Mutex
	closeErr  error
}

func stateEventFor(domain string, client netip.Addr, evidence []evidence, names []string, uncertain bool, now time.Time) stateEvent {
	event := stateEvent{Names: names, Client: client.String(), Uncertain: uncertain}
	for _, e := range evidence {
		expires := now.Add(time.Duration(e.ttl) * time.Second)
		event.Records = append(event.Records, stateRecord{Client: client.String(), IP: e.ip.String(), Domain: domain, Source: e.source, ObservedAt: now, DNSExpiresAt: expires, ExpiresAt: expires})
	}
	return event
}

// A dirty marker is durable before the first answer. Batched WAL avoids disk
// latency on the DNS hot path; an interrupted or dropped batch activates the
// explicit startup guard after restart, never an invented empty history.
func (p *DomainMapping) openState() (*stateStore, error) {
	s := &stateStore{p: p, path: p.args.Allocation.StateFile, queue: make(chan stateEvent, 128), stop: make(chan struct{}), done: make(chan struct{})}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return nil, fmt.Errorf("create allocation state directory: %w", err)
	}
	_, dirtyErr := os.Stat(s.path + ".dirty")
	dirty := dirtyErr == nil || !errors.Is(dirtyErr, os.ErrNotExist)
	if dirty {
		s.logRecovery("dirty_marker", dirtyErr)
	}
	snapshot, err := readStateSnapshot(s.path)
	imported := false
	if errors.Is(err, os.ErrNotExist) && p.args.Allocation.ImportFile != "" {
		snapshot, err = readStateImport(p.args.Allocation.ImportFile)
		imported = err == nil
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read allocation import: %w", err)
		}
	}
	if err == nil {
		if err = p.restoreSnapshot(snapshot); err != nil {
			if imported {
				return nil, fmt.Errorf("validate allocation import: %w", err)
			}
			p.index = observationIndex{}
			p.index.init(p.args.Size)
			p.index.retention = p.args.Retention
			p.index.onRemove = p.forgetObservation
			p.clients = newClientAllocator(p.args.Allocation.Size)
			p.routes.init(p.args.Routing.Size)
			p.preferences.init(p.args.Allocation.Size)
			p.routingRestoreCutoff = 0
			p.routingRestored = false
		}
	}
	if err != nil {
		reason := "snapshot_invalid"
		if errors.Is(err, os.ErrNotExist) {
			reason = "snapshot_missing"
		}
		s.logRecovery(reason, err)
	} else if !snapshot.HistoryComplete && snapshot.GuardUntil.IsZero() {
		s.logRecovery("snapshot_incomplete", nil)
	}
	if err != nil || dirty || (!snapshot.HistoryComplete && snapshot.GuardUntil.IsZero()) {
		p.clients.guardUntil = maxTime(p.clients.guardUntil, p.now().Add(time.Duration(p.args.Allocation.StartupGuard)*time.Second))
		p.clients.recovery = true
	}
	if err != nil || dirty {
		p.clients.incompleteUntil = maxTime(p.clients.incompleteUntil, p.clients.guardUntil)
	}
	// Connection LRU touches are deliberately not journaled. After an
	// interrupted run, replaying DNS alone cannot reconstruct which hints
	// were evicted. Keep allocation evidence, but start routing cold.
	discardRouting := dirty || err != nil || (!snapshot.HistoryComplete && snapshot.GuardUntil.IsZero())
	routingBeforeWAL := p.routes.sequence
	if walErr := s.replayWAL(); walErr != nil {
		discardRouting = true
		s.logRecovery("wal_replay_error", walErr)
		p.clients.guardUntil = maxTime(p.clients.guardUntil, p.now().Add(time.Duration(p.args.Allocation.StartupGuard)*time.Second))
		p.clients.recovery = true
		p.clients.incompleteUntil = maxTime(p.clients.incompleteUntil, p.clients.guardUntil)
	}
	if discardRouting || p.routes.sequence != routingBeforeWAL {
		sequence := p.routes.sequence
		p.routes.init(p.args.Routing.Size)
		p.routes.sequence = sequence
		p.routingRestored = true
		p.routingRestoreCutoff = sequence
		s.logger().Info("domain mapping routing cache starts empty after uncertain recovery")
	}
	if err := s.markDirty(); err != nil {
		return nil, fmt.Errorf("persist allocation startup marker: %w", err)
	}
	// Normalize imports/replayed WAL into a checksummed snapshot before accepting
	// queries. A failed initial checkpoint must not discard the old WAL.
	if err := s.checkpoint(); err != nil {
		return nil, fmt.Errorf("checkpoint allocation state: %w", err)
	}
	p.clients.journalReady = true
	go s.run()
	return s, nil
}

func (s *stateStore) logRecovery(reason string, err error) {
	s.logger().Warn("domain mapping allocation recovery", zap.String("reason", reason), zap.Error(err))
}

func (s *stateStore) fail(reason string, err error) {
	if !s.failed.Swap(true) {
		s.logger().Error("domain mapping state persistence failed", zap.String("reason", reason), zap.Error(err))
	}
}

func (s *stateStore) logger() *zap.Logger {
	if s.p.logger != nil {
		return s.p.logger
	}
	return mlog.L()
}

func readStateImport(path string) (stateSnapshot, error) {
	var snapshot stateSnapshot
	f, err := os.Open(path)
	if err != nil {
		return snapshot, err
	}
	defer f.Close()
	return decodeStateSnapshot(io.LimitReader(f, maxStateJSON+1))
}

func readStateSnapshot(path string) (stateSnapshot, error) {
	var snapshot stateSnapshot
	f, err := os.Open(path)
	if err != nil {
		return snapshot, err
	}
	defer f.Close()
	header := make([]byte, len(stateMagic)+65)
	if _, err = io.ReadFull(f, header); err != nil {
		return snapshot, err
	}
	if string(header[:len(stateMagic)]) != stateMagic || header[len(header)-1] != '\n' {
		return snapshot, fmt.Errorf("invalid allocation state header")
	}
	expected, err := hex.DecodeString(string(header[len(stateMagic) : len(header)-1]))
	if err != nil {
		return snapshot, err
	}
	hash := sha256.New()
	limited := io.LimitReader(f, maxStateFile+1)
	compressed, err := io.ReadAll(io.TeeReader(limited, hash))
	if err != nil || len(compressed) > maxStateFile {
		return snapshot, fmt.Errorf("allocation state exceeds limit")
	}
	if !equalBytes(hash.Sum(nil), expected) {
		return snapshot, fmt.Errorf("allocation state checksum mismatch")
	}
	z, err := gzip.NewReader(newByteReader(compressed))
	if err != nil {
		return snapshot, err
	}
	defer z.Close()
	return decodeStateSnapshot(io.LimitReader(z, maxStateJSON+1))
}

// Decode the record array incrementally rather than retaining its whole JSON
// representation in addition to the ownership index and snapshot records.
func decodeStateSnapshot(reader io.Reader) (stateSnapshot, error) {
	var s stateSnapshot
	dec := json.NewDecoder(reader)
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return s, fmt.Errorf("invalid state object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return s, err
		}
		key, ok := tok.(string)
		if !ok || seen[key] {
			return s, fmt.Errorf("duplicate state field")
		}
		seen[key] = true
		switch key {
		case "version":
			err = dec.Decode(&s.Version)
		case "history_complete":
			err = dec.Decode(&s.HistoryComplete)
		case "guard_until":
			err = dec.Decode(&s.GuardUntil)
		case "incomplete_until":
			err = dec.Decode(&s.IncompleteUntil)
		case "generation":
			err = dec.Decode(&s.Generation)
		case "routing_sequence":
			err = dec.Decode(&s.RoutingSequence)
		case "routing_hints":
			tok, err = dec.Token()
			if err != nil {
				return s, err
			}
			if tok != json.Delim('[') {
				return s, fmt.Errorf("invalid state routing hints")
			}
			hints := make([]stateRoutingHint, 0)
			for dec.More() {
				if len(hints) >= 1048576 {
					return s, fmt.Errorf("too many state routing hints")
				}
				var hint stateRoutingHint
				if err = dec.Decode(&hint); err != nil {
					return s, err
				}
				hints = append(hints, hint)
			}
			s.RoutingHints = &hints
			_, err = dec.Token()
		case "guard":
			err = dec.Decode(&s.Guard)
		case "incomplete_buckets":
			err = dec.Decode(&s.IncompleteBuckets)
		case "preferences":
			tok, err = dec.Token()
			if err != nil {
				return s, err
			}
			if tok == nil {
				continue
			}
			if tok != json.Delim('[') {
				return s, fmt.Errorf("invalid state preferences")
			}
			for dec.More() {
				if len(s.Preferences) >= 1048576 {
					return s, fmt.Errorf("too many state preferences")
				}
				var preference statePreference
				if err = dec.Decode(&preference); err != nil {
					return s, err
				}
				s.Preferences = append(s.Preferences, preference)
			}
			_, err = dec.Token()
		case "records":
			tok, err = dec.Token()
			if err != nil {
				return s, err
			}
			if tok == nil {
				continue
			}
			if tok != json.Delim('[') {
				return s, fmt.Errorf("invalid state records")
			}
			for dec.More() {
				if len(s.Records) >= 1048576 {
					return s, fmt.Errorf("too many state records")
				}
				var record stateRecord
				if err = dec.Decode(&record); err != nil {
					return s, err
				}
				s.Records = append(s.Records, record)
			}
			_, err = dec.Token()
		default:
			return s, fmt.Errorf("unknown state field %q", key)
		}
		if err != nil {
			return s, err
		}
	}
	if _, err = dec.Token(); err != nil {
		return s, err
	}
	var trailing any
	if err = dec.Decode(&trailing); err != io.EOF {
		return s, fmt.Errorf("trailing state data")
	}
	return s, nil
}

func (p *DomainMapping) restoreSnapshot(snapshot stateSnapshot) error {
	if snapshot.Version != 1 || len(snapshot.Records) > 1048576 || (len(snapshot.Guard) != 0 && len(snapshot.Guard) != exposureGuardBytes) {
		return fmt.Errorf("invalid allocation state version or limits")
	}
	if len(snapshot.Guard) > 0 {
		copy(p.clients.guard, snapshot.Guard)
	}
	p.clients.guardUntil = snapshot.GuardUntil
	p.clients.incompleteUntil = snapshot.IncompleteUntil
	p.clients.recovery = p.now().Before(snapshot.GuardUntil) || p.now().Before(snapshot.IncompleteUntil)
	p.generation = snapshot.Generation
	p.routingRestored = snapshot.RoutingHints != nil
	p.routingRestoreCutoff = snapshot.RoutingSequence
	sort.SliceStable(snapshot.Records, func(i, j int) bool {
		a, b := snapshot.Records[i], snapshot.Records[j]
		if a.ObservedAt.Equal(b.ObservedAt) {
			return a.Sequence < b.Sequence
		}
		return a.ObservedAt.Before(b.ObservedAt)
	})
	for _, r := range snapshot.Records {
		if err := p.restoreRecordWithRouting(r, !p.routingRestored); err != nil {
			return err
		}
	}
	if snapshot.RoutingHints != nil {
		if err := p.restoreRouting(*snapshot.RoutingHints); err != nil {
			return err
		}
		p.routes.sequence = snapshot.RoutingSequence
	}
	if err := p.restorePreferences(snapshot.Preferences); err != nil {
		return err
	}
	for _, key := range snapshot.IncompleteBuckets {
		if err := p.restoreTaint(key); err != nil {
			return err
		}
	}
	p.clients.taints = nil
	return nil
}

func parseStateClient(s string) (netip.Addr, error) {
	if s == "" || s == "invalid IP" {
		return netip.Addr{}, nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid state client")
	}
	return ip.Unmap(), nil
}
func (p *DomainMapping) restoreRecord(r stateRecord) error {
	return p.restoreRecordWithRouting(r, true)
}

func (p *DomainMapping) restoreRecordWithRouting(r stateRecord, restoreRouting bool) error {
	client, err := parseStateClient(r.Client)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(r.IP)
	if err != nil || ip.Zone() != "" || len(r.Domain) > 253 || canonicalName(r.Domain) != r.Domain || r.Domain == "" || len(r.Source) > 64 || r.ObservedAt.IsZero() || r.DNSExpiresAt.IsZero() || r.BaseTTL < 0 {
		return fmt.Errorf("invalid allocation state record")
	}
	if _, ok := dns.IsDomainName(r.Domain); !ok {
		return fmt.Errorf("invalid allocation state domain")
	}
	ip = ip.Unmap()
	key := observationKey{lookupKey: lookupKey{client: client, ip: ip}, domain: r.Domain, source: r.Source}
	if old := p.index.records[key]; old != nil && old.ObservedAt.After(r.ObservedAt) {
		return nil
	}
	expires := r.DNSExpiresAt
	p.stats.ObservationEvicts += p.index.put(client, ip, Candidate{Domain: r.Domain, Source: r.Source, ObservedAt: r.ObservedAt, ExpiresAt: r.ExpiresAt, DNSExpiresAt: &expires, RetentionMode: p.args.Retention.Mode})
	o := p.index.records[key]
	o.ExpiresAt = maxTime(o.ExpiresAt, r.ExpiresAt)
	o.baseTTL = max(o.baseTTL, time.Duration(r.BaseTTL))
	if restoreRouting {
		p.restoreRoutingHint(r, client, ip)
	}
	return nil
}
func (p *DomainMapping) restoreTaint(key stateKey) error {
	client, err := parseStateClient(key.Client)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(key.IP)
	if err != nil || ip.Zone() != "" {
		return fmt.Errorf("invalid allocation taint")
	}
	p.clients.guard.add(client, ip.Unmap(), "")
	p.clients.guard.add(netip.Addr{}, ip.Unmap(), "")
	return nil
}
func (p *DomainMapping) applyStateEvent(event stateEvent) error {
	// Compaction can include observations whose WAL events are still queued.
	// Replaying those events must not resurrect an LRU entry evicted before
	// the snapshot, or replace its persisted access order with DNS-time order.
	restoreRouting := !p.routingRestored || (event.RoutingSequence != 0 && event.RoutingSequence > p.routingRestoreCutoff)
	client, err := parseStateClient(event.Client)
	if err != nil {
		return err
	}
	if len(event.Records) > 4096 || len(event.Names) > 4096 || len(event.Taints) > 4096 || len(event.Preferences) > 4096 {
		return fmt.Errorf("oversized allocation event")
	}
	for _, name := range event.Names {
		if name == "" || len(name) > 253 {
			return fmt.Errorf("invalid state dependency")
		}
		p.clients.guard.add(client, netip.Addr{}, name)
		if event.Uncertain {
			p.clients.guard.add(client, netip.Addr{}, "uncertain:"+name)
			p.clients.guard.add(netip.Addr{}, netip.Addr{}, "uncertain:"+name)
		}
	}
	for _, r := range event.Records {
		if err := p.restoreRecordWithRouting(r, restoreRouting); err != nil {
			return err
		}
		if event.Uncertain {
			if err := p.restoreTaint(stateKey{Client: r.Client, IP: r.IP}); err != nil {
				return err
			}
		}
	}
	for _, key := range event.Taints {
		if err := p.restoreTaint(key); err != nil {
			return err
		}
	}
	if restoreRouting {
		if err := p.restorePreferences(event.Preferences); err != nil {
			return err
		}
		p.routes.sequence = max(p.routes.sequence, event.RoutingSequence)
		if p.routingRestored {
			p.routingRestoreCutoff = event.RoutingSequence
		}
	}
	p.clients.taints = nil
	return nil
}

func (s *stateStore) replayWAL() error {
	f, err := os.Open(s.path + ".wal")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	reader := bufio.NewReader(io.LimitReader(f, maxWALFile+1))
	total := 0
	for {
		var header [36]byte
		_, err := io.ReadFull(reader, header[:])
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		n := int(binary.BigEndian.Uint32(header[:4]))
		total += n + 36
		if n < 1 || n > maxWALEvent || total > maxWALFile {
			return fmt.Errorf("invalid allocation WAL length")
		}
		body := make([]byte, n)
		if _, err = io.ReadFull(reader, body); err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		if !equalBytes(sum[:], header[4:]) {
			return fmt.Errorf("allocation WAL checksum mismatch")
		}
		var event stateEvent
		if err = json.Unmarshal(body, &event); err != nil {
			return err
		}
		if err = s.p.applyStateEvent(event); err != nil {
			return err
		}
	}
}

func (s *stateStore) markDirty() error {
	s.markerMu.Lock()
	defer s.markerMu.Unlock()
	f, err := os.OpenFile(s.path+".dirty", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.WriteAt([]byte("unclean until checkpointed shutdown\n"), 0); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = syncDirectory(filepath.Dir(s.path))
	}
	return err
}

func (s *stateStore) enqueue(event stateEvent) {
	select {
	case s.queue <- event:
	default:
		s.fail("queue_overflow", nil)
		s.p.clients.recovery = true
		s.p.clients.guardUntil = maxTime(s.p.clients.guardUntil, s.p.now().Add(time.Duration(s.p.args.Allocation.StartupGuard)*time.Second))
		s.p.clients.incompleteUntil = maxTime(s.p.clients.incompleteUntil, s.p.clients.guardUntil)
	}
}
func (s *stateStore) run() {
	defer close(s.done)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			for {
				select {
				case event := <-s.queue:
					if err := s.appendEvent(event); err != nil {
						s.fail("wal_append_error", err)
					}
				default:
					goto drained
				}
			}
		drained:
			if s.file != nil {
				if err := s.file.Sync(); err != nil {
					s.fail("wal_sync_error", err)
				}
				if err := s.file.Close(); err != nil {
					s.fail("wal_close_error", err)
				}
				s.file = nil
			}
			return
		case event := <-s.queue:
			if err := s.appendEvent(event); err != nil {
				s.fail("wal_append_error", err)
			}
		case <-ticker.C:
			if s.file != nil {
				if err := s.file.Sync(); err != nil {
					s.fail("wal_sync_error", err)
				}
			}
		}
		if s.bytes >= compactWALAt {
			if err := s.checkpoint(); err != nil {
				s.fail("checkpoint_error", err)
			}
		}
	}
}
func (s *stateStore) appendEvent(event stateEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(body) > maxWALEvent {
		return fmt.Errorf("allocation event exceeds limit")
	}
	if s.bytes+int64(len(body)+36) > maxWALFile {
		if err := s.checkpoint(); err != nil {
			return err
		}
	}
	if s.file == nil {
		s.file, err = os.OpenFile(s.path+".wal", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return err
		}
		info, err := s.file.Stat()
		if err != nil {
			return err
		}
		s.bytes = info.Size()
	}
	var header [36]byte
	binary.BigEndian.PutUint32(header[:4], uint32(len(body)))
	sum := sha256.Sum256(body)
	copy(header[4:], sum[:])
	if _, err = s.file.Write(header[:]); err != nil {
		return err
	}
	if _, err = s.file.Write(body); err != nil {
		return err
	}
	s.bytes += int64(len(body) + 36)
	return nil
}

// Snapshot iteration holds the response lock for at most 128 entries. Map
// changes between batches are allowed by Go's iterator semantics. New commits
// remain in the queue/WAL, and the guard copied AFTER iteration covers owners
// evicted during the copy. A snapshot may conservatively retain extra owners.
func (s *stateStore) snapshot() stateSnapshot {
	p := s.p
	snapshot := stateSnapshot{Version: 1, HistoryComplete: true}
	p.mu.Lock()
	iter := reflect.ValueOf(p.index.records).MapRange()
	snapshot.Records = make([]stateRecord, 0, len(p.index.records))
	p.mu.Unlock()
	more := true
	for more {
		p.mu.Lock()
		for count := 0; count < 128; count++ {
			if !iter.Next() {
				more = false
				break
			}
			o := iter.Value().Interface().(*observation)
			r := stateRecord{Client: o.key.client.String(), IP: o.key.ip.String(), Domain: o.Domain, Source: o.Source, ObservedAt: o.ObservedAt, ExpiresAt: o.ExpiresAt, BaseTTL: int64(o.baseTTL), Sequence: o.sequence}
			if o.DNSExpiresAt != nil {
				r.DNSExpiresAt = *o.DNSExpiresAt
			} else {
				r.DNSExpiresAt = o.ExpiresAt
			}
			snapshot.Records = append(snapshot.Records, r)
		}
		p.mu.Unlock()
	}
	p.mu.Lock()
	snapshot.Guard = append([]byte(nil), p.clients.guard...)
	snapshot.GuardUntil = p.clients.guardUntil
	snapshot.IncompleteUntil = p.clients.incompleteUntil
	snapshot.HistoryComplete = !p.now().Before(snapshot.GuardUntil) && !p.now().Before(snapshot.IncompleteUntil)
	snapshot.Generation = p.generation
	snapshot.Preferences = p.preferenceSnapshot()
	hints := p.routingSnapshot()
	snapshot.RoutingHints = &hints
	snapshot.RoutingSequence = p.routes.sequence
	p.mu.Unlock()
	return snapshot
}

type cappedWriter struct {
	w    io.Writer
	left int64
}

func (w *cappedWriter) Write(b []byte) (int, error) {
	if int64(len(b)) > w.left {
		return 0, fmt.Errorf("allocation snapshot exceeds disk limit")
	}
	n, err := w.w.Write(b)
	w.left -= int64(n)
	return n, err
}
func (s *stateStore) checkpoint() error {
	snapshot := s.snapshot()
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".domain-mapping-state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = tmp.Close(); _ = os.Remove(tmpName) }()
	header := make([]byte, len(stateMagic)+65)
	copy(header, stateMagic)
	header[len(header)-1] = '\n'
	if _, err = tmp.Write(header); err != nil {
		return err
	}
	hash := sha256.New()
	limited := &cappedWriter{w: io.MultiWriter(tmp, hash), left: maxStateFile}
	z, err := gzip.NewWriterLevel(limited, gzip.BestSpeed)
	if err != nil {
		return err
	}
	if err = writeStateJSON(z, snapshot); err != nil {
		_ = z.Close()
		return err
	}
	if err = z.Close(); err != nil {
		return err
	}
	copy(header[len(stateMagic):], hex.EncodeToString(hash.Sum(nil)))
	header[len(header)-1] = '\n'
	if _, err = tmp.WriteAt(header, 0); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, s.path); err != nil {
		return err
	}
	if err = syncDirectory(filepath.Dir(s.path)); err != nil {
		return err
	}
	if s.file != nil {
		if err = s.file.Close(); err != nil {
			s.file = nil
			return err
		}
		s.file = nil
	}
	f, err := os.OpenFile(s.path+".wal", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	s.file = f
	s.bytes = 0
	s.failed.Store(false)
	return nil
}

func writeStateJSON(writer io.Writer, snapshot stateSnapshot) error {
	metadata := struct {
		Version         int       `json:"version"`
		HistoryComplete bool      `json:"history_complete"`
		GuardUntil      time.Time `json:"guard_until,omitempty"`
		IncompleteUntil time.Time `json:"incomplete_until,omitempty"`
		Generation      uint64    `json:"generation"`
		Guard           []byte    `json:"guard"`
		RoutingSequence uint64    `json:"routing_sequence,omitempty"`
	}{snapshot.Version, snapshot.HistoryComplete, snapshot.GuardUntil, snapshot.IncompleteUntil, snapshot.Generation, snapshot.Guard, snapshot.RoutingSequence}
	header, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	buf := bufio.NewWriterSize(writer, 65536)
	if _, err = buf.Write(header[:len(header)-1]); err != nil {
		return err
	}
	if _, err = buf.WriteString(",\"records\":["); err != nil {
		return err
	}
	enc := json.NewEncoder(buf)
	for i, record := range snapshot.Records {
		if i > 0 {
			if err = buf.WriteByte(','); err != nil {
				return err
			}
		}
		if err = enc.Encode(record); err != nil {
			return err
		}
	}
	if _, err = buf.WriteString("],\"preferences\":["); err != nil {
		return err
	}
	for i, preference := range snapshot.Preferences {
		if i > 0 {
			if err = buf.WriteByte(','); err != nil {
				return err
			}
		}
		if err = enc.Encode(preference); err != nil {
			return err
		}
	}
	if err = buf.WriteByte(']'); err != nil {
		return err
	}
	if snapshot.RoutingHints != nil {
		if _, err = buf.WriteString(",\"routing_hints\":["); err != nil {
			return err
		}
		for i, hint := range *snapshot.RoutingHints {
			if i > 0 {
				if err = buf.WriteByte(','); err != nil {
					return err
				}
			}
			if err = enc.Encode(hint); err != nil {
				return err
			}
		}
		if err = buf.WriteByte(']'); err != nil {
			return err
		}
	}
	if _, err = buf.WriteString("}\n"); err != nil {
		return err
	}
	return buf.Flush()
}

func (p *DomainMapping) Close() error {
	if p.state == nil {
		return nil
	}
	p.state.closeOnce.Do(func() {
		p.mu.Lock()
		p.clients.closing = true
		p.mu.Unlock()
		drained := make(chan struct{})
		go func() {
			p.clients.inflight.Wait()
			close(drained)
		}()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case <-drained:
		case <-timer.C:
			p.state.closeErr = errors.New("response finalizers did not drain; allocation state left dirty")
			p.state.fail("finalizer_drain_timeout", p.state.closeErr)
			return
		}
		if p.policy != nil {
			p.policy.close()
		}
		close(p.state.stop)
		<-p.state.done
		p.state.closeErr = p.state.checkpoint()
		if p.state.file != nil {
			p.state.closeErr = errors.Join(p.state.closeErr, p.state.file.Close())
			p.state.file = nil
		}
		p.state.markerMu.Lock()
		p.mu.Lock()
		if p.clients.late {
			p.state.closeErr = errors.Join(p.state.closeErr, errors.New("late response after shutdown began; allocation state left dirty"))
			p.state.logRecovery("late_close", nil)
		}
		if p.state.closeErr == nil {
			p.state.closeErr = os.Remove(p.state.path + ".dirty")
			if p.state.closeErr == nil {
				p.state.closeErr = syncDirectory(filepath.Dir(p.state.path))
			}
		}
		p.mu.Unlock()
		p.state.markerMu.Unlock()
		if p.state.closeErr != nil {
			// A directory fsync can fail after unlink. Recreate the recovery
			// marker rather than advertising clean state after that failure.
			p.state.closeErr = errors.Join(p.state.closeErr, p.state.markDirty())
			p.state.fail("shutdown_checkpoint_error", p.state.closeErr)
		}
	})
	return p.state.closeErr
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

type byteReader struct {
	data []byte
	off  int
}

func newByteReader(data []byte) *byteReader { return &byteReader{data: data} }
func (r *byteReader) Read(b []byte) (int, error) {
	if r.off == len(r.data) {
		return 0, io.EOF
	}
	n := copy(b, r.data[r.off:])
	r.off += n
	return n, nil
}
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// Windows does not expose directory fsync through os.File. File contents
	// are still synced; Linux/OpenWrt requires and checks directory durability.
	if runtime.GOOS == "windows" {
		return nil
	}
	return f.Sync()
}
