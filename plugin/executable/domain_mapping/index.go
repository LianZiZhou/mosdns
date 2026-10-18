package domain_mapping

import (
	"container/heap"
	"container/list"
	"context"
	"net/netip"
	"time"
)

type lookupKey struct{ client, ip netip.Addr }

type observationKey struct {
	lookupKey
	domain, source string
}

type observation struct {
	key observationKey
	Candidate
	sequence     uint64
	heapPos      int
	order        *list.Element
	bucketOrders [2]*list.Element
}

type observationHeap []*observation

func (h observationHeap) Len() int           { return len(h) }
func (h observationHeap) Less(i, j int) bool { return h[i].ExpiresAt.Before(h[j].ExpiresAt) }
func (h observationHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapPos, h[j].heapPos = i, j
}
func (h *observationHeap) Push(v any) {
	o := v.(*observation)
	o.heapPos = len(*h)
	*h = append(*h, o)
}
func (h *observationHeap) Pop() any {
	old := *h
	o := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	return o
}

type observationIndex struct {
	size     int
	sequence uint64
	records  map[observationKey]*observation
	buckets  map[lookupKey]*observationBucket
	expiry   observationHeap
	order    list.List
}

// Every observation belongs to its client bucket and the global bucket. Each
// bucket keeps the same recency order as the index, plus reference counts for
// distinct domains. Route queries can therefore select and detect conflicts
// without scanning all records sharing an address.
type observationBucket struct {
	order   list.List
	domains map[string]int
}

// Candidates are bounded diagnostics, not an exhaustive list of observations.
// Keep at least two so limiting the list never hides a domain conflict.
const maxLookupCandidates = 32

// A caller may release its lock and check cancellation between expiry batches.
// All expired observations must be removed before reading route/conflict data.
const observationExpiryBatch = 128

func observationBucketKeys(key lookupKey) ([2]lookupKey, int) {
	keys := [2]lookupKey{key, {ip: key.ip}}
	if !key.client.IsValid() {
		// Without a client address, the client key already is the global key.
		return keys, 1
	}
	return keys, 2
}

func (s *observationIndex) init(size int) {
	s.size = size
	s.records = make(map[observationKey]*observation)
	s.buckets = make(map[lookupKey]*observationBucket)
}

func (s *observationIndex) remove(o *observation) {
	delete(s.records, o.key)
	keys, n := observationBucketKeys(o.key.lookupKey)
	for i, key := range keys[:n] {
		bucket := s.buckets[key]
		bucket.order.Remove(o.bucketOrders[i])
		bucket.domains[o.Domain]--
		if bucket.domains[o.Domain] == 0 {
			delete(bucket.domains, o.Domain)
		}
		if bucket.order.Len() == 0 {
			delete(s.buckets, key)
		}
	}
	heap.Remove(&s.expiry, o.heapPos)
	s.order.Remove(o.order)
}

func (s *observationIndex) expire(now time.Time) {
	for !s.expireBatch(now, observationExpiryBatch) {
	}
}

// expireBatch removes at most limit expired observations, returning true when
// none remain. The caller holds the index lock for each batch and must not read
// selection or domain counts until this reports completion for its lookup time.
func (s *observationIndex) expireBatch(now time.Time, limit int) bool {
	for removed := 0; removed < limit && len(s.expiry) > 0 && !now.Before(s.expiry[0].ExpiresAt); removed++ {
		s.remove(s.expiry[0])
	}
	return len(s.expiry) == 0 || now.Before(s.expiry[0].ExpiresAt)
}

func (s *observationIndex) put(client, ip netip.Addr, candidate Candidate) uint64 {
	key := observationKey{lookupKey: lookupKey{client: client, ip: ip}, domain: candidate.Domain, source: candidate.Source}
	s.sequence++
	if o := s.records[key]; o != nil {
		// A shorter new answer does not invalidate an earlier client cache.
		if candidate.ExpiresAt.Before(o.ExpiresAt) {
			candidate.ExpiresAt = o.ExpiresAt
		}
		o.Candidate, o.sequence = candidate, s.sequence
		heap.Fix(&s.expiry, o.heapPos)
		s.order.MoveToBack(o.order)
		keys, n := observationBucketKeys(key.lookupKey)
		for i, bucketKey := range keys[:n] {
			s.buckets[bucketKey].order.MoveToBack(o.bucketOrders[i])
		}
		return 0
	}
	var evicted uint64
	if len(s.records) >= s.size {
		// Writers only clean a bounded expiry batch. If more expired records
		// remain, reuse their capacity before evicting any live observation.
		if len(s.expiry) > 0 && !candidate.ObservedAt.Before(s.expiry[0].ExpiresAt) {
			s.remove(s.expiry[0])
		} else {
			s.remove(s.order.Front().Value.(*observation))
			evicted = 1
		}
	}
	o := &observation{key: key, Candidate: candidate, sequence: s.sequence}
	o.order = s.order.PushBack(o)
	s.records[key] = o
	heap.Push(&s.expiry, o)
	keys, n := observationBucketKeys(key.lookupKey)
	for i, bucketKey := range keys[:n] {
		bucket := s.buckets[bucketKey]
		if bucket == nil {
			bucket = &observationBucket{domains: make(map[string]int)}
			s.buckets[bucketKey] = bucket
		}
		o.bucketOrders[i] = bucket.order.PushBack(o)
		bucket.domains[o.Domain]++
	}
	return evicted
}

func (s *observationIndex) candidates(key lookupKey) []Candidate {
	result, _ := s.candidatesContext(context.Background(), key)
	return result
}

// route returns the latest observation, whether distinct domains conflict, and
// whether the bucket exists. The caller must first finish expiry at its lookup
// time; otherwise both selection and conflict could include expired evidence.
func (s *observationIndex) route(key lookupKey) (candidate Candidate, conflict, found bool) {
	bucket := s.buckets[key]
	if bucket == nil {
		return Candidate{}, false, false
	}
	return bucket.order.Back().Value.(*observation).Candidate, len(bucket.domains) > 1, true
}

// Diagnostics retain the newest observation for up to 32 distinct domains.
// Repeated records of one domain may still require walking a large bucket; the
// route view avoids this entirely, and diagnostic walks check cancellation.
func (s *observationIndex) candidatesContext(ctx context.Context, key lookupKey) ([]Candidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bucket := s.buckets[key]
	if bucket == nil {
		return []Candidate{}, nil
	}
	count := min(maxLookupCandidates, len(bucket.domains))
	result := make([]Candidate, 0, count)
	seen := make(map[string]struct{}, count)
	visited := 0
	for e := bucket.order.Back(); e != nil && len(result) < count; e = e.Prev() {
		if visited%observationExpiryBatch == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		visited++
		o := e.Value.(*observation)
		if _, exists := seen[o.Domain]; exists {
			continue
		}
		seen[o.Domain] = struct{}{}
		result = append(result, o.Candidate)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
