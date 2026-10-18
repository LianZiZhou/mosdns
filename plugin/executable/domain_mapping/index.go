package domain_mapping

import (
	"container/heap"
	"container/list"
	"net/netip"
	"sort"
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
	sequence uint64
	heapPos  int
	order    *list.Element
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
	buckets  map[lookupKey]map[observationKey]*observation
	expiry   observationHeap
	order    list.List
}

// Candidates are bounded diagnostics, not an exhaustive list of observations.
// Keep at least two so limiting the list never hides a domain conflict.
const maxLookupCandidates = 32

// candidateHeap retains the newest observation for each of the newest domains.
// Its root is the oldest retained candidate, so lookup work and temporary memory
// do not include sorting or collecting every domain in a large shared-IP bucket.
type candidateHeap struct {
	ordered  []*observation
	byDomain map[string]int
}

func (h candidateHeap) Len() int           { return len(h.ordered) }
func (h candidateHeap) Less(i, j int) bool { return h.ordered[i].sequence < h.ordered[j].sequence }
func (h candidateHeap) Swap(i, j int) {
	h.ordered[i], h.ordered[j] = h.ordered[j], h.ordered[i]
	h.byDomain[h.ordered[i].Domain], h.byDomain[h.ordered[j].Domain] = i, j
}
func (h *candidateHeap) Push(v any) {
	o := v.(*observation)
	h.byDomain[o.Domain] = len(h.ordered)
	h.ordered = append(h.ordered, o)
}
func (h *candidateHeap) Pop() any {
	last := len(h.ordered) - 1
	o := h.ordered[last]
	h.ordered[last] = nil
	h.ordered = h.ordered[:last]
	delete(h.byDomain, o.Domain)
	return o
}

func (h *candidateHeap) consider(o *observation) {
	if pos, exists := h.byDomain[o.Domain]; exists {
		if o.sequence > h.ordered[pos].sequence {
			h.ordered[pos] = o
			heap.Fix(h, pos)
		}
		return
	}
	if h.Len() < maxLookupCandidates {
		heap.Push(h, o)
	} else if o.sequence > h.ordered[0].sequence {
		delete(h.byDomain, h.ordered[0].Domain)
		h.ordered[0] = o
		h.byDomain[o.Domain] = 0
		heap.Fix(h, 0)
	}
}

func (s *observationIndex) init(size int) {
	s.size = size
	s.records = make(map[observationKey]*observation)
	s.buckets = make(map[lookupKey]map[observationKey]*observation)
}

func (s *observationIndex) remove(o *observation) {
	delete(s.records, o.key)
	for _, key := range []lookupKey{o.key.lookupKey, {ip: o.key.ip}} {
		bucket := s.buckets[key]
		delete(bucket, o.key)
		if len(bucket) == 0 {
			delete(s.buckets, key)
		}
	}
	heap.Remove(&s.expiry, o.heapPos)
	s.order.Remove(o.order)
}

func (s *observationIndex) expire(now time.Time) {
	for len(s.expiry) > 0 && !now.Before(s.expiry[0].ExpiresAt) {
		s.remove(s.expiry[0])
	}
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
		return 0
	}
	var evicted uint64
	if len(s.records) >= s.size {
		s.remove(s.order.Front().Value.(*observation))
		evicted = 1
	}
	o := &observation{key: key, Candidate: candidate, sequence: s.sequence}
	o.order = s.order.PushBack(o)
	s.records[key] = o
	heap.Push(&s.expiry, o)
	for _, bucketKey := range []lookupKey{key.lookupKey, {ip: ip}} {
		if s.buckets[bucketKey] == nil {
			s.buckets[bucketKey] = make(map[observationKey]*observation)
		}
		s.buckets[bucketKey][key] = o
	}
	return evicted
}

func (s *observationIndex) candidates(key lookupKey) []Candidate {
	bucket := s.buckets[key]
	if len(bucket) == 0 {
		return []Candidate{}
	}
	capacity := min(maxLookupCandidates, len(bucket))
	top := candidateHeap{
		ordered:  make([]*observation, 0, capacity),
		byDomain: make(map[string]int, capacity),
	}
	for _, o := range bucket {
		top.consider(o)
	}
	sort.Slice(top.ordered, func(i, j int) bool { return top.ordered[i].sequence > top.ordered[j].sequence })
	result := make([]Candidate, 0, len(top.ordered))
	for _, o := range top.ordered {
		result = append(result, o.Candidate)
	}
	return result
}
