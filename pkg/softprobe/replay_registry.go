// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	DefaultReplayRegistrySize = 16384
	DefaultReplayRegistryTTL  = 10 * time.Minute

	DefaultWriteTrackerSize   = 32768
	DefaultWriteTrackerTTL    = 2 * time.Minute
	defaultPerSocketRingBound = 64
)

var sharedReplayRegistry = sync.OnceValue(func() *ReplayRegistry {
	return NewReplayRegistry(0, 0)
})

func SharedReplayRegistry() *ReplayRegistry {
	return sharedReplayRegistry()
}

type ReplaySession struct {
	TraceID            [16]byte
	Mode               TrafficMode
	RecordedTraceID    string
	ReplayID           string
	SegmentID          string
	IgnoreDependencies bool
	ExclusionOps       OperationFilterMap
	InclusionOps       OperationFilterMap
	ExpiresAt          time.Time
}

func (s *ReplaySession) Clone() *ReplaySession {
	if s == nil {
		return nil
	}
	cp := *s
	cp.ExclusionOps = cloneOperationFilterMap(s.ExclusionOps)
	cp.InclusionOps = cloneOperationFilterMap(s.InclusionOps)
	return &cp
}

func (s *ReplaySession) ShouldIgnoreMock(serviceKey, operationKey, hostAndPort string) bool {
	if s == nil || strings.TrimSpace(serviceKey) == "" {
		return false
	}
	if s.IgnoreDependencies {
		return true
	}

	svc := strings.ToLower(strings.TrimSpace(serviceKey))
	if s.InclusionOps != nil {
		ops, found := lookupOperationRules(s.InclusionOps, svc)
		if !found {
			return true
		}
		if len(ops) == 0 || matchesOperationList(ops, operationKey, hostAndPort) {
			return false
		}
		return true
	}

	if s.ExclusionOps == nil {
		return false
	}
	ops, found := lookupOperationRules(s.ExclusionOps, svc)
	if !found {
		return false
	}
	if len(ops) == 0 {
		return true
	}
	return matchesOperationList(ops, operationKey, hostAndPort)
}

func lookupOperationRules(filter OperationFilterMap, svc string) ([]string, bool) {
	if ops, ok := filter[svc]; ok {
		return ops, true
	}
	if ops, ok := filter["*"]; ok {
		return ops, true
	}
	return nil, false
}

func matchesOperationList(ops []string, operationKey, hostAndPort string) bool {
	for _, rule := range ops {
		if rule == "*" || (operationKey != "" && rule == operationKey) || (hostAndPort != "" && rule == hostAndPort) {
			return true
		}
	}
	return false
}

func cloneOperationFilterMap(in OperationFilterMap) OperationFilterMap {
	if in == nil {
		return nil
	}
	out := make(OperationFilterMap, len(in))
	for k, v := range in {
		out[k] = slices.Clone(v)
	}
	return out
}

type ReplayRegistry struct {
	ttl   time.Duration
	cache *expirable.LRU[[16]byte, *ReplaySession]
}

func NewReplayRegistry(maxEntries int, ttl time.Duration) *ReplayRegistry {
	if maxEntries <= 0 {
		maxEntries = DefaultReplayRegistrySize
	}
	if ttl <= 0 {
		ttl = DefaultReplayRegistryTTL
	}
	return &ReplayRegistry{
		ttl:   ttl,
		cache: expirable.NewLRU[[16]byte, *ReplaySession](maxEntries, nil, ttl),
	}
}

func (r *ReplayRegistry) Register(traceID [16]byte, session ReplaySession) *ReplaySession {
	now := time.Now()
	stored := session
	stored.TraceID = traceID
	if stored.Mode == "" {
		stored.Mode = ModeReplay
	}
	if stored.ExpiresAt.IsZero() {
		stored.ExpiresAt = now.Add(r.ttl)
	}
	stored.ExclusionOps = cloneOperationFilterMap(session.ExclusionOps)
	stored.InclusionOps = cloneOperationFilterMap(session.InclusionOps)
	r.cache.Add(traceID, &stored)
	return stored.Clone()
}

func (r *ReplayRegistry) RegisterHex(traceIDHex string, session ReplaySession) (*ReplaySession, error) {
	traceID, err := ParseTraceIDHex(traceIDHex)
	if err != nil {
		return nil, err
	}
	return r.Register(traceID, session), nil
}

func (r *ReplayRegistry) RegisterInbound(meta InboundReplayMetadata) (*ReplaySession, bool) {
	if !meta.HasTraceContext {
		return nil, false
	}
	sess := r.Register(meta.TraceContext.TraceID, ReplaySession{
		TraceID:            meta.TraceContext.TraceID,
		Mode:               meta.Mode,
		RecordedTraceID:    meta.RecordedTraceID,
		ReplayID:           meta.ReplayID,
		SegmentID:          meta.SegmentID,
		IgnoreDependencies: meta.IgnoreDependencies,
		ExclusionOps:       meta.ExclusionOperations,
		InclusionOps:       meta.InclusionOperations,
	})
	return sess, true
}

func (r *ReplayRegistry) Lookup(traceID [16]byte) (*ReplaySession, bool) {
	sess, ok := r.cache.Get(traceID)
	if !ok || sess == nil {
		return nil, false
	}
	if !sess.ExpiresAt.IsZero() && time.Now().After(sess.ExpiresAt) {
		r.cache.Remove(traceID)
		return nil, false
	}
	return sess.Clone(), true
}

func (r *ReplayRegistry) LookupHex(traceIDHex string) (*ReplaySession, bool) {
	traceID, err := ParseTraceIDHex(traceIDHex)
	if err != nil {
		return nil, false
	}
	return r.Lookup(traceID)
}

func (r *ReplayRegistry) Delete(traceID [16]byte) bool {
	return r.cache.Remove(traceID)
}

func (r *ReplayRegistry) Len() int {
	return r.cache.Len()
}

type SocketWriteKey struct {
	SockCookie uint64
	ByteOffset uint64
}

type SocketWriteContext struct {
	SockCookie   uint64
	ByteOffset   uint64
	PayloadLen   uint32
	TraceID      [16]byte
	ServerSpanID [8]byte
	Metadata     map[string]string
	RecordedAt   time.Time
}

type socketOffsetRing struct {
	entries []SocketWriteContext
}

type WriteContextTracker struct {
	mu      sync.RWMutex
	exact   *expirable.LRU[SocketWriteKey, SocketWriteContext]
	sockets *expirable.LRU[uint64, *socketOffsetRing]
}

func NewWriteContextTracker(maxEntries int, ttl time.Duration) *WriteContextTracker {
	if maxEntries <= 0 {
		maxEntries = DefaultWriteTrackerSize
	}
	if ttl <= 0 {
		ttl = DefaultWriteTrackerTTL
	}
	socketMax := max(maxEntries/4, 256)
	return &WriteContextTracker{
		exact:   expirable.NewLRU[SocketWriteKey, SocketWriteContext](maxEntries, nil, ttl),
		sockets: expirable.NewLRU[uint64, *socketOffsetRing](socketMax, nil, ttl),
	}
}

func (t *WriteContextTracker) RecordWrite(w SocketWriteContext) {
	if w.RecordedAt.IsZero() {
		w.RecordedAt = time.Now()
	}
	stored := cloneWriteContext(w)

	t.mu.Lock()
	defer t.mu.Unlock()

	t.exact.Add(SocketWriteKey{
		SockCookie: stored.SockCookie,
		ByteOffset: stored.ByteOffset,
	}, stored)

	ring, ok := t.sockets.Get(stored.SockCookie)
	if !ok || ring == nil {
		ring = &socketOffsetRing{
			entries: make([]SocketWriteContext, 0, 8),
		}
	}
	replaced := false
	for i := range ring.entries {
		if ring.entries[i].ByteOffset == stored.ByteOffset {
			ring.entries[i] = stored
			replaced = true
			break
		}
	}
	if !replaced {
		if len(ring.entries) >= defaultPerSocketRingBound {
			copy(ring.entries, ring.entries[1:])
			ring.entries[len(ring.entries)-1] = stored
		} else {
			ring.entries = append(ring.entries, stored)
		}
		slices.SortFunc(ring.entries, func(a, b SocketWriteContext) int {
			if a.ByteOffset < b.ByteOffset {
				return -1
			}
			if a.ByteOffset > b.ByteOffset {
				return 1
			}
			return 0
		})
	}
	t.sockets.Add(stored.SockCookie, ring)
}

func (t *WriteContextTracker) LookupExact(sockCookie, byteOffset uint64) (SocketWriteContext, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	w, ok := t.exact.Get(SocketWriteKey{SockCookie: sockCookie, ByteOffset: byteOffset})
	if !ok {
		return SocketWriteContext{}, false
	}
	return cloneWriteContext(w), true
}

func (t *WriteContextTracker) LookupAtOffset(sockCookie, byteOffset uint64) (SocketWriteContext, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if w, ok := t.exact.Get(SocketWriteKey{SockCookie: sockCookie, ByteOffset: byteOffset}); ok {
		return cloneWriteContext(w), true
	}

	ring, ok := t.sockets.Get(sockCookie)
	if !ok || ring == nil || len(ring.entries) == 0 {
		return SocketWriteContext{}, false
	}

	bestIdx := -1
	for i, entry := range ring.entries {
		if entry.ByteOffset > byteOffset {
			break
		}
		bestIdx = i
		spanEnd := entry.ByteOffset + uint64(max(entry.PayloadLen, 1))
		if byteOffset < spanEnd {
			return cloneWriteContext(entry), true
		}
	}
	if bestIdx >= 0 {
		return cloneWriteContext(ring.entries[bestIdx]), true
	}
	return SocketWriteContext{}, false
}

func (t *WriteContextTracker) EvictSocket(sockCookie uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if ring, ok := t.sockets.Get(sockCookie); ok && ring != nil {
		for _, entry := range ring.entries {
			t.exact.Remove(SocketWriteKey{
				SockCookie: sockCookie,
				ByteOffset: entry.ByteOffset,
			})
		}
	}
	t.sockets.Remove(sockCookie)
}

func cloneWriteContext(w SocketWriteContext) SocketWriteContext {
	cp := w
	if len(w.Metadata) > 0 {
		cp.Metadata = maps.Clone(w.Metadata)
	}
	return cp
}
