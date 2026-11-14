// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTraceID(seed uint64) [16]byte {
	var id [16]byte
	binary.BigEndian.PutUint64(id[:8], 0x4bf92f3577b34da6)
	binary.BigEndian.PutUint64(id[8:], seed+1)
	return id
}

func makeSpanID(seed uint64) [8]byte {
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], seed+100)
	return id
}

func TestReplayRegistryLifecycleAndEviction(t *testing.T) {
	t.Run("registers inbound headers and enforces LRU capacity", func(t *testing.T) {
		reg := NewReplayRegistry(3, time.Minute)

		h := make(http.Header)
		h.Set(HeaderTraceparent, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
		h.Set(HeaderTracestate, "sp=mode:replay;tid:rec-1;rid:rep-1")
		h.Set(HeaderSegmentID, "seg-1")

		meta, ok := ExtractInboundReplay(h)
		require.True(t, ok)

		sess, registered := reg.RegisterInbound(meta)
		require.True(t, registered)
		assert.Equal(t, "rec-1", sess.RecordedTraceID)
		assert.Equal(t, "rep-1", sess.ReplayID)

		got, found := reg.LookupHex("4bf92f3577b34da6a3ce929d0e0e4736")
		require.True(t, found)
		assert.Equal(t, "seg-1", got.SegmentID)

		for i := uint64(1); i <= 4; i++ {
			reg.Register(makeTraceID(i), ReplaySession{
				RecordedTraceID: fmt.Sprintf("rec-%d", i),
				ReplayID:        fmt.Sprintf("rep-%d", i),
			})
		}
		assert.Equal(t, 3, reg.Len())
		_, stillThere := reg.LookupHex("4bf92f3577b34da6a3ce929d0e0e4736")
		assert.False(t, stillThere)
	})

	t.Run("expires entries after TTL", func(t *testing.T) {
		reg := NewReplayRegistry(16, 25*time.Millisecond)
		tid := makeTraceID(99)
		reg.Register(tid, ReplaySession{
			RecordedTraceID: "rec-ttl",
			ReplayID:        "rep-ttl",
		})

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			_, ok := reg.Lookup(tid)
			assert.False(c, ok)
		}, 500*time.Millisecond, 10*time.Millisecond)
	})
}

func TestReplaySessionShouldIgnoreMockMatchesJavaSemantics(t *testing.T) {
	globalBypass := &ReplaySession{IgnoreDependencies: true}
	assert.True(t, globalBypass.ShouldIgnoreMock(ServiceKeyHTTP, "/ndc/shop", "spair:443"))

	includeMode := &ReplaySession{
		InclusionOps: OperationFilterMap{
			ServiceKeyHTTP:     {"/ndc/shop"},
			ServiceKeyDatabase: {},
		},
	}
	assert.False(t, includeMode.ShouldIgnoreMock(ServiceKeyHTTP, "/ndc/shop", ""))
	assert.True(t, includeMode.ShouldIgnoreMock(ServiceKeyHTTP, "/ndc/book", ""))
	assert.False(t, includeMode.ShouldIgnoreMock(ServiceKeyDatabase, "query", ""))
	assert.True(t, includeMode.ShouldIgnoreMock(ServiceKeyRedis, "GET", ""))

	excludeMode := &ReplaySession{
		ExclusionOps: OperationFilterMap{
			ServiceKeyHTTP:  {"audit.internal:8080"},
			ServiceKeyRedis: {},
		},
	}
	assert.True(t, excludeMode.ShouldIgnoreMock(ServiceKeyHTTP, "/audit", "audit.internal:8080"))
	assert.False(t, excludeMode.ShouldIgnoreMock(ServiceKeyHTTP, "/ndc/shop", "spair:443"))
	assert.True(t, excludeMode.ShouldIgnoreMock(ServiceKeyRedis, "MGET", ""))
	assert.False(t, excludeMode.ShouldIgnoreMock(ServiceKeyDatabase, "query", ""))
}

func TestWriteContextTrackerExactAndOffsetCorrelation(t *testing.T) {
	tracker := NewWriteContextTracker(128, time.Minute)
	const cookie = uint64(0xabc001)

	t1 := makeTraceID(1)
	s1 := makeSpanID(1)
	t2 := makeTraceID(2)
	s2 := makeSpanID(2)

	tracker.RecordWrite(SocketWriteContext{
		SockCookie:   cookie,
		ByteOffset:   0,
		PayloadLen:   250,
		TraceID:      t1,
		ServerSpanID: s1,
	})
	tracker.RecordWrite(SocketWriteContext{
		SockCookie:   cookie,
		ByteOffset:   250,
		PayloadLen:   180,
		TraceID:      t2,
		ServerSpanID: s2,
	})

	exact, ok := tracker.LookupExact(cookie, 250)
	require.True(t, ok)
	assert.Equal(t, t2, exact.TraceID)
	assert.Equal(t, s2, exact.ServerSpanID)

	midFirst, ok := tracker.LookupAtOffset(cookie, 120)
	require.True(t, ok)
	assert.Equal(t, t1, midFirst.TraceID)

	midSecond, ok := tracker.LookupAtOffset(cookie, 300)
	require.True(t, ok)
	assert.Equal(t, t2, midSecond.TraceID)

	tracker.EvictSocket(cookie)
	_, ok = tracker.LookupAtOffset(cookie, 250)
	assert.False(t, ok)
}

func TestReplayRegistryAndWriteTrackerConcurrentAccess(t *testing.T) {
	reg := NewReplayRegistry(1024, time.Minute)
	tracker := NewWriteContextTracker(2048, time.Minute)

	const workers = 50
	const iterations = 80

	var wg sync.WaitGroup
	wg.Add(workers)
	for g := range workers {
		go func(workerID int) {
			defer wg.Done()
			cookie := uint64(1000 + workerID)
			for i := range iterations {
				seed := uint64(workerID*iterations + i)
				tid := makeTraceID(seed)
				sid := makeSpanID(seed)
				offset := uint64(i * 128)

				reg.Register(tid, ReplaySession{
					Mode:            ModeReplay,
					RecordedTraceID: FormatTraceIDHex(tid),
					ReplayID:        fmt.Sprintf("rep-%d-%d", workerID, i),
					ExclusionOps:    OperationFilterMap{ServiceKeyHTTP: {"/healthz"}},
				})

				tracker.RecordWrite(SocketWriteContext{
					SockCookie:   cookie,
					ByteOffset:   offset,
					PayloadLen:   128,
					TraceID:      tid,
					ServerSpanID: sid,
					Metadata:     map[string]string{"worker": strconv.Itoa(workerID)},
				})

				if sess, ok := reg.Lookup(tid); ok {
					_ = sess.ShouldIgnoreMock(ServiceKeyHTTP, "/offers", "")
				}
				if wctx, ok := tracker.LookupAtOffset(cookie, offset+64); ok {
					assert.Equal(t, cookie, wctx.SockCookie)
				}
				if i%25 == 24 {
					reg.Delete(tid)
				}
			}
		}(g)
	}
	wg.Wait()
}
