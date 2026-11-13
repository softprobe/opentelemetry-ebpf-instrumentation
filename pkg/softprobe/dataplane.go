// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"context"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	defaultExchangeCacheSize     = 4096
	defaultExchangeCacheTTL      = 30 * time.Second
	maxCapturedExchangesPerRoute = 16
)

type CapturedHTTPClientExchange struct {
	QueryString  string
	ContentType  string
	RequestBody  []byte
	StatusCode   int
	StatusReason string
	RespHeaders  map[string]string
	HeaderTuples []HeaderTuple
	ResponseBody []byte
}

type httpExchangeKey struct {
	TraceID       [16]byte
	Method        string
	OperationName string
}

type capturedExchangeQueue struct {
	items []CapturedHTTPClientExchange
}

type HTTPExchangeCache struct {
	mu      sync.Mutex
	entries *expirable.LRU[httpExchangeKey, *capturedExchangeQueue]
}

func NewHTTPExchangeCache(maxEntries int, ttl time.Duration) *HTTPExchangeCache {
	if maxEntries <= 0 {
		maxEntries = defaultExchangeCacheSize
	}
	if ttl <= 0 {
		ttl = defaultExchangeCacheTTL
	}
	return &HTTPExchangeCache{
		entries: expirable.NewLRU[httpExchangeKey, *capturedExchangeQueue](maxEntries, nil, ttl),
	}
}

func normalizeExchangeKey(traceID [16]byte, method, operationName string) httpExchangeKey {
	op := stripQuery(strings.TrimSpace(operationName))
	if op == "" {
		op = "/"
	}
	return httpExchangeKey{
		TraceID:       traceID,
		Method:        strings.ToUpper(strings.TrimSpace(method)),
		OperationName: op,
	}
}

func cloneCapturedExchange(in CapturedHTTPClientExchange) CapturedHTTPClientExchange {
	out := in
	if len(in.RequestBody) > 0 {
		out.RequestBody = slices.Clone(in.RequestBody)
	}
	if len(in.ResponseBody) > 0 {
		out.ResponseBody = slices.Clone(in.ResponseBody)
	}
	if len(in.RespHeaders) > 0 {
		out.RespHeaders = maps.Clone(in.RespHeaders)
	}
	if len(in.HeaderTuples) > 0 {
		out.HeaderTuples = slices.Clone(in.HeaderTuples)
	}
	return out
}

func (c *HTTPExchangeCache) RecordHTTPClient(traceID [16]byte, method, operationName string, ex CapturedHTTPClientExchange) {
	if c == nil || traceID == ([16]byte{}) {
		return
	}
	key := normalizeExchangeKey(traceID, method, operationName)
	stored := cloneCapturedExchange(ex)

	c.mu.Lock()
	defer c.mu.Unlock()

	q, ok := c.entries.Get(key)
	if !ok || q == nil {
		q = &capturedExchangeQueue{
			items: make([]CapturedHTTPClientExchange, 0, 2),
		}
	}
	if len(q.items) >= maxCapturedExchangesPerRoute {
		copy(q.items, q.items[1:])
		q.items[len(q.items)-1] = stored
	} else {
		q.items = append(q.items, stored)
	}
	c.entries.Add(key, q)
}

func (c *HTTPExchangeCache) ConsumeHTTPClient(traceID [16]byte, method, operationName string) (CapturedHTTPClientExchange, bool) {
	if c == nil || traceID == ([16]byte{}) {
		return CapturedHTTPClientExchange{}, false
	}
	key := normalizeExchangeKey(traceID, method, operationName)

	c.mu.Lock()
	defer c.mu.Unlock()

	q, ok := c.entries.Get(key)
	if !ok || q == nil || len(q.items) == 0 {
		return CapturedHTTPClientExchange{}, false
	}
	first := q.items[0]
	if len(q.items) == 1 {
		c.entries.Remove(key)
	} else {
		q.items = q.items[1:]
		c.entries.Add(key, q)
	}
	return cloneCapturedExchange(first), true
}

type EgressTarget struct {
	SockCookie uint64
	AddrPort   netip.AddrPort
	PID        uint32
}

type RedirectDataplane interface {
	LookupEgressTarget(remoteAddr net.Addr) (EgressTarget, bool)
	RegisterIngressListener(ln net.Listener) error
}

type DataplaneBridge struct {
	mu            sync.RWMutex
	writeTracker  *WriteContextTracker
	exchangeCache *HTTPExchangeCache
	ingressLn     net.Listener
	dataplane     RedirectDataplane
}

var sharedDataplaneBridge = sync.OnceValue(func() *DataplaneBridge {
	return NewDataplaneBridge(NewWriteContextTracker(0, 0))
})

func SharedDataplaneBridge() *DataplaneBridge {
	return sharedDataplaneBridge()
}

func NewDataplaneBridge(tracker *WriteContextTracker) *DataplaneBridge {
	if tracker == nil {
		tracker = NewWriteContextTracker(0, 0)
	}
	return &DataplaneBridge{
		writeTracker:  tracker,
		exchangeCache: NewHTTPExchangeCache(0, 0),
	}
}

func (b *DataplaneBridge) WriteTracker() *WriteContextTracker {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.writeTracker
}

func (b *DataplaneBridge) ExchangeCache() *HTTPExchangeCache {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.exchangeCache
}

func (b *DataplaneBridge) SetIngressListener(ln net.Listener) error {
	b.mu.Lock()
	b.ingressLn = ln
	dp := b.dataplane
	b.mu.Unlock()

	if dp != nil && ln != nil {
		return dp.RegisterIngressListener(ln)
	}
	return nil
}

func (b *DataplaneBridge) AttachDataplane(dp RedirectDataplane) error {
	b.mu.Lock()
	b.dataplane = dp
	ln := b.ingressLn
	b.mu.Unlock()

	if dp != nil && ln != nil {
		return dp.RegisterIngressListener(ln)
	}
	return nil
}

func (b *DataplaneBridge) DetachDataplane(dp RedirectDataplane) {
	b.mu.Lock()
	if b.dataplane == dp {
		b.dataplane = nil
	}
	b.mu.Unlock()
}

func (b *DataplaneBridge) LookupEgressTarget(remoteAddr net.Addr) (EgressTarget, bool) {
	b.mu.RLock()
	dp := b.dataplane
	b.mu.RUnlock()

	if dp == nil {
		return EgressTarget{}, false
	}
	return dp.LookupEgressTarget(remoteAddr)
}

func ListenNonMPTCP(ctx context.Context, network, address string) (net.Listener, error) {
	var lc net.ListenConfig
	lc.SetMultipathTCP(false)
	return lc.Listen(ctx, network, address)
}
