// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"context"
	"encoding/binary"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	defaultExchangeCacheSize     = 4096
	defaultExchangeCacheTTL      = 30 * time.Second
	maxCapturedExchangesPerRoute = 256
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

type CapturedDatabaseExchange struct {
	ClientPort uint16
	DBName     string
	StmtName   string
	SQL        string
	Parameters []any
	Result     *DatabaseResult
}

type CapturedRedisExchange struct {
	ClientPort  uint16
	Command     string
	ClusterName string
	Keys        []string
	Fields      []string
	Reply       *RedisReply
}

type httpExchangeKey struct {
	TraceID       [16]byte
	Method        string
	OperationName string
}

type capturedExchangeQueue struct {
	items []CapturedHTTPClientExchange
}

type capturedDatabaseItem struct {
	ex       CapturedDatabaseExchange
	consumed bool
}

type capturedDatabaseQueue struct {
	items []*capturedDatabaseItem
}

type capturedRedisItem struct {
	ex       CapturedRedisExchange
	consumed bool
}

type capturedRedisQueue struct {
	items []*capturedRedisItem
}

type HTTPExchangeCache struct {
	mu            sync.Mutex
	inFlightDB    atomic.Int32
	inFlightRedis atomic.Int32
	entries       *expirable.LRU[httpExchangeKey, *capturedExchangeQueue]
	db            *expirable.LRU[[16]byte, *capturedDatabaseQueue]
	dbByPort      *expirable.LRU[uint16, *capturedDatabaseQueue]
	redis         *expirable.LRU[[16]byte, *capturedRedisQueue]
	redisByPort   *expirable.LRU[uint16, *capturedRedisQueue]
}

func NewHTTPExchangeCache(maxEntries int, ttl time.Duration) *HTTPExchangeCache {
	if maxEntries <= 0 {
		maxEntries = defaultExchangeCacheSize
	}
	if ttl <= 0 {
		ttl = defaultExchangeCacheTTL
	}
	return &HTTPExchangeCache{
		entries:     expirable.NewLRU[httpExchangeKey, *capturedExchangeQueue](maxEntries, nil, ttl),
		db:          expirable.NewLRU[[16]byte, *capturedDatabaseQueue](maxEntries, nil, ttl),
		dbByPort:    expirable.NewLRU[uint16, *capturedDatabaseQueue](maxEntries, nil, ttl),
		redis:       expirable.NewLRU[[16]byte, *capturedRedisQueue](maxEntries, nil, ttl),
		redisByPort: expirable.NewLRU[uint16, *capturedRedisQueue](maxEntries, nil, ttl),
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

func cloneDatabaseResult(in *DatabaseResult) *DatabaseResult {
	if in == nil {
		return nil
	}
	cp := *in
	if len(in.Columns) > 0 {
		cp.Columns = slices.Clone(in.Columns)
	}
	if len(in.Rows) > 0 {
		cp.Rows = make([][]any, len(in.Rows))
		for i, row := range in.Rows {
			cp.Rows[i] = slices.Clone(row)
		}
	}
	return &cp
}

func cloneCapturedDatabaseExchange(in CapturedDatabaseExchange) CapturedDatabaseExchange {
	out := in
	if len(in.Parameters) > 0 {
		out.Parameters = slices.Clone(in.Parameters)
	}
	out.Result = cloneDatabaseResult(in.Result)
	return out
}

func cloneRedisReply(in *RedisReply) *RedisReply {
	if in == nil {
		return nil
	}
	cp := cloneRedisReplyValue(*in)
	return &cp
}

func cloneRedisReplyValue(in RedisReply) RedisReply {
	out := in
	if len(in.Bulk) > 0 {
		out.Bulk = slices.Clone(in.Bulk)
	}
	if len(in.Elements) > 0 {
		out.Elements = make([]RedisReply, len(in.Elements))
		for i, elem := range in.Elements {
			out.Elements[i] = cloneRedisReplyValue(elem)
		}
	}
	return out
}

func cloneCapturedRedisExchange(in CapturedRedisExchange) CapturedRedisExchange {
	out := in
	out.Command = strings.ToUpper(strings.TrimSpace(in.Command))
	if len(in.Keys) > 0 {
		out.Keys = slices.Clone(in.Keys)
	}
	if len(in.Fields) > 0 {
		out.Fields = slices.Clone(in.Fields)
	}
	out.Reply = cloneRedisReply(in.Reply)
	return out
}

func remoteTCPPort(conn net.Conn) uint16 {
	if conn == nil {
		return 0
	}
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok && tcpAddr.Port > 0 && tcpAddr.Port <= 65535 {
		return uint16(tcpAddr.Port)
	}
	return 0
}

func appendBoundedDBItem(q *capturedDatabaseQueue, entry *capturedDatabaseItem) *capturedDatabaseQueue {
	if q == nil {
		q = &capturedDatabaseQueue{items: make([]*capturedDatabaseItem, 0, 4)}
	}
	q.items = slices.DeleteFunc(q.items, func(it *capturedDatabaseItem) bool {
		return it == nil || it.consumed
	})
	if len(q.items) >= maxCapturedExchangesPerRoute {
		copy(q.items, q.items[1:])
		q.items[len(q.items)-1] = entry
	} else {
		q.items = append(q.items, entry)
	}
	return q
}

func appendBoundedRedisItem(q *capturedRedisQueue, entry *capturedRedisItem) *capturedRedisQueue {
	if q == nil {
		q = &capturedRedisQueue{items: make([]*capturedRedisItem, 0, 4)}
	}
	q.items = slices.DeleteFunc(q.items, func(it *capturedRedisItem) bool {
		return it == nil || it.consumed
	})
	if len(q.items) >= maxCapturedExchangesPerRoute {
		copy(q.items, q.items[1:])
		q.items[len(q.items)-1] = entry
	} else {
		q.items = append(q.items, entry)
	}
	return q
}

func (c *HTTPExchangeCache) RecordDatabase(traceID [16]byte, ex CapturedDatabaseExchange) {
	if c == nil || (traceID == ([16]byte{}) && ex.ClientPort == 0) || strings.TrimSpace(ex.SQL) == "" {
		return
	}
	entry := &capturedDatabaseItem{ex: cloneCapturedDatabaseExchange(ex)}

	c.mu.Lock()
	defer c.mu.Unlock()

	if traceID != ([16]byte{}) {
		q, _ := c.db.Get(traceID)
		c.db.Add(traceID, appendBoundedDBItem(q, entry))
	}
	if ex.ClientPort != 0 {
		pq, _ := c.dbByPort.Get(ex.ClientPort)
		c.dbByPort.Add(ex.ClientPort, appendBoundedDBItem(pq, entry))
	}
}

func (c *HTTPExchangeCache) BeginInFlightDB() {
	if c != nil {
		c.inFlightDB.Add(1)
	}
}

func (c *HTTPExchangeCache) EndInFlightDB() {
	if c != nil {
		c.inFlightDB.Add(-1)
	}
}

func (c *HTTPExchangeCache) BeginInFlightRedis() {
	if c != nil {
		c.inFlightRedis.Add(1)
	}
}

func (c *HTTPExchangeCache) EndInFlightRedis() {
	if c != nil {
		c.inFlightRedis.Add(-1)
	}
}

func (c *HTTPExchangeCache) ConsumeDatabase(traceID [16]byte, sqlHint, methodHint, pathHint string) (CapturedDatabaseExchange, bool) {
	return c.ConsumeDatabaseForConn(traceID, 0, sqlHint, methodHint, pathHint)
}

func (c *HTTPExchangeCache) ConsumeDatabaseForConn(traceID [16]byte, clientPort uint16, sqlHint, methodHint, pathHint string) (CapturedDatabaseExchange, bool) {
	if c == nil || (traceID == ([16]byte{}) && clientPort == 0) {
		return CapturedDatabaseExchange{}, false
	}
	if ex, ok := c.tryConsumeDatabase(traceID, clientPort, sqlHint, methodHint, pathHint); ok {
		return ex, true
	}
	if c.inFlightDB.Load() > 0 {
		deadline := time.Now().Add(100 * time.Millisecond)
		for time.Now().Before(deadline) && c.inFlightDB.Load() > 0 {
			time.Sleep(500 * time.Microsecond)
			if ex, ok := c.tryConsumeDatabase(traceID, clientPort, sqlHint, methodHint, pathHint); ok {
				return ex, true
			}
		}
		return c.tryConsumeDatabase(traceID, clientPort, sqlHint, methodHint, pathHint)
	}
	return CapturedDatabaseExchange{}, false
}

func matchDatabaseItemIndex(items []*capturedDatabaseItem, normHint string, isPrepFallback bool, pathHint string) int {
	if normHint != "" && !isPrepFallback {
		for i, item := range items {
			if NormalizeSQL(item.ex.SQL) == normHint {
				return i
			}
		}
		for i, item := range items {
			if strings.HasPrefix(NormalizeSQL(item.ex.SQL), normHint) {
				return i
			}
		}
	}
	if isPrepFallback {
		stmtName, _, _ := strings.Cut(pathHint, ".")
		if stmtName != "" {
			for i, item := range items {
				if item.ex.StmtName == stmtName {
					return i
				}
			}
		}
		for i, item := range items {
			if !isSessionControlSQL(item.ex.SQL) {
				return i
			}
		}
	}
	if normHint == "" {
		for i, item := range items {
			if !isSessionControlSQL(item.ex.SQL) {
				return i
			}
		}
	}
	return -1
}

func (c *HTTPExchangeCache) tryConsumeDatabase(traceID [16]byte, clientPort uint16, sqlHint, methodHint, pathHint string) (CapturedDatabaseExchange, bool) {
	normHint := NormalizeSQL(sqlHint)
	isPrepFallback := strings.EqualFold(strings.TrimSpace(methodHint), "PREPARED STATEMENT")

	c.mu.Lock()
	defer c.mu.Unlock()

	if traceID != ([16]byte{}) {
		if q, ok := c.db.Get(traceID); ok && q != nil {
			q.items = slices.DeleteFunc(q.items, func(it *capturedDatabaseItem) bool {
				return it == nil || it.consumed
			})
			if len(q.items) == 0 {
				c.db.Remove(traceID)
			} else if matchIdx := matchDatabaseItemIndex(q.items, normHint, isPrepFallback, pathHint); matchIdx >= 0 {
				matched := q.items[matchIdx]
				matched.consumed = true
				q.items = slices.Delete(q.items, matchIdx, matchIdx+1)
				if len(q.items) == 0 {
					c.db.Remove(traceID)
				} else {
					c.db.Add(traceID, q)
				}
				return cloneCapturedDatabaseExchange(matched.ex), true
			}
		}
	}

	if clientPort != 0 {
		if pq, ok := c.dbByPort.Get(clientPort); ok && pq != nil {
			pq.items = slices.DeleteFunc(pq.items, func(it *capturedDatabaseItem) bool {
				return it == nil || it.consumed
			})
			if len(pq.items) == 0 {
				c.dbByPort.Remove(clientPort)
			} else if idx := matchDatabaseItemIndex(pq.items, normHint, isPrepFallback, pathHint); idx >= 0 {
				matched := pq.items[idx]
				matched.consumed = true
				pq.items = slices.Delete(pq.items, idx, idx+1)
				if len(pq.items) == 0 {
					c.dbByPort.Remove(clientPort)
				} else {
					c.dbByPort.Add(clientPort, pq)
				}
				return cloneCapturedDatabaseExchange(matched.ex), true
			}
		}
	}

	return CapturedDatabaseExchange{}, false
}

func (c *HTTPExchangeCache) RecordRedis(traceID [16]byte, ex CapturedRedisExchange) {
	if c == nil || (traceID == ([16]byte{}) && ex.ClientPort == 0) || strings.TrimSpace(ex.Command) == "" {
		return
	}
	entry := &capturedRedisItem{ex: cloneCapturedRedisExchange(ex)}

	c.mu.Lock()
	defer c.mu.Unlock()

	if traceID != ([16]byte{}) {
		q, _ := c.redis.Get(traceID)
		c.redis.Add(traceID, appendBoundedRedisItem(q, entry))
	}
	if ex.ClientPort != 0 {
		pq, _ := c.redisByPort.Get(ex.ClientPort)
		c.redisByPort.Add(ex.ClientPort, appendBoundedRedisItem(pq, entry))
	}
}

func (c *HTTPExchangeCache) ConsumeRedis(traceID [16]byte, cmdHint string, keysHint []string) (CapturedRedisExchange, bool) {
	return c.ConsumeRedisForConn(traceID, 0, cmdHint, keysHint)
}

func (c *HTTPExchangeCache) ConsumeRedisForConn(traceID [16]byte, clientPort uint16, cmdHint string, keysHint []string) (CapturedRedisExchange, bool) {
	if c == nil || (traceID == ([16]byte{}) && clientPort == 0) {
		return CapturedRedisExchange{}, false
	}
	upperCmd := strings.ToUpper(strings.TrimSpace(cmdHint))
	if upperCmd == "" {
		return CapturedRedisExchange{}, false
	}
	if ex, ok := c.tryConsumeRedis(traceID, clientPort, upperCmd, keysHint); ok {
		return ex, true
	}
	if c.inFlightRedis.Load() > 0 {
		deadline := time.Now().Add(100 * time.Millisecond)
		for time.Now().Before(deadline) && c.inFlightRedis.Load() > 0 {
			time.Sleep(500 * time.Microsecond)
			if ex, ok := c.tryConsumeRedis(traceID, clientPort, upperCmd, keysHint); ok {
				return ex, true
			}
		}
		return c.tryConsumeRedis(traceID, clientPort, upperCmd, keysHint)
	}
	return CapturedRedisExchange{}, false
}

func matchRedisItemIndex(items []*capturedRedisItem, upperCmd string, keysHint []string) int {
	for i, item := range items {
		if item.ex.Command == upperCmd && slices.Equal(item.ex.Keys, keysHint) {
			return i
		}
	}
	if len(keysHint) == 0 {
		for i, item := range items {
			if item.ex.Command == upperCmd {
				return i
			}
		}
	}
	return -1
}

func (c *HTTPExchangeCache) tryConsumeRedis(traceID [16]byte, clientPort uint16, upperCmd string, keysHint []string) (CapturedRedisExchange, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if traceID != ([16]byte{}) {
		if q, ok := c.redis.Get(traceID); ok && q != nil {
			q.items = slices.DeleteFunc(q.items, func(it *capturedRedisItem) bool {
				return it == nil || it.consumed
			})
			if len(q.items) == 0 {
				c.redis.Remove(traceID)
			} else if matchIdx := matchRedisItemIndex(q.items, upperCmd, keysHint); matchIdx >= 0 {
				matched := q.items[matchIdx]
				matched.consumed = true
				q.items = slices.Delete(q.items, matchIdx, matchIdx+1)
				if len(q.items) == 0 {
					c.redis.Remove(traceID)
				} else {
					c.redis.Add(traceID, q)
				}
				return cloneCapturedRedisExchange(matched.ex), true
			}
		}
	}

	if clientPort != 0 {
		if pq, ok := c.redisByPort.Get(clientPort); ok && pq != nil {
			pq.items = slices.DeleteFunc(pq.items, func(it *capturedRedisItem) bool {
				return it == nil || it.consumed
			})
			if len(pq.items) == 0 {
				c.redisByPort.Remove(clientPort)
			} else if idx := matchRedisItemIndex(pq.items, upperCmd, keysHint); idx >= 0 {
				matched := pq.items[idx]
				matched.consumed = true
				pq.items = slices.Delete(pq.items, idx, idx+1)
				if len(pq.items) == 0 {
					c.redisByPort.Remove(clientPort)
				} else {
					c.redisByPort.Add(clientPort, pq)
				}
				return cloneCapturedRedisExchange(matched.ex), true
			}
		}
	}

	return CapturedRedisExchange{}, false
}

func stripSQLComments(sql string) string {
	var b strings.Builder
	b.Grow(len(sql))
	var quote byte
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if quote != 0 {
			b.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			b.WriteByte(c)
			continue
		}
		if c == '-' && i+1 < len(sql) && sql[i+1] == '-' {
			i += 2
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			b.WriteByte(' ')
			continue
		}
		if c == '/' && i+1 < len(sql) && sql[i+1] == '*' {
			i += 2
			for i+1 < len(sql) && (sql[i] != '*' || sql[i+1] != '/') {
				i++
			}
			i++
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func isSessionControlSQL(sql string) bool {
	cleaned := stripSQLComments(sql)
	parts := strings.Split(cleaned, ";")
	hasStmt := false
	for _, rawPart := range parts {
		trimmed := strings.TrimSpace(rawPart)
		if trimmed == "" {
			continue
		}
		hasStmt = true
		if !isSingleSessionControlSQL(trimmed) {
			return false
		}
	}
	return hasStmt || strings.TrimSpace(cleaned) == ""
}

func isSingleSessionControlSQL(trimmed string) bool {
	upper := strings.ToUpper(NormalizeSQL(trimmed))
	switch upper {
	case "BEGIN", "COMMIT", "ROLLBACK", "END", "START TRANSACTION", "DISCARD ALL", "RESET ALL", "CLOSE ALL", "UNLISTEN *", "SELECT PG_ADVISORY_UNLOCK_ALL()":
		return true
	}
	for _, prefix := range []string{
		"BEGIN ",
		"START TRANSACTION ",
		"COMMIT ",
		"ROLLBACK ",
		"SAVEPOINT ",
		"RELEASE SAVEPOINT ",
		"SET ",
		"RESET ",
		"DISCARD ",
		"DEALLOCATE ",
		"UNLISTEN ",
		"LISTEN ",
		"CLOSE ",
		"SHOW ",
		"USE ",
		"SELECT @@",
		"SELECT VERSION()",
		"SELECT PG_CATALOG.",
		"SELECT PG_ADVISORY_UNLOCK_ALL(",
		"SELECT DATABASE()",
		"SELECT CURRENT_SCHEMA",
		"WITH RECURSIVE TYPEINFO_TREE",
	} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	if strings.HasPrefix(upper, "SELECT ") &&
		(strings.Contains(upper, "PG_CATALOG.") || strings.Contains(upper, "INFORMATION_SCHEMA.")) {
		return true
	}
	return false
}

func isNonExecutionSQLWireRequest(wireReq []byte) bool {
	if len(wireReq) < 5 {
		return false
	}

	pgPos := 0
	pgFrames := 0
	pgHasExec := false
	pgValid := true
	for pgPos+5 <= len(wireReq) {
		msgType := wireReq[pgPos]
		switch msgType {
		case 'P', 'B', 'D', 'E', 'H', 'S', 'C', 'X', 'Q':
		default:
			pgValid = false
		}
		if !pgValid {
			break
		}
		msgLen := int(binary.BigEndian.Uint32(wireReq[pgPos+1 : pgPos+5]))
		if msgLen < 4 || pgPos+1+msgLen > len(wireReq) {
			pgValid = false
			break
		}
		if msgType == 'Q' || msgType == 'E' || msgType == 'B' {
			pgHasExec = true
		}
		pgFrames++
		pgPos += 1 + msgLen
	}
	if pgValid && pgFrames > 0 && pgPos == len(wireReq) {
		return !pgHasExec
	}

	myPos := 0
	myNonExecCmds := 0
	myHasExec := false
	myValid := true
	for myPos+4 < len(wireReq) {
		pktLen := int(wireReq[myPos]) | int(wireReq[myPos+1])<<8 | int(wireReq[myPos+2])<<16
		seq := wireReq[myPos+3]
		if pktLen <= 0 || myPos+4+pktLen > len(wireReq) {
			if myPos == 0 && seq == 0 {
				switch wireReq[4] {
				case 0x01, 0x02, 0x0e, 0x16, 0x19, 0x1a, 0x1f:
					return true
				}
			}
			myValid = false
			break
		}
		if seq == 0 {
			switch wireReq[myPos+4] {
			case 0x01, 0x02, 0x0e, 0x16, 0x19, 0x1a, 0x1f:
				myNonExecCmds++
			default:
				myHasExec = true
			}
		}
		myPos += 4 + pktLen
	}
	return myValid && myPos == len(wireReq) && myNonExecCmds > 0 && !myHasExec
}

func isMySQLPrepareOKWireResponse(wireResp []byte) bool {
	if len(wireResp) < 16 {
		return false
	}
	pktLen := int(wireResp[0]) | int(wireResp[1])<<8 | int(wireResp[2])<<16
	if pktLen != 12 || wireResp[3] != 1 || wireResp[4] != 0x00 || wireResp[13] != 0x00 {
		return false
	}
	numCols := binary.LittleEndian.Uint16(wireResp[9:11])
	numParams := binary.LittleEndian.Uint16(wireResp[11:13])
	if numCols == 0 && numParams == 0 {
		return len(wireResp) == 16
	}
	return len(wireResp) >= 24 && wireResp[19] == 2 && wireResp[20] == 3 &&
		wireResp[21] == 'd' && wireResp[22] == 'e' && wireResp[23] == 'f'
}

func lookupWriteInFrameRange(tracker *WriteContextTracker, sockCookie, rawStart, rawEnd uint64) (SocketWriteContext, bool) {
	if tracker == nil || sockCookie == 0 {
		return SocketWriteContext{}, false
	}
	pollEnd := max(rawEnd, rawStart+1)
	wctx, ok := tracker.LookupInRange(sockCookie, rawStart, pollEnd)
	if !ok {
		return SocketWriteContext{}, false
	}
	if rawStart > 0 && wctx.PayloadLen > 0 {
		if wctx.ByteOffset+uint64(wctx.PayloadLen) <= rawStart {
			return SocketWriteContext{}, false
		}
	}
	return wctx, true
}

func isRedisSessionCommand(cmd string) bool {
	switch strings.ToUpper(strings.TrimSpace(cmd)) {
	case "", "HELLO", "AUTH", "SELECT", "CLIENT", "QUIT", "RESET", "READONLY", "READWRITE", "COMMAND", "INFO", "CONFIG", "CLUSTER":
		return true
	default:
		return false
	}
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
