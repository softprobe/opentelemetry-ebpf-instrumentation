// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	pgSSLRequestCode    uint32 = 80877103
	pgGSSENCRequestCode uint32 = 80877104
	pgProtocolVersion30 uint32 = 0x00030000

	defaultSQLMetadataCacheSize = 2048
	defaultSQLMetadataCacheTTL  = 30 * time.Minute
	maxPGFrameBytes             = 64 << 20
)

type PostgresHandlerOption func(*PostgresProtocolHandler)

func WithPostgresDialer(dialFn func(ctx context.Context, network, address string) (net.Conn, error)) PostgresHandlerOption {
	return func(h *PostgresProtocolHandler) {
		if dialFn != nil {
			h.dialContext = dialFn
		}
	}
}

func WithPostgresExchangeCache(cache *HTTPExchangeCache) PostgresHandlerOption {
	return func(h *PostgresProtocolHandler) {
		if cache != nil {
			h.exchangeCache = cache
		}
	}
}

func WithPostgresLogExporter(exp *LogExporter) PostgresHandlerOption {
	return func(h *PostgresProtocolHandler) {
		if exp != nil {
			h.logExporter = exp
		}
	}
}

type pgSQLMetadata struct {
	paramOIDs []uint32
	columns   []DatabaseColumn
}

type pgPreparedStmt struct {
	name      string
	sql       string
	paramOIDs []uint32
	columns   []DatabaseColumn
}

type pgPortal struct {
	name          string
	stmtName      string
	params        []any
	rawBind       []byte
	resultFormats []int16
}

type pgConnState struct {
	dbName        string
	upConn        net.Conn
	preparedStmts map[string]*pgPreparedStmt
	portals       map[string]*pgPortal
}

type pgFrontendMsg struct {
	msgType byte
	payload []byte
	raw     []byte
}

type PostgresProtocolHandler struct {
	cfg            Config
	replayRegistry *ReplayRegistry
	writeTracker   *WriteContextTracker
	exchangeCache  *HTTPExchangeCache
	logExporter    *LogExporter
	backendClient  *BackendClient
	dialContext    func(ctx context.Context, network, address string) (net.Conn, error)
	stats          *EgressStats
	metadataCache  *expirable.LRU[string, pgSQLMetadata]
	log            *slog.Logger
}

func NewPostgresProtocolHandler(
	cfg Config,
	replayRegistry *ReplayRegistry,
	writeTracker *WriteContextTracker,
	backendClient *BackendClient,
	opts ...PostgresHandlerOption,
) *PostgresProtocolHandler {
	cfg = cfg.WithDefaults()
	if replayRegistry == nil {
		replayRegistry = SharedReplayRegistry()
	}
	if writeTracker == nil {
		writeTracker = SharedDataplaneBridge().WriteTracker()
	}
	var dialer net.Dialer
	dialer.Timeout = defaultUpstreamDialTTL
	dialer.SetMultipathTCP(false)

	h := &PostgresProtocolHandler{
		cfg:            cfg,
		replayRegistry: replayRegistry,
		writeTracker:   writeTracker,
		exchangeCache:  SharedDataplaneBridge().ExchangeCache(),
		backendClient:  backendClient,
		dialContext:    dialer.DialContext,
		stats:          &EgressStats{},
		metadataCache:  expirable.NewLRU[string, pgSQLMetadata](defaultSQLMetadataCacheSize, nil, defaultSQLMetadataCacheTTL),
		log:            slog.With("component", "softprobe.PostgresProtocolHandler"),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(h)
		}
	}
	return h
}

func (h *PostgresProtocolHandler) Name() string {
	return "postgres"
}

func (h *PostgresProtocolHandler) Stats() *EgressStats {
	return h.stats
}

func (h *PostgresProtocolHandler) CanHandle(preamble []byte, origPort uint16) bool {
	if isPostgresStartupPreamble(preamble) {
		return true
	}
	if origPort != 5432 || len(preamble) < 5 {
		return false
	}
	switch preamble[0] {
	case 'Q', 'P', 'B', 'D', 'E', 'S', 'H', 'C', 'X':
		msgLen := binary.BigEndian.Uint32(preamble[1:5])
		return msgLen >= 4 && msgLen <= uint32(maxPGFrameBytes)
	default:
		return false
	}
}

func isPostgresStartupPreamble(preamble []byte) bool {
	if len(preamble) < 8 {
		return false
	}
	msgLen := binary.BigEndian.Uint32(preamble[0:4])
	code := binary.BigEndian.Uint32(preamble[4:8])
	if msgLen == 8 && (code == pgSSLRequestCode || code == pgGSSENCRequestCode) {
		return true
	}
	if msgLen >= 8 && msgLen <= 10000 {
		major := code >> 16
		minor := code & 0xffff
		if major == 3 && minor <= 2 {
			return true
		}
	}
	return false
}

func (h *PostgresProtocolHandler) HandleConnection(ctx context.Context, oc OutgoingConnectionContext) error {
	state := &pgConnState{
		dbName:        "postgres",
		preparedStmts: make(map[string]*pgPreparedStmt),
		portals:       make(map[string]*pgPortal),
	}
	defer func() {
		if state.upConn != nil {
			_ = state.upConn.Close()
		}
	}()

	if err := h.handleStartup(ctx, oc, state); err != nil {
		return err
	}
	return h.serveCommandLoop(ctx, oc, state)
}

func (h *PostgresProtocolHandler) handleStartup(ctx context.Context, oc OutgoingConnectionContext, state *pgConnState) error {
	for range 2 {
		peek, err := oc.BufReader.Peek(8)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		msgLen := binary.BigEndian.Uint32(peek[0:4])
		code := binary.BigEndian.Uint32(peek[4:8])
		if msgLen != 8 || (code != pgSSLRequestCode && code != pgGSSENCRequestCode) {
			break
		}
		var discard [8]byte
		if _, err := io.ReadFull(oc.BufReader, discard[:]); err != nil {
			return err
		}
		// Reply 'N' so PostgreSQL clients keep the redirected local socket in plaintext v3 framing.
		if _, err := oc.ClientConn.Write([]byte{'N'}); err != nil {
			return err
		}
	}

	peek, err := oc.BufReader.Peek(8)
	if err != nil {
		if len(peek) == 0 && (errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)) {
			return nil
		}
		if len(peek) < 5 {
			return err
		}
	}
	if !isPostgresStartupPreamble(peek) {
		return nil
	}

	rawStart := rawConsumedBytes(oc.ClientConn, oc.BufReader)
	msgLen := int(binary.BigEndian.Uint32(peek[0:4]))
	if msgLen < 8 || msgLen > 10000 {
		return fmt.Errorf("invalid postgres startup length %d", msgLen)
	}
	startupRaw := make([]byte, msgLen)
	if _, err := io.ReadFull(oc.BufReader, startupRaw); err != nil {
		return err
	}
	rawEnd := rawConsumedBytes(oc.ClientConn, oc.BufReader)

	if db := extractPostgresStartupDB(startupRaw[8:]); db != "" {
		state.dbName = db
	}

	_, _, sess, isReplay := h.resolveSocketSession(ctx, oc.SockCookie, min(rawStart, 0), rawEnd)
	if isReplay || sess != nil {
		_, err := oc.ClientConn.Write(buildSyntheticPostgresStartupOK())
		return err
	}

	upConn, dialErr := h.dialUpstream(ctx, oc.OrigDst)
	if dialErr != nil {
		_, err := oc.ClientConn.Write(buildSyntheticPostgresStartupOK())
		return err
	}
	state.upConn = upConn

	if _, err := upConn.Write(startupRaw); err != nil {
		_ = upConn.Close()
		state.upConn = nil
		_, wErr := oc.ClientConn.Write(buildSyntheticPostgresStartupOK())
		return wErr
	}

	for {
		bType, bPayload, bRaw, err := readPostgresFrame(upConn)
		if err != nil {
			return err
		}
		if _, err := oc.ClientConn.Write(bRaw); err != nil {
			return err
		}
		switch bType {
		case 'Z':
			return nil
		case 'E':
			return errors.New("postgres upstream startup error")
		case 'R':
			if len(bPayload) >= 4 {
				authType := binary.BigEndian.Uint32(bPayload[0:4])
				switch authType {
				case 3, 5, 10, 11:
					_, _, cRaw, cErr := readPostgresFrame(oc.BufReader)
					if cErr != nil {
						return cErr
					}
					if _, wErr := upConn.Write(cRaw); wErr != nil {
						return wErr
					}
				}
			}
		}
	}
}

func extractPostgresStartupDB(params []byte) string {
	var dbName, userName string
	p := 0
	for p < len(params) && params[p] != 0 {
		key, nextP, ok := readCString(params, p)
		if !ok {
			break
		}
		val, nextP2, ok := readCString(params, nextP)
		if !ok {
			break
		}
		p = nextP2
		switch key {
		case "database":
			dbName = val
		case "user":
			userName = val
		}
	}
	if dbName != "" {
		return dbName
	}
	return userName
}

func buildSyntheticPostgresStartupOK() []byte {
	var buf bytes.Buffer
	var authPayload [4]byte
	writePGMsg(&buf, 'R', authPayload[:])

	for _, kv := range [][2]string{
		{"server_version", "16.0"},
		{"server_encoding", "UTF8"},
		{"client_encoding", "UTF8"},
		{"DateStyle", "ISO, MDY"},
		{"TimeZone", "UTC"},
		{"IntervalStyle", "postgres"},
		{"integer_datetimes", "on"},
		{"standard_conforming_strings", "on"},
		{"is_superuser", "on"},
		{"session_authorization", "postgres"},
		{"application_name", ""},
	} {
		var p bytes.Buffer
		p.WriteString(kv[0])
		p.WriteByte(0)
		p.WriteString(kv[1])
		p.WriteByte(0)
		writePGMsg(&buf, 'S', p.Bytes())
	}

	var keyData [8]byte
	binary.BigEndian.PutUint32(keyData[0:4], 1)
	binary.BigEndian.PutUint32(keyData[4:8], 1)
	writePGMsg(&buf, 'K', keyData[:])
	writePGMsg(&buf, 'Z', []byte{'I'})
	return buf.Bytes()
}

func (h *PostgresProtocolHandler) serveCommandLoop(ctx context.Context, oc OutgoingConnectionContext, state *pgConnState) error {
	prevOffset := rawConsumedBytes(oc.ClientConn, oc.BufReader)
	for {
		rawStart := prevOffset
		if oc.BufReader.Buffered() == 0 {
			rawStart = max(prevOffset, rawConsumedBytes(oc.ClientConn, oc.BufReader))
		}
		msgType, payload, rawMsg, err := readPostgresFrame(oc.BufReader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		if msgType == 'X' {
			return nil
		}

		if msgType == 'Q' {
			rawEnd := rawConsumedBytes(oc.ClientConn, oc.BufReader)
			prevOffset = rawEnd
			if err := h.handleSimpleQuery(ctx, oc, state, payload, rawMsg, rawStart, rawEnd); err != nil {
				return err
			}
			continue
		}

		batch := []pgFrontendMsg{{msgType: msgType, payload: payload, raw: rawMsg}}
		for msgType != 'S' && msgType != 'H' {
			nextType, nextPayload, nextRaw, nextErr := readPostgresFrame(oc.BufReader)
			if nextErr != nil {
				return nextErr
			}
			if nextType == 'X' {
				return nil
			}
			batch = append(batch, pgFrontendMsg{msgType: nextType, payload: nextPayload, raw: nextRaw})
			msgType = nextType
		}
		rawEnd := rawConsumedBytes(oc.ClientConn, oc.BufReader)
		prevOffset = rawEnd

		if err := h.handleExtendedBatch(ctx, oc, state, batch, rawStart, rawEnd); err != nil {
			return err
		}
	}
}

func (h *PostgresProtocolHandler) handleSimpleQuery(
	ctx context.Context,
	oc OutgoingConnectionContext,
	state *pgConnState,
	payload []byte,
	rawMsg []byte,
	rawStart uint64,
	rawEnd uint64,
) error {
	sqlText, _, ok := readCString(payload, 0)
	if !ok {
		sqlText = string(bytes.TrimRight(payload, "\x00"))
	}

	traceID, serverSpanID, sess, isReplay := h.resolveSocketSession(ctx, oc.SockCookie, rawStart, rawEnd)
	if !isReplay || sess == nil {
		h.exchangeCache.BeginInFlightDB()
		wireResp, res, err := h.forwardSimpleQueryLive(ctx, oc.OrigDst, state, rawMsg)
		if err != nil {
			h.exchangeCache.EndInFlightDB()
			_, _ = oc.ClientConn.Write(append(
				encodePGErrorResponse("ERROR", "08006", err.Error()),
				encodePGReadyForQuery()...,
			))
			return err
		}
		if res != nil && len(res.Columns) > 0 {
			h.rememberSQLMetadata(sqlText, nil, res.Columns)
		}
		if traceID == ([16]byte{}) {
			traceID = h.resolvePostForwardTrace(ctx, oc.SockCookie, rawStart, rawEnd)
		}
		clientPort := remoteTCPPort(oc.ClientConn)
		if (traceID != ([16]byte{}) || clientPort != 0) && h.exchangeCache != nil && !isSessionControlSQL(sqlText) {
			h.exchangeCache.RecordDatabase(traceID, CapturedDatabaseExchange{
				ClientPort: clientPort,
				DBName:     state.dbName,
				SQL:        sqlText,
				Result:     res,
			})
		}
		h.exchangeCache.EndInFlightDB()
		_, err = oc.ClientConn.Write(wireResp)
		return err
	}

	if strings.TrimSpace(strings.TrimRight(strings.TrimSpace(sqlText), ";")) == "" {
		var out bytes.Buffer
		writePGMsg(&out, 'I', nil)
		out.Write(encodePGReadyForQuery())
		_, err := oc.ClientConn.Write(out.Bytes())
		return err
	}

	if isSessionControlSQL(sqlText) {
		_, err := oc.ClientConn.Write(encodeSyntheticPostgresSessionReply(sqlText, true))
		return err
	}

	qOutcome, res, skipLive, errMsg := h.queryDatabaseMock(ctx, oc, sess, serverSpanID, state.dbName, sqlText, nil)
	if skipLive {
		wireResp, _, err := h.forwardSimpleQueryLive(ctx, oc.OrigDst, state, rawMsg)
		if err != nil {
			_, _ = oc.ClientConn.Write(append(
				encodePGErrorResponse("ERROR", "08006", err.Error()),
				encodePGReadyForQuery()...,
			))
			return err
		}
		_, err = oc.ClientConn.Write(wireResp)
		return err
	}
	if qOutcome == QueryOutcomeMustMock {
		_, err := oc.ClientConn.Write(append(
			encodePGErrorResponse("ERROR", "XX000", "softprobe mustMock miss"),
			encodePGReadyForQuery()...,
		))
		return err
	}
	if errMsg != "" || res == nil {
		if errMsg == "" {
			errMsg = "softprobe replay mock miss"
		}
		_, err := oc.ClientConn.Write(append(
			encodePGErrorResponse("ERROR", "XX000", errMsg),
			encodePGReadyForQuery()...,
		))
		return err
	}

	_, err := oc.ClientConn.Write(encodePostgresResultWire(sqlText, res, nil, true))
	return err
}

func (h *PostgresProtocolHandler) forwardSimpleQueryLive(
	ctx context.Context,
	origDst netip.AddrPort,
	state *pgConnState,
	rawMsg []byte,
) ([]byte, *DatabaseResult, error) {
	upConn, err := h.ensureUpstream(ctx, origDst, state)
	if err != nil {
		return nil, nil, err
	}
	h.stats.LiveForwards.Add(1)
	if _, err := upConn.Write(rawMsg); err != nil {
		_ = upConn.Close()
		state.upConn = nil
		return nil, nil, err
	}
	var wire bytes.Buffer
	for {
		bType, _, bRaw, rErr := readPostgresFrame(upConn)
		if rErr != nil {
			_ = upConn.Close()
			state.upConn = nil
			return nil, nil, rErr
		}
		wire.Write(bRaw)
		if bType == 'Z' {
			break
		}
	}
	return wire.Bytes(), ParsePostgresWireResponse(wire.Bytes()), nil
}

func (h *PostgresProtocolHandler) handleExtendedBatch(
	ctx context.Context,
	oc OutgoingConnectionContext,
	state *pgConnState,
	batch []pgFrontendMsg,
	rawStart uint64,
	rawEnd uint64,
) error {
	traceID, serverSpanID, sess, isReplay := h.resolveSocketSession(ctx, oc.SockCookie, rawStart, rawEnd)
	if !isReplay || sess == nil {
		return h.forwardExtendedBatchLive(ctx, oc, state, batch, traceID, rawStart, rawEnd)
	}
	return h.replayExtendedBatch(ctx, oc, state, batch, sess, serverSpanID)
}

func (h *PostgresProtocolHandler) forwardExtendedBatchLive(
	ctx context.Context,
	oc OutgoingConnectionContext,
	state *pgConnState,
	batch []pgFrontendMsg,
	traceID [16]byte,
	rawStart uint64,
	rawEnd uint64,
) error {
	h.exchangeCache.BeginInFlightDB()
	inFlight := true
	defer func() {
		if inFlight {
			h.exchangeCache.EndInFlightDB()
		}
	}()

	upConn, err := h.ensureUpstream(ctx, oc.OrigDst, state)
	if err != nil {
		_, _ = oc.ClientConn.Write(append(
			encodePGErrorResponse("ERROR", "08006", err.Error()),
			encodePGReadyForQuery()...,
		))
		return err
	}

	var rawBatch bytes.Buffer
	hasSync := false
	for _, m := range batch {
		rawBatch.Write(m.raw)
		if m.msgType == 'S' {
			hasSync = true
		}
		h.applyFrontendStateUpdate(state, m)
	}

	h.stats.LiveForwards.Add(1)
	if _, err := upConn.Write(rawBatch.Bytes()); err != nil {
		_ = upConn.Close()
		state.upConn = nil
		return err
	}

	var backendFrames []pgFrontendMsg
	var wireResp bytes.Buffer
	if hasSync {
		for {
			bType, bPayload, bRaw, rErr := readPostgresFrame(upConn)
			if rErr != nil {
				_ = upConn.Close()
				state.upConn = nil
				return rErr
			}
			backendFrames = append(backendFrames, pgFrontendMsg{msgType: bType, payload: bPayload, raw: bRaw})
			wireResp.Write(bRaw)
			if bType == 'Z' {
				break
			}
		}
	} else {
		expectedSteps := countFlushExpectedSteps(batch)
		completedSteps := 0
		for completedSteps < expectedSteps {
			bType, bPayload, bRaw, rErr := readPostgresFrame(upConn)
			if rErr != nil {
				_ = upConn.Close()
				state.upConn = nil
				return rErr
			}
			backendFrames = append(backendFrames, pgFrontendMsg{msgType: bType, payload: bPayload, raw: bRaw})
			wireResp.Write(bRaw)
			switch bType {
			case '1', '2', '3', 'T', 'n', 'C', 's', 'I':
				completedSteps++
			case 'E':
				completedSteps = expectedSteps
			}
		}
	}

	capturedList := h.extractBatchExecutions(state, batch, backendFrames)
	if len(capturedList) > 0 && h.exchangeCache != nil {
		if traceID == ([16]byte{}) {
			traceID = h.resolvePostForwardTrace(ctx, oc.SockCookie, rawStart, rawEnd)
		}
		clientPort := remoteTCPPort(oc.ClientConn)
		if traceID != ([16]byte{}) || clientPort != 0 {
			for _, ex := range capturedList {
				if !isSessionControlSQL(ex.SQL) {
					ex.ClientPort = clientPort
					h.exchangeCache.RecordDatabase(traceID, ex)
				}
			}
		}
	}
	inFlight = false
	h.exchangeCache.EndInFlightDB()

	_, err = oc.ClientConn.Write(wireResp.Bytes())
	return err
}

func countFlushExpectedSteps(batch []pgFrontendMsg) int {
	steps := 0
	for _, m := range batch {
		switch m.msgType {
		case 'P', 'B', 'D', 'E', 'C':
			steps++
		}
	}
	return steps
}

func (h *PostgresProtocolHandler) applyFrontendStateUpdate(state *pgConnState, m pgFrontendMsg) {
	switch m.msgType {
	case 'P':
		stmtName, sqlText, oids, ok := parsePostgresParsePayload(m.payload)
		if !ok {
			return
		}
		var existingCols []DatabaseColumn
		if prev, exists := state.preparedStmts[stmtName]; exists && prev.sql == sqlText {
			existingCols = prev.columns
		}
		if meta, ok := h.metadataCache.Get(NormalizeSQL(sqlText)); ok {
			if len(oids) == 0 && len(meta.paramOIDs) > 0 {
				oids = slices.Clone(meta.paramOIDs)
			}
			if len(existingCols) == 0 && len(meta.columns) > 0 {
				existingCols = slices.Clone(meta.columns)
			}
		}
		state.preparedStmts[stmtName] = &pgPreparedStmt{
			name:      stmtName,
			sql:       sqlText,
			paramOIDs: oids,
			columns:   existingCols,
		}
	case 'B':
		portalName, stmtName, params, resFormats, ok := parsePostgresBindPayload(m.payload, func(name string) []uint32 {
			if st, exists := state.preparedStmts[name]; exists {
				return st.paramOIDs
			}
			return nil
		})
		if !ok {
			return
		}
		state.portals[portalName] = &pgPortal{
			name:          portalName,
			stmtName:      stmtName,
			params:        params,
			rawBind:       slices.Clone(m.payload),
			resultFormats: resFormats,
		}
	case 'C':
		if len(m.payload) < 2 {
			return
		}
		targetName, _, ok := readCString(m.payload, 1)
		if !ok {
			return
		}
		switch m.payload[0] {
		case 'S':
			delete(state.preparedStmts, targetName)
		case 'P':
			delete(state.portals, targetName)
		}
	}
}

func (h *PostgresProtocolHandler) extractBatchExecutions(
	state *pgConnState,
	batch []pgFrontendMsg,
	backend []pgFrontendMsg,
) []CapturedDatabaseExchange {
	var out []CapturedDatabaseExchange
	bIdx := 0

	for _, f := range batch {
		if bIdx >= len(backend) {
			break
		}
		switch f.msgType {
		case 'P':
			if backend[bIdx].msgType == '1' {
				bIdx++
			}
		case 'B':
			if backend[bIdx].msgType == '2' {
				bIdx++
			}
		case 'C':
			if backend[bIdx].msgType == '3' {
				bIdx++
			}
		case 'D':
			if len(f.payload) < 2 {
				continue
			}
			descType := f.payload[0]
			targetName, _, _ := readCString(f.payload, 1)
			var st *pgPreparedStmt
			switch descType {
			case 'S':
				st = state.preparedStmts[targetName]
				if bIdx < len(backend) && backend[bIdx].msgType == 't' {
					oids := parsePostgresParamDesc(backend[bIdx].payload)
					if st != nil && len(oids) > 0 {
						st.paramOIDs = oids
						for _, portal := range state.portals {
							if portal.stmtName == targetName && len(portal.rawBind) > 0 {
								_, _, reParams, _, ok := parsePostgresBindPayload(portal.rawBind, func(string) []uint32 {
									return oids
								})
								if ok {
									portal.params = reParams
								}
							}
						}
					}
					bIdx++
				}
			case 'P':
				if portal, ok := state.portals[targetName]; ok {
					st = state.preparedStmts[portal.stmtName]
				}
			}
			if bIdx < len(backend) {
				switch backend[bIdx].msgType {
				case 'T':
					cols, _, ok := parsePostgresRowDescription(backend[bIdx].payload)
					if ok && st != nil {
						st.columns = cols
						h.rememberSQLMetadata(st.sql, st.paramOIDs, st.columns)
					}
					bIdx++
				case 'n':
					if st != nil && len(st.paramOIDs) > 0 {
						h.rememberSQLMetadata(st.sql, st.paramOIDs, st.columns)
					}
					bIdx++
				}
			}
		case 'E':
			portalName, _, _ := readCString(f.payload, 0)
			portal := state.portals[portalName]
			var st *pgPreparedStmt
			if portal != nil {
				st = state.preparedStmts[portal.stmtName]
			}
			var execRaw bytes.Buffer
			for bIdx < len(backend) {
				bt := backend[bIdx].msgType
				if bt == 'Z' {
					break
				}
				execRaw.Write(backend[bIdx].raw)
				bIdx++
				if bt == 'C' || bt == 's' || bt == 'I' || bt == 'E' {
					break
				}
			}
			if st != nil && execRaw.Len() > 0 {
				var resFormats []int16
				var params []any
				var stmtName string
				if portal != nil {
					resFormats = portal.resultFormats
					params = slices.Clone(portal.params)
					stmtName = portal.stmtName
				}
				res := parsePostgresWireResponseWithFormats(execRaw.Bytes(), st.columns, resFormats)
				if res != nil {
					if len(res.Columns) > 0 {
						st.columns = res.Columns
						h.rememberSQLMetadata(st.sql, st.paramOIDs, res.Columns)
					}
					out = append(out, CapturedDatabaseExchange{
						DBName:     state.dbName,
						StmtName:   stmtName,
						SQL:        st.sql,
						Parameters: params,
						Result:     res,
					})
				}
			}
		}
	}
	return out
}

func (h *PostgresProtocolHandler) rememberSQLMetadata(sqlText string, paramOIDs []uint32, cols []DatabaseColumn) {
	norm := NormalizeSQL(sqlText)
	if norm == "" {
		return
	}
	existing, _ := h.metadataCache.Get(norm)
	if len(paramOIDs) > 0 {
		existing.paramOIDs = slices.Clone(paramOIDs)
	}
	if len(cols) > 0 {
		existing.columns = slices.Clone(cols)
	}
	h.metadataCache.Add(norm, existing)
}

type cachedPortalExec struct {
	outcome  QueryOutcome
	result   *DatabaseResult
	skipLive bool
	errMsg   string
}

func (h *PostgresProtocolHandler) replayExtendedBatch(
	ctx context.Context,
	oc OutgoingConnectionContext,
	state *pgConnState,
	batch []pgFrontendMsg,
	sess *ReplaySession,
	serverSpanID [8]byte,
) error {
	var out bytes.Buffer
	aborted := false
	pendingPortalExec := make(map[string]*cachedPortalExec)

	hasExecuteForPortal := func(startIdx int, portalName string) bool {
		for j := startIdx + 1; j < len(batch); j++ {
			if batch[j].msgType == 'B' || batch[j].msgType == 'S' {
				pName, _, _ := readCString(batch[j].payload, 0)
				if batch[j].msgType == 'B' && pName == portalName {
					return false
				}
			}
			if batch[j].msgType == 'E' {
				pName, _, _ := readCString(batch[j].payload, 0)
				if pName == portalName {
					return true
				}
			}
		}
		return false
	}

	runPortalQuery := func(portal *pgPortal, st *pgPreparedStmt) *cachedPortalExec {
		if st == nil || strings.TrimSpace(st.sql) == "" {
			return &cachedPortalExec{errMsg: "unknown prepared statement"}
		}
		if isSessionControlSQL(st.sql) {
			var sessionCols []DatabaseColumn
			if len(st.columns) > 0 {
				sessionCols = slices.Clone(st.columns)
			} else if inferred := inferSelectColumns(st.sql); len(inferred) > 0 {
				sessionCols = inferred
			}
			tag := sessionSQLCommandTag(st.sql)
			switch firstSQLVerb(st.sql) {
			case "SELECT", "WITH", "VALUES", "SHOW":
				tag = pgCommandTag(st.sql, nil)
			}
			return &cachedPortalExec{
				outcome: QueryOutcomeHit,
				result: &DatabaseResult{
					Columns:    sessionCols,
					CommandTag: tag,
				},
			}
		}
		qOut, res, skipLive, errMsg := h.queryDatabaseMock(ctx, oc, sess, serverSpanID, state.dbName, st.sql, portal.params)
		if res != nil && len(res.Columns) == 0 && len(st.columns) > 0 {
			res.Columns = slices.Clone(st.columns)
		}
		if res != nil && len(st.columns) > 0 {
			for i := range res.Columns {
				if res.Columns[i].TypeOID == 0 && i < len(st.columns) {
					res.Columns[i].TypeOID = st.columns[i].TypeOID
				}
			}
		}
		return &cachedPortalExec{
			outcome:  qOut,
			result:   res,
			skipLive: skipLive,
			errMsg:   errMsg,
		}
	}

	for i, m := range batch {
		if m.msgType == 'S' {
			aborted = false
			out.Write(encodePGReadyForQuery())
			continue
		}
		if m.msgType == 'H' {
			continue
		}
		if aborted {
			continue
		}

		switch m.msgType {
		case 'P':
			h.applyFrontendStateUpdate(state, m)
			writePGMsg(&out, '1', nil)

		case 'B':
			h.applyFrontendStateUpdate(state, m)
			portalName, _, _ := readCString(m.payload, 0)
			delete(pendingPortalExec, portalName)
			writePGMsg(&out, '2', nil)

		case 'C':
			h.applyFrontendStateUpdate(state, m)
			writePGMsg(&out, '3', nil)

		case 'D':
			if len(m.payload) < 2 {
				out.Write(encodePGErrorResponse("ERROR", "08P01", "malformed Describe"))
				aborted = true
				continue
			}
			descType := m.payload[0]
			targetName, _, _ := readCString(m.payload, 1)
			if descType == 'S' {
				st := state.preparedStmts[targetName]
				if st == nil {
					out.Write(encodePGErrorResponse("ERROR", "26000", "prepared statement does not exist"))
					aborted = true
					continue
				}
				oids := resolveStatementParamOIDs(st)
				out.Write(encodePGParameterDescription(oids))
				cols := st.columns
				if len(cols) == 0 {
					if meta, ok := h.metadataCache.Get(NormalizeSQL(st.sql)); ok && len(meta.columns) > 0 {
						cols = meta.columns
					}
				}
				if len(cols) > 0 {
					out.Write(encodePGRowDescription(cols, nil))
				} else if inferred := inferSelectColumns(st.sql); len(inferred) > 0 {
					out.Write(encodePGRowDescription(inferred, nil))
				} else {
					writePGMsg(&out, 'n', nil)
				}
			} else if descType == 'P' {
				portal := state.portals[targetName]
				if portal == nil {
					out.Write(encodePGErrorResponse("ERROR", "34000", "portal does not exist"))
					aborted = true
					continue
				}
				st := state.preparedStmts[portal.stmtName]
				var cols []DatabaseColumn
				if st != nil {
					cols = st.columns
				}
				if hasExecuteForPortal(i, targetName) {
					execRes := runPortalQuery(portal, st)
					pendingPortalExec[targetName] = execRes
					if execRes.skipLive {
						return h.forwardExtendedBatchLive(ctx, oc, state, batch, [16]byte{}, 0, 0)
					}
					if execRes.outcome == QueryOutcomeMustMock {
						out.Write(encodePGErrorResponse("ERROR", "XX000", "softprobe mustMock miss"))
						aborted = true
						continue
					}
					if execRes.errMsg != "" || execRes.result == nil {
						msg := execRes.errMsg
						if msg == "" {
							msg = "softprobe replay mock miss"
						}
						out.Write(encodePGErrorResponse("ERROR", "XX000", msg))
						aborted = true
						continue
					}
					if execRes.result.ErrorMessage != "" {
						code := execRes.result.ErrorCode
						if code == "" {
							code = "XX000"
						}
						out.Write(encodePGErrorResponse("ERROR", code, execRes.result.ErrorMessage))
						aborted = true
						continue
					}
					cols = execRes.result.Columns
				}
				if len(cols) > 0 {
					out.Write(encodePGRowDescription(cols, portal.resultFormats))
				} else {
					writePGMsg(&out, 'n', nil)
				}
			}

		case 'E':
			portalName, _, _ := readCString(m.payload, 0)
			portal := state.portals[portalName]
			if portal == nil {
				out.Write(encodePGErrorResponse("ERROR", "34000", "portal does not exist"))
				aborted = true
				continue
			}
			st := state.preparedStmts[portal.stmtName]
			execRes, hasCached := pendingPortalExec[portalName]
			delete(pendingPortalExec, portalName)
			if !hasCached {
				execRes = runPortalQuery(portal, st)
			}
			if execRes.skipLive {
				return h.forwardExtendedBatchLive(ctx, oc, state, batch, [16]byte{}, 0, 0)
			}
			if execRes.outcome == QueryOutcomeMustMock {
				out.Write(encodePGErrorResponse("ERROR", "XX000", "softprobe mustMock miss"))
				aborted = true
				continue
			}
			if execRes.errMsg != "" || execRes.result == nil {
				msg := execRes.errMsg
				if msg == "" {
					msg = "softprobe replay mock miss"
				}
				out.Write(encodePGErrorResponse("ERROR", "XX000", msg))
				aborted = true
				continue
			}
			res := execRes.result
			if res.ErrorMessage != "" {
				code := res.ErrorCode
				if code == "" {
					code = "XX000"
				}
				out.Write(encodePGErrorResponse("ERROR", code, res.ErrorMessage))
				aborted = true
				continue
			}
			for _, row := range res.Rows {
				out.Write(encodePGDataRow(row, res.Columns, portal.resultFormats))
			}
			sqlForTag := ""
			if st != nil {
				sqlForTag = st.sql
			}
			if len(res.Rows) == 0 && strings.TrimSpace(strings.Trim(stripSQLComments(sqlForTag), "; \t\r\n")) == "" {
				writePGMsg(&out, 'I', nil)
			} else {
				out.Write(encodePGCommandComplete(pgCommandTag(sqlForTag, res)))
			}
		}
	}

	_, err := oc.ClientConn.Write(out.Bytes())
	return err
}

func (h *PostgresProtocolHandler) queryDatabaseMock(
	ctx context.Context,
	oc OutgoingConnectionContext,
	sess *ReplaySession,
	serverSpanID [8]byte,
	dbName string,
	sqlText string,
	params []any,
) (QueryOutcome, *DatabaseResult, bool, string) {
	hostAndPort := ""
	if oc.OrigDst.IsValid() {
		hostAndPort = oc.OrigDst.String()
	}
	localIgnored := sess.ShouldIgnoreMock(ServiceKeyDatabase, DatabaseQueryOperationName, hostAndPort) ||
		sess.ShouldIgnoreMock(CategoryDatabase.Name, DatabaseQueryOperationName, hostAndPort)

	if h.backendClient == nil {
		if localIgnored {
			h.stats.SkipMockForwards.Add(1)
			return QueryOutcomeSkipMock, nil, true, ""
		}
		h.stats.EmptyMissBlocks.Add(1)
		return QueryOutcomeEmptyMiss, nil, false, "softprobe backend client unavailable"
	}

	traceIDHex := sess.RecordedTraceID
	if traceIDHex == "" {
		traceIDHex = FormatTraceIDHex(sess.TraceID)
	}
	segmentID := sess.SegmentID
	if segmentID == "" && serverSpanID != ([8]byte{}) {
		segmentID = FormatSpanIDHex(serverSpanID)
	}

	queryMocker, err := BuildDatabaseMocker(SpanMetadata{
		AppID:             h.cfg.AppID,
		TraceID:           traceIDHex,
		ReplayID:          sess.ReplayID,
		SegmentID:         segmentID,
		CreationTimeMs:    time.Now().UnixMilli(),
		RecordEnvironment: recordEnvironmentCode(h.cfg.Env),
		RecordVersion:     defaultRecordVersion,
	}, DatabaseExchange{
		DBName:     dbName,
		SQL:        sqlText,
		Parameters: params,
	})
	if err != nil {
		h.stats.EmptyMissBlocks.Add(1)
		return QueryOutcomeEmptyMiss, nil, false, err.Error()
	}
	if queryMocker.TargetResponse == nil {
		queryMocker.TargetResponse = &Target{}
	}
	queryMocker.TargetResponse.SetAttribute(AttrRealCallAware, "1")
	if localIgnored {
		queryMocker.TargetResponse.SetAttribute(AttrLocalRelease, "1")
	}

	qRes, qErr := h.backendClient.QueryRecord(ctx, queryMocker, MockStrategyDatabase)
	if qErr != nil {
		if localIgnored {
			h.stats.SkipMockForwards.Add(1)
			return QueryOutcomeSkipMock, nil, true, ""
		}
		h.stats.EmptyMissBlocks.Add(1)
		h.emitReplayLog(sess, serverSpanID, "WARN", "softprobe replay query failed Database "+dbName)
		return QueryOutcomeEmptyMiss, nil, false, qErr.Error()
	}

	switch qRes.Outcome {
	case QueryOutcomeHit:
		decoded, decErr := DecodeDatabaseResult(qRes.Mocker)
		if decErr != nil {
			h.stats.EmptyMissBlocks.Add(1)
			return QueryOutcomeEmptyMiss, nil, false, decErr.Error()
		}
		h.stats.MockHits.Add(1)
		h.emitReplayLog(sess, serverSpanID, "INFO", "softprobe replay mock hit Database "+dbName)
		return QueryOutcomeHit, decoded, false, ""

	case QueryOutcomeMustMock:
		h.stats.MustMockBlocks.Add(1)
		h.emitReplayLog(sess, serverSpanID, "WARN", "softprobe replay MUST_MOCK blocked Database "+dbName)
		return QueryOutcomeMustMock, nil, false, "softprobe mustMock miss"

	case QueryOutcomeSkipMock:
		h.stats.SkipMockForwards.Add(1)
		h.emitReplayLog(sess, serverSpanID, "INFO", "softprobe replay skip-mock forwarded Database "+dbName)
		return QueryOutcomeSkipMock, nil, true, ""

	default:
		if localIgnored {
			h.stats.SkipMockForwards.Add(1)
			return QueryOutcomeSkipMock, nil, true, ""
		}
		h.stats.EmptyMissBlocks.Add(1)
		h.emitReplayLog(sess, serverSpanID, "WARN", "softprobe replay mock miss Database "+dbName)
		return QueryOutcomeEmptyMiss, nil, false, "softprobe replay mock miss"
	}
}

func (h *PostgresProtocolHandler) emitReplayLog(sess *ReplaySession, spanID [8]byte, severity, body string) {
	if h.logExporter == nil || sess == nil {
		return
	}
	logTraceID := sess.TraceID
	if sess.RecordedTraceID != "" {
		if parsed, err := ParseTraceIDHex(sess.RecordedTraceID); err == nil {
			logTraceID = parsed
		}
	}
	if logTraceID == ([16]byte{}) {
		return
	}
	h.logExporter.Enqueue(LogRecordInput{
		TraceID:      logTraceID,
		SpanID:       spanID,
		Source:       LogSourceAgent,
		ReplayID:     sess.ReplayID,
		SeverityText: severity,
		Body:         body,
	})
}

func (h *PostgresProtocolHandler) ensureUpstream(ctx context.Context, origDst netip.AddrPort, state *pgConnState) (net.Conn, error) {
	if state.upConn != nil {
		return state.upConn, nil
	}
	upConn, err := h.dialUpstream(ctx, origDst)
	if err != nil {
		return nil, err
	}
	state.upConn = upConn
	return upConn, nil
}

func (h *PostgresProtocolHandler) dialUpstream(ctx context.Context, origDst netip.AddrPort) (net.Conn, error) {
	if !origDst.IsValid() {
		return nil, errors.New("missing original destination for postgres upstream")
	}
	h.stats.UpstreamDials.Add(1)
	return h.dialContext(ctx, "tcp", origDst.String())
}

func (h *PostgresProtocolHandler) resolveSocketSession(
	ctx context.Context,
	sockCookie uint64,
	rawStart uint64,
	rawEnd uint64,
) ([16]byte, [8]byte, *ReplaySession, bool) {
	if sockCookie == 0 || h.writeTracker == nil {
		return [16]byte{}, [8]byte{}, nil, false
	}
	if wctx, ok := lookupWriteInFrameRange(h.writeTracker, sockCookie, rawStart, rawEnd); ok && wctx.TraceID != ([16]byte{}) {
		if h.replayRegistry != nil {
			if sess, isReplay := h.replayRegistry.Lookup(wctx.TraceID); isReplay && sess != nil {
				return wctx.TraceID, wctx.ServerSpanID, sess, true
			}
		}
		return wctx.TraceID, wctx.ServerSpanID, nil, false
	}
	if h.replayRegistry != nil && h.replayRegistry.Len() > 0 {
		deadline := time.Now().Add(100 * time.Millisecond)
		for time.Now().Before(deadline) {
			if ctx.Err() != nil {
				break
			}
			time.Sleep(writeContextPollStep)
			if wctx, ok := lookupWriteInFrameRange(h.writeTracker, sockCookie, rawStart, rawEnd); ok && wctx.TraceID != ([16]byte{}) {
				if sess, isReplay := h.replayRegistry.Lookup(wctx.TraceID); isReplay && sess != nil {
					return wctx.TraceID, wctx.ServerSpanID, sess, true
				}
				return wctx.TraceID, wctx.ServerSpanID, nil, false
			}
		}
	}
	return [16]byte{}, [8]byte{}, nil, false
}

func (h *PostgresProtocolHandler) resolvePostForwardTrace(
	ctx context.Context,
	sockCookie uint64,
	rawStart uint64,
	rawEnd uint64,
) [16]byte {
	if sockCookie == 0 || h.writeTracker == nil {
		return [16]byte{}
	}
	if wctx, ok := lookupWriteInFrameRange(h.writeTracker, sockCookie, rawStart, rawEnd); ok && wctx.TraceID != ([16]byte{}) {
		return wctx.TraceID
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			break
		}
		time.Sleep(writeContextPollStep)
		if wctx, ok := lookupWriteInFrameRange(h.writeTracker, sockCookie, rawStart, rawEnd); ok && wctx.TraceID != ([16]byte{}) {
			return wctx.TraceID
		}
	}
	return [16]byte{}
}

func readPostgresFrame(r io.Reader) (byte, []byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, nil, err
	}
	msgType := hdr[0]
	msgLen := int(binary.BigEndian.Uint32(hdr[1:5]))
	if msgLen < 4 || msgLen > maxPGFrameBytes {
		return 0, nil, nil, fmt.Errorf("invalid postgres frame length %d", msgLen)
	}
	raw := make([]byte, 1+msgLen)
	copy(raw[:5], hdr[:])
	if msgLen > 4 {
		if _, err := io.ReadFull(r, raw[5:]); err != nil {
			return 0, nil, nil, err
		}
	}
	return msgType, raw[5:], raw, nil
}

func parsePostgresParsePayload(payload []byte) (string, string, []uint32, bool) {
	stmtName, p, ok := readCString(payload, 0)
	if !ok {
		return "", "", nil, false
	}
	sqlText, p, ok := readCString(payload, p)
	if !ok {
		return "", "", nil, false
	}
	var oids []uint32
	if p+2 <= len(payload) {
		n := int(binary.BigEndian.Uint16(payload[p : p+2]))
		p += 2
		if n > 0 && n <= 4096 && p+n*4 <= len(payload) {
			oids = make([]uint32, n)
			for i := range n {
				oids[i] = binary.BigEndian.Uint32(payload[p+i*4 : p+(i+1)*4])
			}
		}
	}
	return stmtName, sqlText, oids, true
}

func parsePostgresParamDesc(payload []byte) []uint32 {
	if len(payload) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(payload[0:2]))
	if n <= 0 || n > 4096 || 2+n*4 > len(payload) {
		return nil
	}
	oids := make([]uint32, n)
	for i := range n {
		oids[i] = binary.BigEndian.Uint32(payload[2+i*4 : 2+(i+1)*4])
	}
	return oids
}

func resolveStatementParamOIDs(st *pgPreparedStmt) []uint32 {
	maxPlaceholder := maxPostgresPlaceholder(st.sql)
	count := max(len(st.paramOIDs), maxPlaceholder)
	if count == 0 {
		return nil
	}
	out := make([]uint32, count)
	for i := range count {
		if i < len(st.paramOIDs) && st.paramOIDs[i] != 0 {
			out[i] = st.paramOIDs[i]
		} else {
			out[i] = pgOIDText
		}
	}
	return out
}

func maxPostgresPlaceholder(sql string) int {
	maxIdx := 0
	var quote byte
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '$' && i+1 < len(sql) && sql[i+1] >= '1' && sql[i+1] <= '9' {
			j := i + 1
			val := 0
			for j < len(sql) && sql[j] >= '0' && sql[j] <= '9' {
				val = val*10 + int(sql[j]-'0')
				j++
			}
			if val > maxIdx && val <= 4096 {
				maxIdx = val
			}
			i = j - 1
		}
	}
	return maxIdx
}

func inferSelectColumns(sql string) []DatabaseColumn {
	norm := strings.TrimSpace(NormalizeSQL(sql))
	upper := strings.ToUpper(norm)
	if !strings.HasPrefix(upper, "SELECT ") {
		return nil
	}
	fromIdx := strings.Index(upper, " FROM ")
	selectList := norm[7:]
	if fromIdx > 7 {
		selectList = norm[7:fromIdx]
	}
	parts := strings.Split(selectList, ",")
	cols := make([]DatabaseColumn, 0, len(parts))
	for idx, part := range parts {
		tokens := strings.Fields(strings.TrimSpace(part))
		name := fmt.Sprintf("column_%d", idx+1)
		if len(tokens) > 0 {
			last := tokens[len(tokens)-1]
			if dot := strings.LastIndexByte(last, '.'); dot >= 0 && dot+1 < len(last) {
				last = last[dot+1:]
			}
			last = strings.Trim(last, `"'`)
			if last != "" && last != "*" {
				name = last
			}
		}
		cols = append(cols, DatabaseColumn{Name: name, TypeOID: pgOIDText})
	}
	return cols
}

func writePGMsg(buf *bytes.Buffer, msgType byte, payload []byte) {
	buf.WriteByte(msgType)
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(4+len(payload)))
	buf.Write(lenBytes[:])
	if len(payload) > 0 {
		buf.Write(payload)
	}
}

func encodePGReadyForQuery() []byte {
	var buf bytes.Buffer
	writePGMsg(&buf, 'Z', []byte{'I'})
	return buf.Bytes()
}

//nolint:unparam // severity follows PostgreSQL ErrorResponse field conventions
func encodePGErrorResponse(severity, code, message string) []byte {
	var p bytes.Buffer
	p.WriteByte('S')
	p.WriteString(severity)
	p.WriteByte(0)
	p.WriteByte('V')
	p.WriteString(severity)
	p.WriteByte(0)
	p.WriteByte('C')
	p.WriteString(code)
	p.WriteByte(0)
	p.WriteByte('M')
	p.WriteString(message)
	p.WriteByte(0)
	p.WriteByte(0)

	var out bytes.Buffer
	writePGMsg(&out, 'E', p.Bytes())
	return out.Bytes()
}

func encodePGParameterDescription(oids []uint32) []byte {
	var p bytes.Buffer
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], uint16(len(oids)))
	p.Write(cnt[:])
	var oidBuf [4]byte
	for _, oid := range oids {
		binary.BigEndian.PutUint32(oidBuf[:], oid)
		p.Write(oidBuf[:])
	}
	var out bytes.Buffer
	writePGMsg(&out, 't', p.Bytes())
	return out.Bytes()
}

func encodePGRowDescription(cols []DatabaseColumn, resultFormats []int16) []byte {
	var p bytes.Buffer
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], uint16(len(cols)))
	p.Write(cnt[:])

	for i, col := range cols {
		p.WriteString(col.Name)
		p.WriteByte(0)
		oid := col.TypeOID
		if oid == 0 {
			oid = pgOIDText
		}
		fmtCode := pgEffectiveFormat(resultFormats, i)
		var meta [18]byte
		binary.BigEndian.PutUint32(meta[6:10], oid)
		binary.BigEndian.PutUint16(meta[10:12], pgTypeSize(oid))
		binary.BigEndian.PutUint32(meta[12:16], 0xffffffff)
		binary.BigEndian.PutUint16(meta[16:18], uint16(fmtCode))
		p.Write(meta[:])
	}
	var out bytes.Buffer
	writePGMsg(&out, 'T', p.Bytes())
	return out.Bytes()
}

func pgTypeSize(oid uint32) uint16 {
	switch oid {
	case pgOIDBool:
		return 1
	case pgOIDInt2:
		return 2
	case pgOIDInt4, pgOIDOID, pgOIDFloat4, pgOIDDate:
		return 4
	case pgOIDInt8, pgOIDFloat8, pgOIDTimestamp, pgOIDTimestamptz:
		return 8
	case pgOIDUUID:
		return 16
	default:
		return 0xffff
	}
}

func encodePGDataRow(row []any, cols []DatabaseColumn, resultFormats []int16) []byte {
	colCount := max(len(cols), len(row))
	var p bytes.Buffer
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], uint16(colCount))
	p.Write(cnt[:])

	var lenBuf [4]byte
	for i := range colCount {
		var val any
		if i < len(row) {
			val = row[i]
		}
		if val == nil {
			binary.BigEndian.PutUint32(lenBuf[:], 0xffffffff)
			p.Write(lenBuf[:])
			continue
		}
		oid := pgOIDText
		if i < len(cols) && cols[i].TypeOID != 0 {
			oid = cols[i].TypeOID
		}
		fmtCode := pgEffectiveFormat(resultFormats, i)
		encoded := encodePostgresWireValue(val, fmtCode, oid)
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(encoded)))
		p.Write(lenBuf[:])
		p.Write(encoded)
	}

	var out bytes.Buffer
	writePGMsg(&out, 'D', p.Bytes())
	return out.Bytes()
}

func encodePostgresWireValue(val any, formatCode int16, oid uint32) []byte {
	strVal := scalarToString(val)
	if formatCode == 0 {
		return []byte(strVal)
	}

	switch oid {
	case pgOIDBool:
		switch strings.ToLower(strings.TrimSpace(strVal)) {
		case "t", "true", "1", "yes", "on":
			return []byte{1}
		default:
			return []byte{0}
		}
	case pgOIDBytea:
		if strings.HasPrefix(strVal, `\x`) {
			if decoded, err := hex.DecodeString(strVal[2:]); err == nil {
				return decoded
			}
		}
		return []byte(strVal)
	case pgOIDInt2:
		if n, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 16); err == nil {
			var b [2]byte
			binary.BigEndian.PutUint16(b[:], uint16(int16(n)))
			return b[:]
		}
	case pgOIDInt4, pgOIDOID:
		if n, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 32); err == nil {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(int32(n)))
			return b[:]
		}
	case pgOIDInt8:
		if n, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], uint64(n))
			return b[:]
		}
	case pgOIDFloat4:
		if f, err := strconv.ParseFloat(strings.TrimSpace(strVal), 32); err == nil {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], math.Float32bits(float32(f)))
			return b[:]
		}
	case pgOIDFloat8:
		if f, err := strconv.ParseFloat(strings.TrimSpace(strVal), 64); err == nil {
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], math.Float64bits(f))
			return b[:]
		}
	case pgOIDJSONB:
		out := make([]byte, 1+len(strVal))
		out[0] = 1
		copy(out[1:], strVal)
		return out
	case pgOIDUUID:
		cleanHex := strings.ReplaceAll(strings.TrimSpace(strVal), "-", "")
		if len(cleanHex) == 32 {
			if decoded, err := hex.DecodeString(cleanHex); err == nil && len(decoded) == 16 {
				return decoded
			}
		}
	case pgOIDDate:
		if t, err := time.Parse("2006-01-02", strings.TrimSpace(strVal)); err == nil {
			days := int32(t.UTC().Sub(pgEpoch).Hours() / 24)
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(days))
			return b[:]
		}
	case pgOIDTimestamp, pgOIDTimestamptz:
		if ts, ok := parseFlexibleTimestamp(strVal); ok {
			usec := ts.UTC().Sub(pgEpoch).Microseconds()
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], uint64(usec))
			return b[:]
		}
	}
	return []byte(strVal)
}

func parseFlexibleTimestamp(s string) (time.Time, bool) {
	trimmed := strings.TrimSpace(s)
	for _, layout := range []string{
		time.RFC3339Nano,
		"2006-01-02 15:04:05.999999-07",
		"2006-01-02 15:04:05.999999+00",
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05-07",
		"2006-01-02 15:04:05+00",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, trimmed); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func scalarToString(val any) string {
	switch v := val.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case bool:
		if v {
			return "t"
		}
		return "f"
	case float64:
		if v == math.Trunc(v) && v >= math.MinInt64 && v <= math.MaxInt64 {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'g', -1, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	default:
		return fmt.Sprint(v)
	}
}

func encodePGCommandComplete(tag string) []byte {
	if tag == "" {
		tag = "OK"
	}
	var p bytes.Buffer
	p.WriteString(tag)
	p.WriteByte(0)
	var out bytes.Buffer
	writePGMsg(&out, 'C', p.Bytes())
	return out.Bytes()
}

func pgCommandTag(sqlText string, res *DatabaseResult) string {
	if res != nil && res.CommandTag != "" {
		return res.CommandTag
	}
	verb := firstSQLVerb(sqlText)
	switch verb {
	case "SELECT", "WITH", "VALUES", "SHOW":
		n := 0
		if res != nil {
			n = len(res.Rows)
		}
		return fmt.Sprintf("SELECT %d", n)
	case "INSERT":
		affected := int64(0)
		if res != nil {
			affected = res.RowsAffected
			if affected == 0 && len(res.Rows) > 0 {
				affected = int64(len(res.Rows))
			}
		}
		return fmt.Sprintf("INSERT 0 %d", affected)
	case "UPDATE", "DELETE":
		affected := int64(0)
		if res != nil {
			affected = res.RowsAffected
		}
		return fmt.Sprintf("%s %d", verb, affected)
	default:
		if verb != "" {
			return verb
		}
		return "SELECT 0"
	}
}

func firstSQLVerb(sqlText string) string {
	fields := strings.Fields(strings.TrimSpace(sqlText))
	if len(fields) == 0 {
		return ""
	}
	return strings.ToUpper(strings.TrimRight(fields[0], ";"))
}

func sessionSQLCommandTag(sqlText string) string {
	verb := firstSQLVerb(sqlText)
	if verb == "START" {
		return "START TRANSACTION"
	}
	if verb == "END" {
		return "COMMIT"
	}
	if verb != "" {
		return verb
	}
	return "OK"
}

func encodeSyntheticPostgresSessionReply(sqlText string, includeReady bool) []byte {
	var out bytes.Buffer
	wrote := false
	for rawStmt := range strings.SplitSeq(stripSQLComments(sqlText), ";") {
		stmt := strings.TrimSpace(rawStmt)
		if stmt == "" {
			continue
		}
		wrote = true
		upper := strings.ToUpper(NormalizeSQL(stmt))
		switch {
		case strings.HasPrefix(upper, "SELECT PG_ADVISORY_UNLOCK_ALL("):
			cols := []DatabaseColumn{{Name: "pg_advisory_unlock_all", TypeOID: 2278}}
			out.Write(encodePGRowDescription(cols, nil))
			out.Write(encodePGDataRow([]any{""}, cols, nil))
			out.Write(encodePGCommandComplete("SELECT 1"))
		case strings.HasPrefix(upper, "SELECT "), strings.HasPrefix(upper, "WITH "):
			cols := []DatabaseColumn{{Name: "result", TypeOID: pgOIDText}}
			out.Write(encodePGRowDescription(cols, nil))
			out.Write(encodePGCommandComplete("SELECT 0"))
		default:
			out.Write(encodePGCommandComplete(sessionSQLCommandTag(stmt)))
		}
	}
	if !wrote {
		writePGMsg(&out, 'I', nil)
	}
	if includeReady {
		out.Write(encodePGReadyForQuery())
	}
	return out.Bytes()
}

func encodePostgresResultWire(sqlText string, res *DatabaseResult, resultFormats []int16, includeReady bool) []byte {
	var out bytes.Buffer
	if res.ErrorMessage != "" {
		code := res.ErrorCode
		if code == "" {
			code = "XX000"
		}
		out.Write(encodePGErrorResponse("ERROR", code, res.ErrorMessage))
		if includeReady {
			out.Write(encodePGReadyForQuery())
		}
		return out.Bytes()
	}

	if len(res.Columns) > 0 {
		out.Write(encodePGRowDescription(res.Columns, resultFormats))
		for _, row := range res.Rows {
			out.Write(encodePGDataRow(row, res.Columns, resultFormats))
		}
	}
	out.Write(encodePGCommandComplete(pgCommandTag(sqlText, res)))
	if includeReady {
		out.Write(encodePGReadyForQuery())
	}
	return out.Bytes()
}
