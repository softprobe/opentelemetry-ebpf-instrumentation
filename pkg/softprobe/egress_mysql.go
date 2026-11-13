// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bytes"
	"context"
	"encoding/binary"
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
	mysqlComQuit        uint8 = 0x01
	mysqlComInitDB      uint8 = 0x02
	mysqlComQuery       uint8 = 0x03
	mysqlComPing        uint8 = 0x0e
	mysqlComStmtPrepare uint8 = 0x16
	mysqlComStmtExecute uint8 = 0x17
	mysqlComStmtClose   uint8 = 0x19
	mysqlComStmtReset   uint8 = 0x1a

	mysqlCapLongPassword               uint32 = 0x00000001
	mysqlCapFoundRows                  uint32 = 0x00000002
	mysqlCapLongFlag                   uint32 = 0x00000004
	mysqlCapConnectWithDB              uint32 = 0x00000008
	mysqlCapCompress                   uint32 = 0x00000020
	mysqlCapProtocol41                 uint32 = 0x00000200
	mysqlCapSSL                        uint32 = 0x00000800
	mysqlCapTransactions               uint32 = 0x00002000
	mysqlCapSecureConnection           uint32 = 0x00008000
	mysqlCapPluginAuth                 uint32 = 0x00080000
	mysqlCapPluginAuthLenEncClientData uint32 = 0x00200000
	mysqlCapDeprecateEOF               uint32 = 0x01000000
	mysqlCapZstdCompression            uint32 = 0x04000000
	mysqlCapQueryAttributes            uint32 = 0x08000000

	maxMySQLPacketBytes = 64 << 20
)

type MySQLHandlerOption func(*MySQLProtocolHandler)

func WithMySQLDialer(dialFn func(ctx context.Context, network, address string) (net.Conn, error)) MySQLHandlerOption {
	return func(h *MySQLProtocolHandler) {
		if dialFn != nil {
			h.dialContext = dialFn
		}
	}
}

func WithMySQLExchangeCache(cache *HTTPExchangeCache) MySQLHandlerOption {
	return func(h *MySQLProtocolHandler) {
		if cache != nil {
			h.exchangeCache = cache
		}
	}
}

func WithMySQLLogExporter(exp *LogExporter) MySQLHandlerOption {
	return func(h *MySQLProtocolHandler) {
		if exp != nil {
			h.logExporter = exp
		}
	}
}

type mysqlParamType struct {
	fieldType uint8
	unsigned  bool
}

type mysqlPreparedStmt struct {
	id         uint32
	sql        string
	numParams  int
	paramTypes []mysqlParamType
	columns    []DatabaseColumn
}

type mysqlConnState struct {
	dbName              string
	clientFlags         uint32
	deprecateEOF        bool
	upConn              net.Conn
	preparedStmts       map[uint32]*mysqlPreparedStmt
	nextSyntheticStmtID uint32
}

type MySQLProtocolHandler struct {
	cfg            Config
	replayRegistry *ReplayRegistry
	writeTracker   *WriteContextTracker
	exchangeCache  *HTTPExchangeCache
	logExporter    *LogExporter
	backendClient  *BackendClient
	dialContext    func(ctx context.Context, network, address string) (net.Conn, error)
	stats          *EgressStats
	metadataCache  *expirable.LRU[string, []DatabaseColumn]
	log            *slog.Logger
}

func NewMySQLProtocolHandler(
	cfg Config,
	replayRegistry *ReplayRegistry,
	writeTracker *WriteContextTracker,
	backendClient *BackendClient,
	opts ...MySQLHandlerOption,
) *MySQLProtocolHandler {
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

	h := &MySQLProtocolHandler{
		cfg:            cfg,
		replayRegistry: replayRegistry,
		writeTracker:   writeTracker,
		exchangeCache:  SharedDataplaneBridge().ExchangeCache(),
		backendClient:  backendClient,
		dialContext:    dialer.DialContext,
		stats:          &EgressStats{},
		metadataCache:  expirable.NewLRU[string, []DatabaseColumn](defaultSQLMetadataCacheSize, nil, defaultSQLMetadataCacheTTL),
		log:            slog.With("component", "softprobe.MySQLProtocolHandler"),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(h)
		}
	}
	return h
}

func (h *MySQLProtocolHandler) Name() string {
	return "mysql"
}

func (h *MySQLProtocolHandler) Stats() *EgressStats {
	return h.stats
}

func (h *MySQLProtocolHandler) IsServerFirstPort(origPort uint16) bool {
	return origPort == 3306
}

func (h *MySQLProtocolHandler) CanHandle(_ []byte, origPort uint16) bool {
	return origPort == 3306
}

func (h *MySQLProtocolHandler) HandleConnection(ctx context.Context, oc OutgoingConnectionContext) error {
	state := &mysqlConnState{
		dbName:              "default",
		preparedStmts:       make(map[uint32]*mysqlPreparedStmt),
		nextSyntheticStmtID: 100000,
	}
	defer func() {
		if state.upConn != nil {
			_ = state.upConn.Close()
		}
	}()

	if err := h.handleHandshake(ctx, oc, state); err != nil {
		return err
	}
	return h.serveCommandLoop(ctx, oc, state)
}

func (h *MySQLProtocolHandler) handleHandshake(ctx context.Context, oc OutgoingConnectionContext, state *mysqlConnState) error {
	if h.isKnownReplayAtHandshake(oc.SockCookie) {
		return h.completeSyntheticHandshake(oc, state)
	}

	upConn, err := h.dialUpstream(ctx, oc.OrigDst)
	if err != nil {
		return h.completeSyntheticHandshake(oc, state)
	}
	state.upConn = upConn

	greetingPayload, seq, _, err := readMySQLWirePacket(upConn)
	if err != nil {
		_ = upConn.Close()
		state.upConn = nil
		return h.completeSyntheticHandshake(oc, state)
	}

	// Clear SSL, compression, query-attribute, and deprecate-EOF bits so the local socket
	// stays in deterministic plaintext MySQL 4.1 framing.
	cleanGreeting := stripMySQLGreetingCapabilities(greetingPayload)
	if _, err := oc.ClientConn.Write(encodeMySQLWirePacket(seq, cleanGreeting)); err != nil {
		return err
	}

	clientResp, clientSeq, _, err := readMySQLWirePacket(oc.BufReader)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return err
		}
		return err
	}
	cleanClientResp := stripMySQLClientHandshakeCapabilities(clientResp)
	h.applyClientHandshakeMetadata(state, cleanClientResp)

	if _, err := upConn.Write(encodeMySQLWirePacket(clientSeq, cleanClientResp)); err != nil {
		return err
	}

	for {
		srvPayload, srvSeq, srvRaw, rErr := readMySQLWirePacket(upConn)
		if rErr != nil {
			return rErr
		}
		if _, wErr := oc.ClientConn.Write(srvRaw); wErr != nil {
			return wErr
		}
		if len(srvPayload) == 0 {
			return errors.New("empty mysql handshake packet")
		}
		switch srvPayload[0] {
		case 0x00:
			return nil
		case 0xff:
			return fmt.Errorf("mysql handshake error seq=%d", srvSeq)
		case 0x01:
			// In caching_sha2_password, 0x01 0x03 signals fast-auth success and is followed
			// directly by the server's final OK_Packet without a client reply.
			if len(srvPayload) == 2 && srvPayload[1] == 0x03 {
				continue
			}
			_, _, cRaw, cErr := readMySQLWirePacket(oc.BufReader)
			if cErr != nil {
				return cErr
			}
			if _, wErr := upConn.Write(cRaw); wErr != nil {
				return wErr
			}
		case 0xfe:
			_, _, cRaw, cErr := readMySQLWirePacket(oc.BufReader)
			if cErr != nil {
				return cErr
			}
			if _, wErr := upConn.Write(cRaw); wErr != nil {
				return wErr
			}
		}
	}
}

func (h *MySQLProtocolHandler) isKnownReplayAtHandshake(sockCookie uint64) bool {
	if sockCookie == 0 || h.writeTracker == nil || h.replayRegistry == nil {
		return false
	}
	wctx, ok := h.writeTracker.LookupAtOffset(sockCookie, 0)
	if !ok || wctx.TraceID == ([16]byte{}) {
		return false
	}
	_, isReplay := h.replayRegistry.Lookup(wctx.TraceID)
	return isReplay
}

func (h *MySQLProtocolHandler) completeSyntheticHandshake(oc OutgoingConnectionContext, state *mysqlConnState) error {
	greeting := buildSyntheticMySQLGreeting()
	if _, err := oc.ClientConn.Write(encodeMySQLWirePacket(0, greeting)); err != nil {
		return err
	}
	clientResp, clientSeq, _, err := readMySQLWirePacket(oc.BufReader)
	if err != nil {
		return err
	}
	h.applyClientHandshakeMetadata(state, clientResp)
	_, err = oc.ClientConn.Write(encodeMySQLOKPacket(clientSeq+1, 0, 0))
	return err
}

func (h *MySQLProtocolHandler) applyClientHandshakeMetadata(state *mysqlConnState, payload []byte) {
	if len(payload) < 32 {
		return
	}
	flags := binary.LittleEndian.Uint32(payload[0:4])
	state.clientFlags = flags
	state.deprecateEOF = (flags & mysqlCapDeprecateEOF) != 0

	_, pos, ok := readCString(payload, 32)
	if !ok {
		return
	}
	switch {
	case (flags & mysqlCapPluginAuthLenEncClientData) != 0:
		authLen, nextPos, ok := readMySQLLenEncInt(payload, pos)
		if !ok {
			return
		}
		pos = nextPos + int(authLen)
	case (flags & mysqlCapSecureConnection) != 0:
		if pos >= len(payload) {
			return
		}
		authLen := int(payload[pos])
		pos += 1 + authLen
	default:
		_, pos, ok = readCString(payload, pos)
		if !ok {
			return
		}
	}

	if (flags&mysqlCapConnectWithDB) != 0 && pos < len(payload) {
		if db, _, ok := readCString(payload, pos); ok && db != "" {
			state.dbName = db
		} else if rem := strings.TrimRight(string(payload[pos:]), "\x00"); rem != "" {
			state.dbName = rem
		}
	}
}

func stripMySQLGreetingCapabilities(greeting []byte) []byte {
	out := slices.Clone(greeting)
	if len(out) < 15 || out[0] != 0x0a {
		return out
	}
	_, pos, ok := readCString(out, 1)
	if !ok {
		return out
	}
	pos += 4 + 8 + 1
	if pos+7 > len(out) {
		return out
	}
	capLow := binary.LittleEndian.Uint16(out[pos : pos+2])
	capHigh := binary.LittleEndian.Uint16(out[pos+5 : pos+7])
	capFull := (uint32(capHigh)<<16 | uint32(capLow)) &^
		(mysqlCapSSL | mysqlCapCompress | mysqlCapDeprecateEOF | mysqlCapZstdCompression | mysqlCapQueryAttributes)
	binary.LittleEndian.PutUint16(out[pos:pos+2], uint16(capFull&0xffff))
	binary.LittleEndian.PutUint16(out[pos+5:pos+7], uint16(capFull>>16))
	return out
}

func stripMySQLClientHandshakeCapabilities(payload []byte) []byte {
	if len(payload) < 4 {
		return payload
	}
	out := slices.Clone(payload)
	flags := binary.LittleEndian.Uint32(out[0:4])
	flags &^= (mysqlCapSSL | mysqlCapCompress | mysqlCapDeprecateEOF | mysqlCapZstdCompression | mysqlCapQueryAttributes)
	binary.LittleEndian.PutUint32(out[0:4], flags)
	return out
}

func buildSyntheticMySQLGreeting() []byte {
	caps := mysqlCapLongPassword |
		mysqlCapFoundRows |
		mysqlCapLongFlag |
		mysqlCapConnectWithDB |
		mysqlCapProtocol41 |
		mysqlCapTransactions |
		mysqlCapSecureConnection |
		mysqlCapPluginAuth |
		mysqlCapPluginAuthLenEncClientData

	scramble1 := []byte("12345678")
	scramble2 := []byte("90abcdefghij\x00")
	plugin := "mysql_native_password\x00"

	var p bytes.Buffer
	p.WriteByte(0x0a)
	p.WriteString("8.0.36-softprobe")
	p.WriteByte(0)
	var connID [4]byte
	binary.LittleEndian.PutUint32(connID[:], 1)
	p.Write(connID[:])
	p.Write(scramble1)
	p.WriteByte(0)

	var capLow [2]byte
	binary.LittleEndian.PutUint16(capLow[:], uint16(caps&0xffff))
	p.Write(capLow[:])
	p.WriteByte(uint8(mysqlCharsetUTF8))

	var status [2]byte
	binary.LittleEndian.PutUint16(status[:], 0x0002)
	p.Write(status[:])

	var capHigh [2]byte
	binary.LittleEndian.PutUint16(capHigh[:], uint16(caps>>16))
	p.Write(capHigh[:])

	p.WriteByte(21)
	var reserved [10]byte
	p.Write(reserved[:])
	p.Write(scramble2)
	p.WriteString(plugin)
	return p.Bytes()
}

func (h *MySQLProtocolHandler) serveCommandLoop(ctx context.Context, oc OutgoingConnectionContext, state *mysqlConnState) error {
	prevOffset := rawConsumedBytes(oc.ClientConn, oc.BufReader)
	for {
		rawStart := prevOffset
		if oc.BufReader.Buffered() == 0 {
			rawStart = max(prevOffset, rawConsumedBytes(oc.ClientConn, oc.BufReader))
		}
		payload, _, rawPkt, err := readMySQLWirePacket(oc.BufReader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		rawEnd := rawConsumedBytes(oc.ClientConn, oc.BufReader)
		prevOffset = rawEnd

		if len(payload) == 0 {
			continue
		}

		cmd := payload[0]
		switch cmd {
		case mysqlComQuit:
			if state.upConn != nil {
				_, _ = state.upConn.Write(rawPkt)
			}
			return nil

		case mysqlComStmtClose:
			if len(payload) >= 5 {
				stmtID := binary.LittleEndian.Uint32(payload[1:5])
				delete(state.preparedStmts, stmtID)
			}
			_, _, sess, isReplay := h.resolveSocketSession(ctx, oc.SockCookie, rawStart, rawEnd)
			if !isReplay && sess == nil && state.upConn != nil {
				_, _ = state.upConn.Write(rawPkt)
			}

		case mysqlComInitDB:
			if db := strings.TrimSpace(string(payload[1:])); db != "" {
				state.dbName = db
			}
			_, _, sess, isReplay := h.resolveSocketSession(ctx, oc.SockCookie, rawStart, rawEnd)
			if isReplay || sess != nil || state.upConn == nil {
				if _, err := oc.ClientConn.Write(encodeMySQLOKPacket(1, 0, 0)); err != nil {
					return err
				}
				continue
			}
			if err := h.relaySinglePacketCommand(oc, state, rawPkt); err != nil {
				return err
			}

		case mysqlComPing, mysqlComStmtReset:
			_, _, sess, isReplay := h.resolveSocketSession(ctx, oc.SockCookie, rawStart, rawEnd)
			if isReplay || sess != nil || state.upConn == nil {
				if _, err := oc.ClientConn.Write(encodeMySQLOKPacket(1, 0, 0)); err != nil {
					return err
				}
				continue
			}
			if err := h.relaySinglePacketCommand(oc, state, rawPkt); err != nil {
				return err
			}

		case mysqlComQuery:
			if err := h.handleComQuery(ctx, oc, state, string(payload[1:]), rawPkt, rawStart, rawEnd); err != nil {
				return err
			}

		case mysqlComStmtPrepare:
			if err := h.handleStmtPrepare(ctx, oc, state, string(payload[1:]), rawPkt, rawStart, rawEnd); err != nil {
				return err
			}

		case mysqlComStmtExecute:
			if err := h.handleStmtExecute(ctx, oc, state, payload, rawPkt, rawStart, rawEnd); err != nil {
				return err
			}

		default:
			_, _, sess, isReplay := h.resolveSocketSession(ctx, oc.SockCookie, rawStart, rawEnd)
			if isReplay || sess != nil {
				if _, err := oc.ClientConn.Write(encodeMySQLOKPacket(1, 0, 0)); err != nil {
					return err
				}
				continue
			}
			if err := h.relaySinglePacketCommand(oc, state, rawPkt); err != nil {
				return err
			}
		}
	}
}

func (h *MySQLProtocolHandler) relaySinglePacketCommand(oc OutgoingConnectionContext, state *mysqlConnState, rawPkt []byte) error {
	if state.upConn == nil {
		_, err := oc.ClientConn.Write(encodeMySQLOKPacket(1, 0, 0))
		return err
	}
	h.stats.LiveForwards.Add(1)
	if _, err := state.upConn.Write(rawPkt); err != nil {
		_ = state.upConn.Close()
		state.upConn = nil
		return err
	}
	_, _, respRaw, err := readMySQLWirePacket(state.upConn)
	if err != nil {
		_ = state.upConn.Close()
		state.upConn = nil
		return err
	}
	_, err = oc.ClientConn.Write(respRaw)
	return err
}

func (h *MySQLProtocolHandler) handleComQuery(
	ctx context.Context,
	oc OutgoingConnectionContext,
	state *mysqlConnState,
	sqlText string,
	rawPkt []byte,
	rawStart uint64,
	rawEnd uint64,
) error {
	traceID, serverSpanID, sess, isReplay := h.resolveSocketSession(ctx, oc.SockCookie, rawStart, rawEnd)
	if !isReplay || sess == nil {
		h.exchangeCache.BeginInFlightDB()
		wireResp, res, err := h.forwardQueryLive(ctx, oc.OrigDst, state, rawPkt)
		if err != nil {
			h.exchangeCache.EndInFlightDB()
			_, _ = oc.ClientConn.Write(encodeMySQLErrPacket(1, 2006, "08S01", err.Error()))
			return err
		}
		if res != nil && len(res.Columns) > 0 {
			h.metadataCache.Add(NormalizeSQL(sqlText), slices.Clone(res.Columns))
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

	if isSessionControlSQL(sqlText) {
		_, err := oc.ClientConn.Write(encodeSyntheticMySQLSessionReply(sqlText, state.dbName, state.deprecateEOF))
		return err
	}

	qOut, res, skipLive, errMsg := h.queryDatabaseMock(ctx, oc, sess, serverSpanID, state.dbName, sqlText, nil)
	if skipLive {
		wireResp, _, err := h.forwardQueryLive(ctx, oc.OrigDst, state, rawPkt)
		if err != nil {
			_, _ = oc.ClientConn.Write(encodeMySQLErrPacket(1, 2006, "08S01", err.Error()))
			return err
		}
		_, err = oc.ClientConn.Write(wireResp)
		return err
	}
	if qOut == QueryOutcomeMustMock {
		_, err := oc.ClientConn.Write(encodeMySQLErrPacket(1, 1105, "HY000", "softprobe mustMock miss"))
		return err
	}
	if errMsg != "" || res == nil {
		if errMsg == "" {
			errMsg = "softprobe replay mock miss"
		}
		_, err := oc.ClientConn.Write(encodeMySQLErrPacket(1, 1105, "HY000", errMsg))
		return err
	}
	_, err := oc.ClientConn.Write(encodeMySQLResultResponse(state.dbName, res, false, state.deprecateEOF))
	return err
}

func (h *MySQLProtocolHandler) handleStmtPrepare(
	ctx context.Context,
	oc OutgoingConnectionContext,
	state *mysqlConnState,
	sqlText string,
	rawPkt []byte,
	rawStart uint64,
	rawEnd uint64,
) error {
	_, _, sess, isReplay := h.resolveSocketSession(ctx, oc.SockCookie, rawStart, rawEnd)
	if isReplay || sess != nil {
		return h.replySyntheticStmtPrepare(oc, state, sqlText)
	}

	upConn, err := h.ensureUpstream(ctx, oc.OrigDst, state)
	if err != nil {
		return h.replySyntheticStmtPrepare(oc, state, sqlText)
	}

	h.stats.LiveForwards.Add(1)
	if _, err := upConn.Write(rawPkt); err != nil {
		_ = upConn.Close()
		state.upConn = nil
		return h.replySyntheticStmtPrepare(oc, state, sqlText)
	}

	firstPayload, _, firstRaw, err := readMySQLWirePacket(upConn)
	if err != nil {
		_ = upConn.Close()
		state.upConn = nil
		return err
	}
	var wireResp bytes.Buffer
	wireResp.Write(firstRaw)

	if len(firstPayload) == 0 || firstPayload[0] == 0xff {
		_, err = oc.ClientConn.Write(wireResp.Bytes())
		return err
	}
	if firstPayload[0] != 0x00 || len(firstPayload) < 9 {
		_, err = oc.ClientConn.Write(wireResp.Bytes())
		return err
	}

	stmtID := binary.LittleEndian.Uint32(firstPayload[1:5])
	numCols := int(binary.LittleEndian.Uint16(firstPayload[5:7]))
	numParams := int(binary.LittleEndian.Uint16(firstPayload[7:9]))

	if numParams > 0 {
		for range numParams {
			_, _, pRaw, rErr := readMySQLWirePacket(upConn)
			if rErr != nil {
				return rErr
			}
			wireResp.Write(pRaw)
		}
		if !state.deprecateEOF {
			_, _, eofRaw, rErr := readMySQLWirePacket(upConn)
			if rErr != nil {
				return rErr
			}
			wireResp.Write(eofRaw)
		}
	}

	var cols []DatabaseColumn
	if numCols > 0 {
		cols = make([]DatabaseColumn, 0, numCols)
		for range numCols {
			cPayload, _, cRaw, rErr := readMySQLWirePacket(upConn)
			if rErr != nil {
				return rErr
			}
			wireResp.Write(cRaw)
			if col, ok := parseMySQLColumnDef(cPayload); ok {
				cols = append(cols, col)
			}
		}
		if !state.deprecateEOF {
			_, _, eofRaw, rErr := readMySQLWirePacket(upConn)
			if rErr != nil {
				return rErr
			}
			wireResp.Write(eofRaw)
		}
	}

	if len(cols) > 0 {
		h.metadataCache.Add(NormalizeSQL(sqlText), slices.Clone(cols))
	}
	state.preparedStmts[stmtID] = &mysqlPreparedStmt{
		id:        stmtID,
		sql:       sqlText,
		numParams: numParams,
		columns:   cols,
	}

	_, err = oc.ClientConn.Write(wireResp.Bytes())
	return err
}

func (h *MySQLProtocolHandler) replySyntheticStmtPrepare(
	oc OutgoingConnectionContext,
	state *mysqlConnState,
	sqlText string,
) error {
	stmtID := state.nextSyntheticStmtID
	state.nextSyntheticStmtID++
	numParams := countMySQLPlaceholders(sqlText)
	var cols []DatabaseColumn
	if cached, ok := h.metadataCache.Get(NormalizeSQL(sqlText)); ok {
		cols = slices.Clone(cached)
	}
	state.preparedStmts[stmtID] = &mysqlPreparedStmt{
		id:        stmtID,
		sql:       sqlText,
		numParams: numParams,
		columns:   cols,
	}
	_, err := oc.ClientConn.Write(encodeMySQLStmtPrepareOK(stmtID, numParams, state.dbName, state.deprecateEOF))
	return err
}

func (h *MySQLProtocolHandler) handleStmtExecute(
	ctx context.Context,
	oc OutgoingConnectionContext,
	state *mysqlConnState,
	payload []byte,
	rawPkt []byte,
	rawStart uint64,
	rawEnd uint64,
) error {
	if len(payload) < 10 {
		_, err := oc.ClientConn.Write(encodeMySQLErrPacket(1, 1210, "HY000", "malformed COM_STMT_EXECUTE"))
		return err
	}
	stmtID := binary.LittleEndian.Uint32(payload[1:5])
	st := state.preparedStmts[stmtID]

	var params []any
	if st != nil && st.numParams > 0 {
		params = decodeMySQLStmtExecuteParams(payload, st)
	}

	traceID, serverSpanID, sess, isReplay := h.resolveSocketSession(ctx, oc.SockCookie, rawStart, rawEnd)
	if !isReplay || sess == nil {
		h.exchangeCache.BeginInFlightDB()
		wireResp, res, err := h.forwardQueryLive(ctx, oc.OrigDst, state, rawPkt)
		if err != nil {
			h.exchangeCache.EndInFlightDB()
			_, _ = oc.ClientConn.Write(encodeMySQLErrPacket(1, 2006, "08S01", err.Error()))
			return err
		}
		if st != nil && res != nil {
			if len(res.Columns) > 0 {
				st.columns = slices.Clone(res.Columns)
				h.metadataCache.Add(NormalizeSQL(st.sql), slices.Clone(res.Columns))
			}
			if traceID == ([16]byte{}) {
				traceID = h.resolvePostForwardTrace(ctx, oc.SockCookie, rawStart, rawEnd)
			}
			clientPort := remoteTCPPort(oc.ClientConn)
			if (traceID != ([16]byte{}) || clientPort != 0) && h.exchangeCache != nil && !isSessionControlSQL(st.sql) {
				h.exchangeCache.RecordDatabase(traceID, CapturedDatabaseExchange{
					ClientPort: clientPort,
					DBName:     state.dbName,
					StmtName:   strconv.FormatUint(uint64(stmtID), 10),
					SQL:        st.sql,
					Parameters: params,
					Result:     res,
				})
			}
		}
		h.exchangeCache.EndInFlightDB()
		_, err = oc.ClientConn.Write(wireResp)
		return err
	}

	if st == nil {
		_, err := oc.ClientConn.Write(encodeMySQLErrPacket(1, 1243, "HY000", "unknown prepared statement"))
		return err
	}
	if isSessionControlSQL(st.sql) {
		_, err := oc.ClientConn.Write(encodeMySQLOKPacket(1, 0, 0))
		return err
	}

	qOut, res, skipLive, errMsg := h.queryDatabaseMock(ctx, oc, sess, serverSpanID, state.dbName, st.sql, params)
	if skipLive {
		wireResp, _, err := h.forwardQueryLive(ctx, oc.OrigDst, state, rawPkt)
		if err != nil {
			_, _ = oc.ClientConn.Write(encodeMySQLErrPacket(1, 2006, "08S01", err.Error()))
			return err
		}
		_, err = oc.ClientConn.Write(wireResp)
		return err
	}
	if qOut == QueryOutcomeMustMock {
		_, err := oc.ClientConn.Write(encodeMySQLErrPacket(1, 1105, "HY000", "softprobe mustMock miss"))
		return err
	}
	if errMsg != "" || res == nil {
		if errMsg == "" {
			errMsg = "softprobe replay mock miss"
		}
		_, err := oc.ClientConn.Write(encodeMySQLErrPacket(1, 1105, "HY000", errMsg))
		return err
	}

	if len(st.columns) > 0 {
		if len(res.Columns) == 0 {
			res.Columns = slices.Clone(st.columns)
		} else {
			for i := range res.Columns {
				if i < len(st.columns) {
					if res.Columns[i].MySQLType == 0 {
						res.Columns[i].MySQLType = st.columns[i].MySQLType
					}
					if res.Columns[i].MySQLFlags == 0 {
						res.Columns[i].MySQLFlags = st.columns[i].MySQLFlags
					}
					if res.Columns[i].MySQLCharset == 0 {
						res.Columns[i].MySQLCharset = st.columns[i].MySQLCharset
					}
				}
			}
		}
	}

	_, err := oc.ClientConn.Write(encodeMySQLResultResponse(state.dbName, res, true, state.deprecateEOF))
	return err
}

func (h *MySQLProtocolHandler) forwardQueryLive(
	ctx context.Context,
	origDst netip.AddrPort,
	state *mysqlConnState,
	rawPkt []byte,
) ([]byte, *DatabaseResult, error) {
	upConn, err := h.ensureUpstream(ctx, origDst, state)
	if err != nil {
		return nil, nil, err
	}
	h.stats.LiveForwards.Add(1)
	if _, err := upConn.Write(rawPkt); err != nil {
		_ = upConn.Close()
		state.upConn = nil
		return nil, nil, err
	}
	wireResp, err := readMySQLCommandResponse(upConn, state.deprecateEOF)
	if err != nil {
		_ = upConn.Close()
		state.upConn = nil
		return nil, nil, err
	}
	return wireResp, ParseMySQLWireResponse(wireResp), nil
}

func readMySQLCommandResponse(r io.Reader, deprecateEOF bool) ([]byte, error) {
	firstPayload, _, firstRaw, err := readMySQLWirePacket(r)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.Write(firstRaw)
	if len(firstPayload) == 0 || firstPayload[0] == 0x00 || firstPayload[0] == 0xff {
		return out.Bytes(), nil
	}

	colCountU64, _, ok := readMySQLLenEncInt(firstPayload, 0)
	if !ok || colCountU64 == 0 {
		return out.Bytes(), nil
	}
	colCount := int(colCountU64)
	for range colCount {
		_, _, colRaw, rErr := readMySQLWirePacket(r)
		if rErr != nil {
			return nil, rErr
		}
		out.Write(colRaw)
	}
	if !deprecateEOF {
		eofPayload, _, eofRaw, rErr := readMySQLWirePacket(r)
		if rErr != nil {
			return nil, rErr
		}
		out.Write(eofRaw)
		if len(eofPayload) > 0 && eofPayload[0] == 0xff {
			return out.Bytes(), nil
		}
	}
	for {
		rowPayload, _, rowRaw, rErr := readMySQLWirePacket(r)
		if rErr != nil {
			return nil, rErr
		}
		out.Write(rowRaw)
		if len(rowPayload) == 0 {
			continue
		}
		if rowPayload[0] == 0xff {
			break
		}
		if rowPayload[0] == 0xfe && len(rowPayload) < 0xffffff {
			if !deprecateEOF && len(rowPayload) < 9 {
				break
			}
			if deprecateEOF {
				break
			}
		}
	}
	return out.Bytes(), nil
}

func (h *MySQLProtocolHandler) queryDatabaseMock(
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
		h.emitReplayLog(sess, serverSpanID, "WARN", "softprobe replay query failed MySQL "+dbName)
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
		h.emitReplayLog(sess, serverSpanID, "INFO", "softprobe replay mock hit MySQL "+dbName)
		return QueryOutcomeHit, decoded, false, ""

	case QueryOutcomeMustMock:
		h.stats.MustMockBlocks.Add(1)
		h.emitReplayLog(sess, serverSpanID, "WARN", "softprobe replay MUST_MOCK blocked MySQL "+dbName)
		return QueryOutcomeMustMock, nil, false, "softprobe mustMock miss"

	case QueryOutcomeSkipMock:
		h.stats.SkipMockForwards.Add(1)
		h.emitReplayLog(sess, serverSpanID, "INFO", "softprobe replay skip-mock forwarded MySQL "+dbName)
		return QueryOutcomeSkipMock, nil, true, ""

	default:
		if localIgnored {
			h.stats.SkipMockForwards.Add(1)
			return QueryOutcomeSkipMock, nil, true, ""
		}
		h.stats.EmptyMissBlocks.Add(1)
		h.emitReplayLog(sess, serverSpanID, "WARN", "softprobe replay mock miss MySQL "+dbName)
		return QueryOutcomeEmptyMiss, nil, false, "softprobe replay mock miss"
	}
}

func (h *MySQLProtocolHandler) emitReplayLog(sess *ReplaySession, spanID [8]byte, severity, body string) {
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

func (h *MySQLProtocolHandler) ensureUpstream(ctx context.Context, origDst netip.AddrPort, state *mysqlConnState) (net.Conn, error) {
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

func (h *MySQLProtocolHandler) dialUpstream(ctx context.Context, origDst netip.AddrPort) (net.Conn, error) {
	if !origDst.IsValid() {
		return nil, errors.New("missing original destination for mysql upstream")
	}
	h.stats.UpstreamDials.Add(1)
	return h.dialContext(ctx, "tcp", origDst.String())
}

func (h *MySQLProtocolHandler) resolveSocketSession(
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

func (h *MySQLProtocolHandler) resolvePostForwardTrace(
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

func readMySQLWirePacket(r io.Reader) ([]byte, uint8, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, 0, nil, err
	}
	pktLen := int(uint32(hdr[0]) | uint32(hdr[1])<<8 | uint32(hdr[2])<<16)
	seq := hdr[3]
	if pktLen < 0 || pktLen > maxMySQLPacketBytes {
		return nil, 0, nil, fmt.Errorf("invalid mysql packet length %d", pktLen)
	}
	raw := make([]byte, 4+pktLen)
	copy(raw[:4], hdr[:])
	if pktLen > 0 {
		if _, err := io.ReadFull(r, raw[4:]); err != nil {
			return nil, 0, nil, err
		}
	}
	if pktLen < 0xffffff {
		return raw[4:], seq, raw, nil
	}

	var fullPayload bytes.Buffer
	var fullRaw bytes.Buffer
	fullPayload.Write(raw[4:])
	fullRaw.Write(raw)
	for pktLen == 0xffffff {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return nil, 0, nil, err
		}
		pktLen = int(uint32(hdr[0]) | uint32(hdr[1])<<8 | uint32(hdr[2])<<16)
		seq = hdr[3]
		if fullPayload.Len()+pktLen > maxMySQLPacketBytes {
			return nil, 0, nil, errors.New("mysql multi-packet payload exceeds limit")
		}
		chunk := make([]byte, pktLen)
		if pktLen > 0 {
			if _, err := io.ReadFull(r, chunk); err != nil {
				return nil, 0, nil, err
			}
		}
		fullRaw.Write(hdr[:])
		fullRaw.Write(chunk)
		fullPayload.Write(chunk)
	}
	return fullPayload.Bytes(), seq, fullRaw.Bytes(), nil
}

func encodeMySQLWirePacket(seq uint8, payload []byte) []byte {
	var out bytes.Buffer
	rem := payload
	for len(rem) >= 0xffffff {
		out.WriteByte(0xff)
		out.WriteByte(0xff)
		out.WriteByte(0xff)
		out.WriteByte(seq)
		seq++
		out.Write(rem[:0xffffff])
		rem = rem[0xffffff:]
	}
	pktLen := len(rem)
	out.WriteByte(byte(pktLen))
	out.WriteByte(byte(pktLen >> 8))
	out.WriteByte(byte(pktLen >> 16))
	out.WriteByte(seq)
	if pktLen > 0 {
		out.Write(rem)
	}
	return out.Bytes()
}

func writeMySQLLenEncInt(buf *bytes.Buffer, v uint64) {
	switch {
	case v < 0xfb:
		buf.WriteByte(byte(v))
	case v <= 0xffff:
		buf.WriteByte(0xfc)
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], uint16(v))
		buf.Write(b[:])
	case v <= 0xffffff:
		buf.WriteByte(0xfd)
		buf.WriteByte(byte(v))
		buf.WriteByte(byte(v >> 8))
		buf.WriteByte(byte(v >> 16))
	default:
		buf.WriteByte(0xfe)
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], v)
		buf.Write(b[:])
	}
}

func writeMySQLLenEncString(buf *bytes.Buffer, s string) {
	writeMySQLLenEncInt(buf, uint64(len(s)))
	buf.WriteString(s)
}

func encodeMySQLOKPacket(seq uint8, rowsAffected, lastInsertID int64) []byte {
	var p bytes.Buffer
	p.WriteByte(0x00)
	writeMySQLLenEncInt(&p, uint64(max(rowsAffected, 0)))
	writeMySQLLenEncInt(&p, uint64(max(lastInsertID, 0)))
	p.WriteByte(0x02)
	p.WriteByte(0x00)
	p.WriteByte(0x00)
	p.WriteByte(0x00)
	return encodeMySQLWirePacket(seq, p.Bytes())
}

func encodeMySQLEOFPacket(seq uint8, deprecateEOF bool) []byte {
	if deprecateEOF {
		return encodeMySQLWirePacket(seq, []byte{0xfe, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
	}
	return encodeMySQLWirePacket(seq, []byte{0xfe, 0x00, 0x00, 0x02, 0x00})
}

//nolint:unparam // sequence number follows MySQL packet framing conventions
func encodeMySQLErrPacket(seq uint8, errCode uint16, sqlState, message string) []byte {
	if len(sqlState) != 5 {
		sqlState = "HY000"
	}
	var p bytes.Buffer
	p.WriteByte(0xff)
	var code [2]byte
	binary.LittleEndian.PutUint16(code[:], errCode)
	p.Write(code[:])
	p.WriteByte('#')
	p.WriteString(sqlState)
	p.WriteString(message)
	return encodeMySQLWirePacket(seq, p.Bytes())
}

func encodeMySQLColumnDefPacket(seq uint8, schema string, col DatabaseColumn) []byte {
	colType := col.MySQLType
	if colType == 0 {
		colType = mysqlTypeVarString
	}
	charset := col.MySQLCharset
	if charset == 0 {
		charset = mysqlCharsetUTF8
	}
	var p bytes.Buffer
	writeMySQLLenEncString(&p, "def")
	writeMySQLLenEncString(&p, schema)
	writeMySQLLenEncString(&p, "")
	writeMySQLLenEncString(&p, "")
	writeMySQLLenEncString(&p, col.Name)
	writeMySQLLenEncString(&p, col.Name)
	p.WriteByte(0x0c)

	var fixed [12]byte
	binary.LittleEndian.PutUint16(fixed[0:2], charset)
	binary.LittleEndian.PutUint32(fixed[2:6], 1024)
	fixed[6] = colType
	binary.LittleEndian.PutUint16(fixed[7:9], col.MySQLFlags)
	fixed[9] = 0
	p.Write(fixed[:])
	return encodeMySQLWirePacket(seq, p.Bytes())
}

func encodeMySQLStmtPrepareOK(stmtID uint32, numParams int, schema string, deprecateEOF bool) []byte {
	var out bytes.Buffer
	var okBody [12]byte
	okBody[0] = 0x00
	binary.LittleEndian.PutUint32(okBody[1:5], stmtID)
	binary.LittleEndian.PutUint16(okBody[5:7], 0)
	binary.LittleEndian.PutUint16(okBody[7:9], uint16(numParams))
	okBody[9] = 0
	binary.LittleEndian.PutUint16(okBody[10:12], 0)

	seq := uint8(1)
	out.Write(encodeMySQLWirePacket(seq, okBody[:]))
	seq++

	if numParams > 0 {
		for range numParams {
			out.Write(encodeMySQLColumnDefPacket(seq, schema, DatabaseColumn{
				Name:         "?",
				MySQLType:    mysqlTypeVarString,
				MySQLCharset: mysqlCharsetUTF8,
			}))
			seq++
		}
		if !deprecateEOF {
			out.Write(encodeMySQLEOFPacket(seq, false))
		}
	}
	return out.Bytes()
}

func decodeMySQLStmtExecuteParams(payload []byte, st *mysqlPreparedStmt) []any {
	if len(payload) < 10 || st == nil || st.numParams <= 0 {
		return nil
	}
	numParams := st.numParams
	pos := 10
	nullBitmapLen := (numParams + 7) / 8
	if pos+nullBitmapLen+1 > len(payload) {
		return nil
	}
	nullBitmap := payload[pos : pos+nullBitmapLen]
	pos += nullBitmapLen

	newParamsBound := payload[pos]
	pos++
	if newParamsBound == 1 {
		if pos+numParams*2 > len(payload) {
			return nil
		}
		types := make([]mysqlParamType, numParams)
		for i := range numParams {
			types[i] = mysqlParamType{
				fieldType: payload[pos+i*2],
				unsigned:  (payload[pos+i*2+1] & 0x80) != 0,
			}
		}
		st.paramTypes = types
		pos += numParams * 2
	}

	params := make([]any, 0, numParams)
	for i := range numParams {
		if (nullBitmap[i/8] & (1 << (i % 8))) != 0 {
			params = append(params, nil)
			continue
		}
		pType := mysqlParamType{fieldType: mysqlTypeVarString}
		if i < len(st.paramTypes) {
			pType = st.paramTypes[i]
		}
		val, nextPos, ok := decodeMySQLBinaryValue(payload, pos, pType.fieldType, pType.unsigned)
		if !ok {
			return params
		}
		params = append(params, val)
		pos = nextPos
	}
	return params
}

func countMySQLPlaceholders(sql string) int {
	count := 0
	var quote byte
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if quote != 0 {
			if c == '\\' && i+1 < len(sql) {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote = c
			continue
		}
		if c == '?' {
			count++
		}
	}
	return count
}

func encodeSyntheticMySQLSessionReply(sqlText, schema string, deprecateEOF bool) []byte {
	upper := strings.ToUpper(NormalizeSQL(strings.TrimSpace(sqlText)))
	if strings.HasPrefix(upper, "SELECT ") || strings.HasPrefix(upper, "SHOW ") {
		res := &DatabaseResult{
			Columns: []DatabaseColumn{{Name: "Value", MySQLType: mysqlTypeVarString, MySQLCharset: mysqlCharsetUTF8}},
			Rows:    [][]any{{"8.0.36-softprobe"}},
		}
		return encodeMySQLResultResponse(schema, res, false, deprecateEOF)
	}
	return encodeMySQLOKPacket(1, 0, 0)
}

func encodeMySQLResultResponse(schema string, res *DatabaseResult, binaryRows bool, deprecateEOF bool) []byte {
	if res.ErrorMessage != "" {
		code := uint16(1105)
		if parsed, err := strconv.Atoi(res.ErrorCode); err == nil && parsed > 0 && parsed <= 65535 {
			code = uint16(parsed)
		}
		return encodeMySQLErrPacket(1, code, "HY000", res.ErrorMessage)
	}
	if len(res.Columns) == 0 {
		return encodeMySQLOKPacket(1, res.RowsAffected, res.LastInsertID)
	}

	var out bytes.Buffer
	seq := uint8(1)

	var cntBuf bytes.Buffer
	writeMySQLLenEncInt(&cntBuf, uint64(len(res.Columns)))
	out.Write(encodeMySQLWirePacket(seq, cntBuf.Bytes()))
	seq++

	for _, col := range res.Columns {
		out.Write(encodeMySQLColumnDefPacket(seq, schema, col))
		seq++
	}
	if !deprecateEOF {
		out.Write(encodeMySQLEOFPacket(seq, false))
		seq++
	}

	for _, row := range res.Rows {
		var rowPayload []byte
		if binaryRows {
			rowPayload = encodeMySQLBinaryRowPayload(row, res.Columns)
		} else {
			rowPayload = encodeMySQLTextRowPayload(row, len(res.Columns))
		}
		out.Write(encodeMySQLWirePacket(seq, rowPayload))
		seq++
	}

	out.Write(encodeMySQLEOFPacket(seq, deprecateEOF))
	return out.Bytes()
}

func encodeMySQLTextRowPayload(row []any, colCount int) []byte {
	var p bytes.Buffer
	for i := range colCount {
		var val any
		if i < len(row) {
			val = row[i]
		}
		if val == nil {
			p.WriteByte(0xfb)
			continue
		}
		writeMySQLLenEncString(&p, scalarToString(val))
	}
	return p.Bytes()
}

func encodeMySQLBinaryRowPayload(row []any, cols []DatabaseColumn) []byte {
	colCount := len(cols)
	nullBitmapLen := (colCount + 7 + 2) / 8
	nullBitmap := make([]byte, nullBitmapLen)

	var valuesBuf bytes.Buffer
	for i, col := range cols {
		var val any
		if i < len(row) {
			val = row[i]
		}
		if val == nil {
			bitPos := i + 2
			nullBitmap[bitPos/8] |= 1 << (bitPos % 8)
			continue
		}
		colType := col.MySQLType
		if colType == 0 {
			colType = mysqlTypeVarString
		}
		unsigned := (col.MySQLFlags & mysqlFlagUnsigned) != 0
		encodeMySQLBinaryValue(&valuesBuf, val, colType, unsigned)
	}

	var p bytes.Buffer
	p.WriteByte(0x00)
	p.Write(nullBitmap)
	p.Write(valuesBuf.Bytes())
	return p.Bytes()
}

func encodeMySQLBinaryValue(buf *bytes.Buffer, val any, colType uint8, unsigned bool) {
	strVal := scalarToString(val)
	switch colType {
	case mysqlTypeTiny:
		if unsigned {
			n, _ := strconv.ParseUint(strings.TrimSpace(strVal), 10, 8)
			buf.WriteByte(byte(n))
		} else {
			n, _ := strconv.ParseInt(strings.TrimSpace(strVal), 10, 8)
			buf.WriteByte(byte(int8(n)))
		}
	case mysqlTypeShort, mysqlTypeYear:
		var b [2]byte
		if unsigned || colType == mysqlTypeYear {
			n, _ := strconv.ParseUint(strings.TrimSpace(strVal), 10, 16)
			binary.LittleEndian.PutUint16(b[:], uint16(n))
		} else {
			n, _ := strconv.ParseInt(strings.TrimSpace(strVal), 10, 16)
			binary.LittleEndian.PutUint16(b[:], uint16(int16(n)))
		}
		buf.Write(b[:])
	case mysqlTypeLong, mysqlTypeInt24:
		var b [4]byte
		if unsigned {
			n, _ := strconv.ParseUint(strings.TrimSpace(strVal), 10, 32)
			binary.LittleEndian.PutUint32(b[:], uint32(n))
		} else {
			n, _ := strconv.ParseInt(strings.TrimSpace(strVal), 10, 32)
			binary.LittleEndian.PutUint32(b[:], uint32(int32(n)))
		}
		buf.Write(b[:])
	case mysqlTypeLongLong:
		var b [8]byte
		if unsigned {
			n, _ := strconv.ParseUint(strings.TrimSpace(strVal), 10, 64)
			binary.LittleEndian.PutUint64(b[:], n)
		} else {
			n, _ := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64)
			binary.LittleEndian.PutUint64(b[:], uint64(n))
		}
		buf.Write(b[:])
	case mysqlTypeFloat:
		f, _ := strconv.ParseFloat(strings.TrimSpace(strVal), 32)
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], math.Float32bits(float32(f)))
		buf.Write(b[:])
	case mysqlTypeDouble:
		f, _ := strconv.ParseFloat(strings.TrimSpace(strVal), 64)
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], math.Float64bits(f))
		buf.Write(b[:])
	case mysqlTypeDate:
		if t, err := time.Parse("2006-01-02", strings.TrimSpace(strVal)); err == nil {
			var b [5]byte
			b[0] = 4
			binary.LittleEndian.PutUint16(b[1:3], uint16(t.Year()))
			b[3] = byte(t.Month())
			b[4] = byte(t.Day())
			buf.Write(b[:])
			return
		}
		buf.WriteByte(0)
	case mysqlTypeDatetime, mysqlTypeTimestamp:
		if t, ok := parseFlexibleTimestamp(strVal); ok {
			usec := uint32(t.Nanosecond() / 1000)
			if usec > 0 {
				var b [12]byte
				b[0] = 11
				binary.LittleEndian.PutUint16(b[1:3], uint16(t.Year()))
				b[3] = byte(t.Month())
				b[4] = byte(t.Day())
				b[5] = byte(t.Hour())
				b[6] = byte(t.Minute())
				b[7] = byte(t.Second())
				binary.LittleEndian.PutUint32(b[8:12], usec)
				buf.Write(b[:])
				return
			}
			var b [8]byte
			b[0] = 7
			binary.LittleEndian.PutUint16(b[1:3], uint16(t.Year()))
			b[3] = byte(t.Month())
			b[4] = byte(t.Day())
			b[5] = byte(t.Hour())
			b[6] = byte(t.Minute())
			b[7] = byte(t.Second())
			buf.Write(b[:])
			return
		}
		buf.WriteByte(0)
	default:
		writeMySQLLenEncString(buf, strVal)
	}
}
