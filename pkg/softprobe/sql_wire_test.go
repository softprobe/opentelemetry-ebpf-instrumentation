// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

type egressRouteMap struct {
	mu     sync.RWMutex
	routes map[string]EgressTarget
}

func newEgressRouteMap() *egressRouteMap {
	return &egressRouteMap{
		routes: make(map[string]EgressTarget),
	}
}

func (m *egressRouteMap) register(localAddr net.Addr, target EgressTarget) {
	m.mu.Lock()
	m.routes[localAddr.String()] = target
	m.mu.Unlock()
}

func (m *egressRouteMap) lookup(remoteAddr net.Addr) (EgressTarget, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.routes[remoteAddr.String()]
	return t, ok
}

func tryDialTrackedEgress(egressAddr net.Addr, routes *egressRouteMap, target EgressTarget) (net.Conn, error) {
	var d net.Dialer
	d.SetMultipathTCP(false)
	localTCP, err := net.ResolveTCPAddr("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	lnProbe, err := net.ListenTCP("tcp4", localTCP)
	if err != nil {
		return nil, err
	}
	reservedAddr := lnProbe.Addr().(*net.TCPAddr)
	if err := lnProbe.Close(); err != nil {
		return nil, err
	}

	d.LocalAddr = reservedAddr
	routes.register(reservedAddr, target)
	return d.Dial("tcp4", egressAddr.String())
}

func dialTrackedEgress(t *testing.T, egressAddr net.Addr, routes *egressRouteMap, target EgressTarget) net.Conn {
	t.Helper()
	conn, err := tryDialTrackedEgress(egressAddr, routes, target)
	require.NoError(t, err)
	return conn
}

func buildPGStartupFrame(dbName, user string) []byte {
	var body bytes.Buffer
	var proto [4]byte
	binary.BigEndian.PutUint32(proto[:], pgProtocolVersion30)
	body.Write(proto[:])
	body.WriteString("user")
	body.WriteByte(0)
	body.WriteString(user)
	body.WriteByte(0)
	body.WriteString("database")
	body.WriteByte(0)
	body.WriteString(dbName)
	body.WriteByte(0)
	body.WriteByte(0)

	out := make([]byte, 4+body.Len())
	binary.BigEndian.PutUint32(out[0:4], uint32(len(out)))
	copy(out[4:], body.Bytes())
	return out
}

func buildPGSSLRequestFrame() []byte {
	var out [8]byte
	binary.BigEndian.PutUint32(out[0:4], 8)
	binary.BigEndian.PutUint32(out[4:8], pgSSLRequestCode)
	return out[:]
}

func buildPGSimpleQueryFrame(sql string) []byte {
	payload := append([]byte(sql), 0)
	var buf bytes.Buffer
	writePGMsg(&buf, 'Q', payload)
	return buf.Bytes()
}

func buildPGParseFrame(stmtName, sql string, paramOIDs []uint32) []byte {
	var p bytes.Buffer
	p.WriteString(stmtName)
	p.WriteByte(0)
	p.WriteString(sql)
	p.WriteByte(0)
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], uint16(len(paramOIDs)))
	p.Write(cnt[:])
	for _, oid := range paramOIDs {
		var ob [4]byte
		binary.BigEndian.PutUint32(ob[:], oid)
		p.Write(ob[:])
	}
	var out bytes.Buffer
	writePGMsg(&out, 'P', p.Bytes())
	return out.Bytes()
}

//nolint:unparam // portalName follows PostgreSQL Bind message framing
func buildPGBindFrame(portalName, stmtName string, paramFormats []int16, paramValues [][]byte, resultFormats []int16) []byte {
	var p bytes.Buffer
	p.WriteString(portalName)
	p.WriteByte(0)
	p.WriteString(stmtName)
	p.WriteByte(0)

	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(paramFormats)))
	p.Write(u16[:])
	for _, f := range paramFormats {
		binary.BigEndian.PutUint16(u16[:], uint16(f))
		p.Write(u16[:])
	}

	binary.BigEndian.PutUint16(u16[:], uint16(len(paramValues)))
	p.Write(u16[:])
	for _, val := range paramValues {
		var u32 [4]byte
		if val == nil {
			binary.BigEndian.PutUint32(u32[:], 0xffffffff)
			p.Write(u32[:])
			continue
		}
		binary.BigEndian.PutUint32(u32[:], uint32(len(val)))
		p.Write(u32[:])
		p.Write(val)
	}

	binary.BigEndian.PutUint16(u16[:], uint16(len(resultFormats)))
	p.Write(u16[:])
	for _, f := range resultFormats {
		binary.BigEndian.PutUint16(u16[:], uint16(f))
		p.Write(u16[:])
	}

	var out bytes.Buffer
	writePGMsg(&out, 'B', p.Bytes())
	return out.Bytes()
}

func buildPGDescribeFrame(target byte, name string) []byte {
	var p bytes.Buffer
	p.WriteByte(target)
	p.WriteString(name)
	p.WriteByte(0)
	var out bytes.Buffer
	writePGMsg(&out, 'D', p.Bytes())
	return out.Bytes()
}

//nolint:unparam // portalName follows PostgreSQL Execute message framing
func buildPGExecuteFrame(portalName string, maxRows uint32) []byte {
	var p bytes.Buffer
	p.WriteString(portalName)
	p.WriteByte(0)
	var mr [4]byte
	binary.BigEndian.PutUint32(mr[:], maxRows)
	p.Write(mr[:])
	var out bytes.Buffer
	writePGMsg(&out, 'E', p.Bytes())
	return out.Bytes()
}

func buildPGSyncFrame() []byte {
	var out bytes.Buffer
	writePGMsg(&out, 'S', nil)
	return out.Bytes()
}

func readPGUntilReadyForQuery(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var wire bytes.Buffer
	for {
		msgType, _, raw, err := readPostgresFrame(r)
		require.NoError(t, err)
		wire.Write(raw)
		if msgType == 'Z' {
			return wire.Bytes()
		}
	}
}

func TestPostgresSimpleAndExtendedOfflineReplay(t *testing.T) {
	ctx := t.Context()

	liveTraceID, err := ParseTraceIDHex("11111111111111111111111111111111")
	require.NoError(t, err)
	replayTraceID, err := ParseTraceIDHex("22222222222222222222222222222222")
	require.NoError(t, err)
	const recordedTraceHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	const extendedSQL = "SELECT id, active, total_cents, code, payload, req_id FROM bookings WHERE id = $1 AND active = $2"
	const simpleSQL = "SELECT name FROM hotels WHERE city = 'SFO'"
	uuidBytes, err := hex.DecodeString("550e8400e29b41d4a716446655440000")
	require.NoError(t, err)
	const uuidStr = "550e8400-e29b-41d4-a716-446655440000"

	pgCols := []DatabaseColumn{
		{Name: "id", TypeOID: pgOIDInt8},
		{Name: "active", TypeOID: pgOIDBool},
		{Name: "total_cents", TypeOID: pgOIDInt4},
		{Name: "code", TypeOID: pgOIDText},
		{Name: "payload", TypeOID: pgOIDJSONB},
		{Name: "req_id", TypeOID: pgOIDUUID},
	}

	pgUpstreamLn, err := ListenNonMPTCP(ctx, "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	pgUpstreamAddr := netip.MustParseAddrPort(pgUpstreamLn.Addr().String())

	go func() {
		conn, acceptErr := pgUpstreamLn.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)

		var lenBuf [4]byte
		if _, rErr := io.ReadFull(br, lenBuf[:]); rErr != nil {
			return
		}
		sLen := int(binary.BigEndian.Uint32(lenBuf[:]))
		rest := make([]byte, sLen-4)
		if _, rErr := io.ReadFull(br, rest); rErr != nil {
			return
		}
		_, _ = conn.Write(buildSyntheticPostgresStartupOK())

		for {
			msgType, _, _, rErr := readPostgresFrame(br)
			if rErr != nil {
				return
			}
			for msgType != 'S' {
				msgType, _, _, rErr = readPostgresFrame(br)
				if rErr != nil {
					return
				}
			}

			var reply bytes.Buffer
			writePGMsg(&reply, '1', nil)
			writePGMsg(&reply, '2', nil)
			reply.Write(encodePGRowDescription(pgCols, []int16{1}))

			var rowFields [][]byte
			var b8 [8]byte
			binary.BigEndian.PutUint64(b8[:], 42)
			rowFields = append(rowFields, slices.Clone(b8[:]))
			rowFields = append(rowFields, []byte{1})
			var b4 [4]byte
			binary.BigEndian.PutUint32(b4[:], 18900)
			rowFields = append(rowFields, slices.Clone(b4[:]))
			rowFields = append(rowFields, []byte("SFO-LAX"))
			rowFields = append(rowFields, append([]byte{1}, []byte(`{"seat":"12A"}`)...))
			rowFields = append(rowFields, uuidBytes)

			var dr bytes.Buffer
			var fc [2]byte
			binary.BigEndian.PutUint16(fc[:], uint16(len(rowFields)))
			dr.Write(fc[:])
			for _, f := range rowFields {
				var fl [4]byte
				binary.BigEndian.PutUint32(fl[:], uint32(len(f)))
				dr.Write(fl[:])
				dr.Write(f)
			}
			writePGMsg(&reply, 'D', dr.Bytes())
			writePGMsg(&reply, 'C', append([]byte("SELECT 1"), 0))
			reply.Write(encodePGReadyForQuery())
			_, _ = conn.Write(reply.Bytes())
		}
	}()

	var queryCount atomic.Int32
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/storage/record/query":
			queryCount.Add(1)
			assert.Equal(t, strconv.Itoa(int(MockStrategyDatabase)), r.Header.Get(HeaderMockStrategyCode))
			raw, rErr := io.ReadAll(r.Body)
			assert.NoError(t, rErr)
			reqMocker := decodePostedMockerForTest(t, raw)
			assert.Equal(t, CategoryDatabase.Name, reqMocker.CategoryType.Name)
			assert.Equal(t, "traveldb", reqMocker.TargetRequest.AttributeString(AttrDBName))

			var res DatabaseResult
			if strings.Contains(reqMocker.TargetRequest.Body, "hotels") {
				res = DatabaseResult{
					Columns: []DatabaseColumn{{Name: "name", TypeOID: pgOIDText}},
					Rows:    [][]any{{"Grand Hyatt SFO"}},
				}
			} else {
				res = DatabaseResult{
					Columns: pgCols,
					Rows: [][]any{{
						float64(42),
						true,
						float64(18900),
						"SFO-LAX",
						`{"seat":"12A"}`,
						uuidStr,
					}},
				}
			}
			hitMocker, mErr := BuildDatabaseMocker(SpanMetadata{
				AppID:   "pg-svc",
				TraceID: recordedTraceHex,
			}, DatabaseExchange{
				DBName: "traveldb",
				SQL:    reqMocker.TargetRequest.Body,
				Result: &res,
			})
			assert.NoError(t, mErr)
			w.Header().Set("Content-Type", "application/zstd")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(zstdCompressForTest(t, hitMocker))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer backendSrv.Close()

	reg := NewReplayRegistry(128, time.Minute)
	tracker := NewWriteContextTracker(128, time.Minute)
	bridge := NewDataplaneBridge(tracker)
	routes := newEgressRouteMap()

	rt, err := NewRuntime(Config{
		Enabled:         true,
		AppID:           "pg-svc",
		BackendURL:      backendSrv.URL,
		EgressProxyPort: 0,
	},
		WithRuntimeCACertPath(""),
		WithRuntimeReplayRegistry(reg),
		WithRuntimeDataplaneBridge(bridge),
		WithRuntimeEgressTargetResolver(routes.lookup),
	)
	require.NoError(t, err)
	rt.cfg.EgressProxyPort = reserveFreePort(t)
	require.NoError(t, rt.Start(ctx))
	defer func() { _ = rt.Close() }()

	const pooledCookie uint64 = 9001
	conn := dialTrackedEgress(t, rt.EgressAddr(), routes, EgressTarget{
		SockCookie: pooledCookie,
		AddrPort:   pgUpstreamAddr,
	})
	defer conn.Close()
	br := bufio.NewReader(conn)

	var clientOffset uint64
	writeTracked := func(traceID [16]byte, data []byte) {
		tracker.RecordWrite(SocketWriteContext{
			SockCookie: pooledCookie,
			ByteOffset: clientOffset,
			TraceID:    traceID,
		})
		n, wErr := conn.Write(data)
		require.NoError(t, wErr)
		clientOffset += uint64(n)
	}

	writeTracked(liveTraceID, buildPGSSLRequestFrame())
	sslResp, err := br.ReadByte()
	require.NoError(t, err)
	require.Equal(t, byte('N'), sslResp)

	writeTracked(liveTraceID, buildPGStartupFrame("traveldb", "postgres"))
	startupReply := readPGUntilReadyForQuery(t, br)
	require.NotEmpty(t, startupReply)

	var param1 [8]byte
	binary.BigEndian.PutUint64(param1[:], 42)
	var liveBatch1 bytes.Buffer
	liveBatch1.Write(buildPGParseFrame("s1", extendedSQL, []uint32{pgOIDInt8, pgOIDBool}))
	liveBatch1.Write(buildPGBindFrame("", "s1", []int16{1, 1}, [][]byte{param1[:], {1}}, []int16{1}))
	liveBatch1.Write(buildPGDescribeFrame('P', ""))
	liveBatch1.Write(buildPGExecuteFrame("", 0))
	liveBatch1.Write(buildPGSyncFrame())

	writeTracked(liveTraceID, liveBatch1.Bytes())
	liveWire1 := readPGUntilReadyForQuery(t, br)
	parsedLive1 := parsePostgresWireResponseWithFormats(liveWire1, pgCols, []int16{1})
	require.NotNil(t, parsedLive1)
	require.Len(t, parsedLive1.Rows, 1)

	enricher := NewSpanEnricher(Config{Enabled: true, AppID: "pg-svc", RecordRate: 1.0}, reg)
	enricher.SetExchangeCache(bridge.ExchangeCache())
	testSpanID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	dbSpan := &request.Span{
		Type:      request.EventTypeSQLClient,
		SubType:   int(request.DBPostgres),
		Method:    "SELECT",
		Path:      "bookings",
		Statement: "",
	}
	enrichedRes := enricher.EnrichSpan(dbSpan, liveTraceID, testSpanID, 1000, 2000)
	enrichedMocker := enrichedRes.Mocker
	require.NotNil(t, enrichedMocker)
	assert.Equal(t, NormalizeSQL(extendedSQL), enrichedMocker.TargetRequest.Body)
	assert.Equal(t, "traveldb", enrichedMocker.TargetRequest.AttributeString(AttrDBName))
	assert.Equal(t, `["42","t"]`, enrichedMocker.TargetRequest.AttributeString(AttrDBParameters))

	var liveBatch2 bytes.Buffer
	liveBatch2.Write(buildPGBindFrame("", "s1", []int16{1, 1}, [][]byte{param1[:], {0}}, []int16{1}))
	liveBatch2.Write(buildPGExecuteFrame("", 0))
	liveBatch2.Write(buildPGSyncFrame())
	writeTracked(liveTraceID, liveBatch2.Bytes())
	_ = readPGUntilReadyForQuery(t, br)

	capturedCached, ok := bridge.ExchangeCache().ConsumeDatabase(liveTraceID, "", "SELECT", "bookings")
	require.True(t, ok)
	assert.Equal(t, extendedSQL, capturedCached.SQL)
	assert.Equal(t, []any{"42", "f"}, capturedCached.Parameters)

	require.NoError(t, pgUpstreamLn.Close())

	reg.Register(replayTraceID, ReplaySession{
		TraceID:         replayTraceID,
		Mode:            ModeReplay,
		RecordedTraceID: recordedTraceHex,
		ReplayID:        "rpl-pg-1",
		SegmentID:       "1122334455667788",
	})

	beforeQueries := queryCount.Load()
	var replayBatch bytes.Buffer
	replayBatch.Write(buildPGParseFrame("s_replay", extendedSQL, []uint32{pgOIDInt8, pgOIDBool}))
	replayBatch.Write(buildPGBindFrame("", "s_replay", []int16{1, 1}, [][]byte{param1[:], {1}}, []int16{1}))
	replayBatch.Write(buildPGDescribeFrame('P', ""))
	replayBatch.Write(buildPGExecuteFrame("", 0))
	replayBatch.Write(buildPGSyncFrame())

	writeTracked(replayTraceID, replayBatch.Bytes())
	replayWire := readPGUntilReadyForQuery(t, br)
	assert.Equal(t, beforeQueries+1, queryCount.Load())

	decodedReplay := parsePostgresWireResponseWithFormats(replayWire, pgCols, []int16{1})
	require.NotNil(t, decodedReplay)
	require.Len(t, decodedReplay.Rows, 1)
	assert.Equal(t, "42", decodedReplay.Rows[0][0])
	assert.Equal(t, "t", decodedReplay.Rows[0][1])
	assert.Equal(t, "18900", decodedReplay.Rows[0][2])
	assert.Equal(t, "SFO-LAX", decodedReplay.Rows[0][3])
	rowJSON, ok := decodedReplay.Rows[0][4].(string)
	require.True(t, ok)
	assert.JSONEq(t, `{"seat":"12A"}`, rowJSON)
	assert.Equal(t, uuidStr, decodedReplay.Rows[0][5])

	var replayCachedBatch bytes.Buffer
	replayCachedBatch.Write(buildPGBindFrame("", "s1", []int16{1, 1}, [][]byte{param1[:], {1}}, []int16{1}))
	replayCachedBatch.Write(buildPGExecuteFrame("", 0))
	replayCachedBatch.Write(buildPGSyncFrame())
	writeTracked(replayTraceID, replayCachedBatch.Bytes())
	replayCachedWire := readPGUntilReadyForQuery(t, br)
	decodedCachedReplay := parsePostgresWireResponseWithFormats(replayCachedWire, pgCols, []int16{1})
	require.NotNil(t, decodedCachedReplay)
	require.Len(t, decodedCachedReplay.Rows, 1)
	assert.Equal(t, "42", decodedCachedReplay.Rows[0][0])

	writeTracked(replayTraceID, buildPGSimpleQueryFrame(simpleSQL))
	simpleWire := readPGUntilReadyForQuery(t, br)
	decodedSimple := ParsePostgresWireResponse(simpleWire)
	require.NotNil(t, decodedSimple)
	require.Len(t, decodedSimple.Rows, 1)
	assert.Equal(t, "Grand Hyatt SFO", decodedSimple.Rows[0][0])

	const offlineCookie uint64 = 9002
	offlineConn := dialTrackedEgress(t, rt.EgressAddr(), routes, EgressTarget{
		SockCookie: offlineCookie,
		AddrPort:   pgUpstreamAddr,
	})
	defer offlineConn.Close()
	offlineBR := bufio.NewReader(offlineConn)
	tracker.RecordWrite(SocketWriteContext{
		SockCookie: offlineCookie,
		ByteOffset: 0,
		TraceID:    replayTraceID,
	})
	_, err = offlineConn.Write(buildPGSSLRequestFrame())
	require.NoError(t, err)
	b, err := offlineBR.ReadByte()
	require.NoError(t, err)
	require.Equal(t, byte('N'), b)

	_, err = offlineConn.Write(buildPGStartupFrame("traveldb", "postgres"))
	require.NoError(t, err)
	offlineStartup := readPGUntilReadyForQuery(t, offlineBR)
	assert.Contains(t, string(offlineStartup), "server_version")

	_, err = offlineConn.Write(buildPGSimpleQueryFrame(simpleSQL))
	require.NoError(t, err)
	offlineSimpleWire := readPGUntilReadyForQuery(t, offlineBR)
	offlineRes := ParsePostgresWireResponse(offlineSimpleWire)
	require.NotNil(t, offlineRes)
	require.Len(t, offlineRes.Rows, 1)
	assert.Equal(t, "Grand Hyatt SFO", offlineRes.Rows[0][0])
}

func TestPostgresMustMockBlocksZeroUpstreamDial(t *testing.T) {
	ctx := t.Context()

	replayTraceID, err := ParseTraceIDHex("33333333333333333333333333333333")
	require.NoError(t, err)

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zstd")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ReplayMustMockZstdBytes)
	}))
	defer backendSrv.Close()

	reg := NewReplayRegistry(64, time.Minute)
	reg.Register(replayTraceID, ReplaySession{
		TraceID:         replayTraceID,
		Mode:            ModeReplay,
		RecordedTraceID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ReplayID:        "rpl-pg-mustmock",
	})
	tracker := NewWriteContextTracker(64, time.Minute)
	bridge := NewDataplaneBridge(tracker)
	routes := newEgressRouteMap()

	var dialAttempts atomic.Int32
	rt, err := NewRuntime(Config{
		Enabled:         true,
		AppID:           "pg-svc",
		BackendURL:      backendSrv.URL,
		EgressProxyPort: reserveFreePort(t),
	},
		WithRuntimeCACertPath(""),
		WithRuntimeReplayRegistry(reg),
		WithRuntimeDataplaneBridge(bridge),
		WithRuntimeEgressTargetResolver(routes.lookup),
		WithRuntimePostgresHandlerOptions(WithPostgresDialer(func(context.Context, string, string) (net.Conn, error) {
			dialAttempts.Add(1)
			return nil, net.ErrClosed
		})),
	)
	require.NoError(t, err)
	require.NoError(t, rt.Start(ctx))
	defer func() { _ = rt.Close() }()

	const cookie uint64 = 9100
	tracker.RecordWrite(SocketWriteContext{
		SockCookie: cookie,
		ByteOffset: 0,
		TraceID:    replayTraceID,
	})
	conn := dialTrackedEgress(t, rt.EgressAddr(), routes, EgressTarget{
		SockCookie: cookie,
		AddrPort:   netip.MustParseAddrPort("127.0.0.1:5432"),
	})
	defer conn.Close()
	br := bufio.NewReader(conn)

	_, err = conn.Write(buildPGStartupFrame("traveldb", "postgres"))
	require.NoError(t, err)
	_ = readPGUntilReadyForQuery(t, br)

	_, err = conn.Write(buildPGSimpleQueryFrame("SELECT 1"))
	require.NoError(t, err)
	errWire := readPGUntilReadyForQuery(t, br)
	parsed := ParsePostgresWireResponse(errWire)
	require.NotNil(t, parsed)
	assert.Equal(t, "XX000", parsed.ErrorCode)
	assert.Contains(t, parsed.ErrorMessage, "mustMock")
	assert.Equal(t, int32(0), dialAttempts.Load())
	assert.Equal(t, uint64(0), rt.PostgresHandler().Stats().UpstreamDials.Load())
	assert.Equal(t, uint64(1), rt.PostgresHandler().Stats().MustMockBlocks.Load())
}

func buildMySQLClientHandshakePacket(seq uint8, dbName string) []byte {
	flags := mysqlCapLongPassword |
		mysqlCapFoundRows |
		mysqlCapLongFlag |
		mysqlCapConnectWithDB |
		mysqlCapProtocol41 |
		mysqlCapTransactions |
		mysqlCapSecureConnection |
		mysqlCapPluginAuth
	var p bytes.Buffer
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], flags)
	p.Write(u32[:])
	binary.LittleEndian.PutUint32(u32[:], 16<<20)
	p.Write(u32[:])
	p.WriteByte(uint8(mysqlCharsetUTF8))
	var reserved [23]byte
	p.Write(reserved[:])
	p.WriteString("root")
	p.WriteByte(0)
	p.WriteByte(0)
	p.WriteString(dbName)
	p.WriteByte(0)
	p.WriteString("mysql_native_password")
	p.WriteByte(0)
	return encodeMySQLWirePacket(seq, p.Bytes())
}

func buildMySQLStmtExecutePacket(stmtID uint32, idParam int32, codeParam string) []byte {
	var p bytes.Buffer
	p.WriteByte(mysqlComStmtExecute)
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], stmtID)
	p.Write(u32[:])
	p.WriteByte(0)
	binary.LittleEndian.PutUint32(u32[:], 1)
	p.Write(u32[:])
	p.WriteByte(0x00)
	p.WriteByte(0x01)
	p.WriteByte(mysqlTypeLong)
	p.WriteByte(0x00)
	p.WriteByte(mysqlTypeVarString)
	p.WriteByte(0x00)
	binary.LittleEndian.PutUint32(u32[:], uint32(idParam))
	p.Write(u32[:])
	writeMySQLLenEncString(&p, codeParam)
	return encodeMySQLWirePacket(0, p.Bytes())
}

func readMySQLResultPacketsForTest(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var wire bytes.Buffer
	first, _, rawFirst, err := readMySQLWirePacket(r)
	require.NoError(t, err)
	wire.Write(rawFirst)
	if len(first) == 0 || first[0] == 0x00 || first[0] == 0xff {
		return wire.Bytes()
	}
	colCountU64, _, ok := readMySQLLenEncInt(first, 0)
	require.True(t, ok)
	for range int(colCountU64) {
		_, _, rawCol, rErr := readMySQLWirePacket(r)
		require.NoError(t, rErr)
		wire.Write(rawCol)
	}
	_, _, rawColEOF, err := readMySQLWirePacket(r)
	require.NoError(t, err)
	wire.Write(rawColEOF)
	for {
		pkt, _, rawPkt, rErr := readMySQLWirePacket(r)
		require.NoError(t, rErr)
		wire.Write(rawPkt)
		if (len(pkt) > 0 && pkt[0] == 0xfe && len(pkt) < 9) || (len(pkt) > 0 && pkt[0] == 0xff) {
			break
		}
	}
	return wire.Bytes()
}

func TestMySQLServerFirstAndPreparedOfflineReplay(t *testing.T) {
	ctx := t.Context()

	liveTraceID, err := ParseTraceIDHex("44444444444444444444444444444444")
	require.NoError(t, err)
	replayTraceID, err := ParseTraceIDHex("55555555555555555555555555555555")
	require.NoError(t, err)
	const recordedTraceHex = "cccccccccccccccccccccccccccccccc"
	const preparedSQL = "SELECT id, price_cents, code, note FROM fares WHERE id = ? AND code = ?"

	mysqlCols := []DatabaseColumn{
		{Name: "id", MySQLType: mysqlTypeLongLong, MySQLCharset: 63},
		{Name: "price_cents", MySQLType: mysqlTypeLong, MySQLCharset: 63},
		{Name: "code", MySQLType: mysqlTypeVarString, MySQLCharset: mysqlCharsetUTF8},
		{Name: "note", MySQLType: mysqlTypeVarString, MySQLCharset: mysqlCharsetUTF8},
	}

	mysqlUpstreamLn, err := ListenNonMPTCP(ctx, "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	realMySQLAddr := mysqlUpstreamLn.Addr().String()

	go func() {
		conn, acceptErr := mysqlUpstreamLn.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)

		_, _ = conn.Write(encodeMySQLWirePacket(0, buildSyntheticMySQLGreeting()))
		_, cSeq, _, rErr := readMySQLWirePacket(br)
		if rErr != nil {
			return
		}
		_, _ = conn.Write(encodeMySQLWirePacket(cSeq+1, []byte{0x01, 0x03}))
		_, _ = conn.Write(encodeMySQLOKPacket(cSeq+2, 0, 0))

		for {
			pkt, _, _, cmdErr := readMySQLWirePacket(br)
			if cmdErr != nil || len(pkt) == 0 {
				return
			}
			switch pkt[0] {
			case mysqlComStmtPrepare:
				var okBody [12]byte
				okBody[0] = 0x00
				binary.LittleEndian.PutUint32(okBody[1:5], 7)
				binary.LittleEndian.PutUint16(okBody[5:7], uint16(len(mysqlCols)))
				binary.LittleEndian.PutUint16(okBody[7:9], 2)
				var out bytes.Buffer
				out.Write(encodeMySQLWirePacket(1, okBody[:]))
				seq := uint8(2)
				for range 2 {
					out.Write(encodeMySQLColumnDefPacket(seq, "ota_mysql", DatabaseColumn{
						Name:         "?",
						MySQLType:    mysqlTypeVarString,
						MySQLCharset: mysqlCharsetUTF8,
					}))
					seq++
				}
				out.Write(encodeMySQLEOFPacket(seq, false))
				seq++
				for _, col := range mysqlCols {
					out.Write(encodeMySQLColumnDefPacket(seq, "ota_mysql", col))
					seq++
				}
				out.Write(encodeMySQLEOFPacket(seq, false))
				_, _ = conn.Write(out.Bytes())

			case mysqlComStmtExecute:
				res := &DatabaseResult{
					Columns: mysqlCols,
					Rows:    [][]any{{"501", "19900", "SFO", nil}},
				}
				_, _ = conn.Write(encodeMySQLResultResponse("ota_mysql", res, true, false))
			}
		}
	}()

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/storage/record/query":
			raw, rErr := io.ReadAll(r.Body)
			assert.NoError(t, rErr)
			reqMocker := decodePostedMockerForTest(t, raw)
			assert.Equal(t, "ota_mysql", reqMocker.TargetRequest.AttributeString(AttrDBName))

			var res DatabaseResult
			if strings.HasPrefix(strings.ToUpper(reqMocker.TargetRequest.Body), "UPDATE") {
				res = DatabaseResult{RowsAffected: 1}
			} else {
				res = DatabaseResult{
					Columns: mysqlCols,
					Rows:    [][]any{{float64(501), float64(19900), "SFO", nil}},
				}
			}
			hitMocker, mErr := BuildDatabaseMocker(SpanMetadata{
				AppID:   "mysql-svc",
				TraceID: recordedTraceHex,
			}, DatabaseExchange{
				DBName: "ota_mysql",
				SQL:    reqMocker.TargetRequest.Body,
				Result: &res,
			})
			assert.NoError(t, mErr)
			w.Header().Set("Content-Type", "application/zstd")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(zstdCompressForTest(t, hitMocker))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer backendSrv.Close()

	reg := NewReplayRegistry(128, time.Minute)
	tracker := NewWriteContextTracker(128, time.Minute)
	bridge := NewDataplaneBridge(tracker)
	routes := newEgressRouteMap()

	rt, err := NewRuntime(Config{
		Enabled:         true,
		AppID:           "mysql-svc",
		BackendURL:      backendSrv.URL,
		EgressProxyPort: reserveFreePort(t),
	},
		WithRuntimeCACertPath(""),
		WithRuntimeReplayRegistry(reg),
		WithRuntimeDataplaneBridge(bridge),
		WithRuntimeEgressTargetResolver(routes.lookup),
		WithRuntimeMySQLHandlerOptions(WithMySQLDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, realMySQLAddr)
		})),
	)
	require.NoError(t, err)
	require.NoError(t, rt.Start(ctx))
	defer func() { _ = rt.Close() }()

	const pooledCookie uint64 = 9201
	conn := dialTrackedEgress(t, rt.EgressAddr(), routes, EgressTarget{
		SockCookie: pooledCookie,
		AddrPort:   netip.MustParseAddrPort("127.0.0.1:3306"),
	})
	defer conn.Close()
	br := bufio.NewReader(conn)

	greeting, gSeq, _, err := readMySQLWirePacket(br)
	require.NoError(t, err)
	assert.Equal(t, uint8(0), gSeq)
	assert.Equal(t, byte(0x0a), greeting[0])

	var clientOffset uint64
	writeTracked := func(traceID [16]byte, pkt []byte) {
		tracker.RecordWrite(SocketWriteContext{
			SockCookie: pooledCookie,
			ByteOffset: clientOffset,
			TraceID:    traceID,
		})
		n, wErr := conn.Write(pkt)
		require.NoError(t, wErr)
		clientOffset += uint64(n)
	}

	writeTracked(liveTraceID, buildMySQLClientHandshakePacket(1, "ota_mysql"))
	fastAuth, _, _, err := readMySQLWirePacket(br)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0x03}, fastAuth)
	finalOK, _, _, err := readMySQLWirePacket(br)
	require.NoError(t, err)
	assert.Equal(t, byte(0x00), finalOK[0])

	prepPkt := encodeMySQLWirePacket(0, append([]byte{mysqlComStmtPrepare}, []byte(preparedSQL)...))
	writeTracked(liveTraceID, prepPkt)
	prepOK, _, _, err := readMySQLWirePacket(br)
	require.NoError(t, err)
	require.Equal(t, byte(0x00), prepOK[0])
	stmtID := binary.LittleEndian.Uint32(prepOK[1:5])
	assert.Equal(t, uint32(7), stmtID)
	for range 2 + 1 + len(mysqlCols) + 1 {
		_, _, _, err = readMySQLWirePacket(br)
		require.NoError(t, err)
	}

	writeTracked(liveTraceID, buildMySQLStmtExecutePacket(stmtID, 77, "SFO"))
	liveExecWire := readMySQLResultPacketsForTest(t, br)
	parsedLive := ParseMySQLWireResponse(liveExecWire)
	require.NotNil(t, parsedLive)
	require.Len(t, parsedLive.Rows, 1)
	assert.Equal(t, "501", parsedLive.Rows[0][0])
	assert.Nil(t, parsedLive.Rows[0][3])

	captured, ok := bridge.ExchangeCache().ConsumeDatabase(liveTraceID, "", "SELECT", "fares")
	require.True(t, ok)
	assert.Equal(t, "ota_mysql", captured.DBName)
	assert.Equal(t, preparedSQL, captured.SQL)
	assert.Equal(t, []any{"77", "SFO"}, captured.Parameters)

	require.NoError(t, mysqlUpstreamLn.Close())

	reg.Register(replayTraceID, ReplaySession{
		TraceID:         replayTraceID,
		Mode:            ModeReplay,
		RecordedTraceID: recordedTraceHex,
		ReplayID:        "rpl-mysql-1",
		SegmentID:       "9988776655443322",
	})

	writeTracked(replayTraceID, buildMySQLStmtExecutePacket(stmtID, 77, "SFO"))
	replayExecWire := readMySQLResultPacketsForTest(t, br)
	parsedReplay := ParseMySQLWireResponse(replayExecWire)
	require.NotNil(t, parsedReplay)
	require.Len(t, parsedReplay.Rows, 1)
	assert.Equal(t, "501", parsedReplay.Rows[0][0])
	assert.Equal(t, "19900", parsedReplay.Rows[0][1])
	assert.Equal(t, "SFO", parsedReplay.Rows[0][2])
	assert.Nil(t, parsedReplay.Rows[0][3])

	updPkt := encodeMySQLWirePacket(0, append([]byte{mysqlComQuery}, []byte("UPDATE fares SET price_cents = 20500 WHERE id = 501")...))
	writeTracked(replayTraceID, updPkt)
	updWire := readMySQLResultPacketsForTest(t, br)
	parsedUpd := ParseMySQLWireResponse(updWire)
	require.NotNil(t, parsedUpd)
	assert.Equal(t, int64(1), parsedUpd.RowsAffected)

	const offlineCookie uint64 = 9202
	tracker.RecordWrite(SocketWriteContext{
		SockCookie: offlineCookie,
		ByteOffset: 0,
		TraceID:    replayTraceID,
	})
	offlineConn := dialTrackedEgress(t, rt.EgressAddr(), routes, EgressTarget{
		SockCookie: offlineCookie,
		AddrPort:   netip.MustParseAddrPort("127.0.0.1:3306"),
	})
	defer offlineConn.Close()
	offlineBR := bufio.NewReader(offlineConn)

	offGreet, _, _, err := readMySQLWirePacket(offlineBR)
	require.NoError(t, err)
	assert.Equal(t, byte(0x0a), offGreet[0])

	_, err = offlineConn.Write(buildMySQLClientHandshakePacket(1, "ota_mysql"))
	require.NoError(t, err)
	offOK, _, _, err := readMySQLWirePacket(offlineBR)
	require.NoError(t, err)
	assert.Equal(t, byte(0x00), offOK[0])

	_, err = offlineConn.Write(prepPkt)
	require.NoError(t, err)
	offPrepOK, _, _, err := readMySQLWirePacket(offlineBR)
	require.NoError(t, err)
	require.Equal(t, byte(0x00), offPrepOK[0])
	synthStmtID := binary.LittleEndian.Uint32(offPrepOK[1:5])
	assert.GreaterOrEqual(t, synthStmtID, uint32(100000))
	numCols := int(binary.LittleEndian.Uint16(offPrepOK[5:7]))
	numParams := int(binary.LittleEndian.Uint16(offPrepOK[7:9]))
	if numParams > 0 {
		for range numParams + 1 {
			_, _, _, err = readMySQLWirePacket(offlineBR)
			require.NoError(t, err)
		}
	}
	if numCols > 0 {
		for range numCols + 1 {
			_, _, _, err = readMySQLWirePacket(offlineBR)
			require.NoError(t, err)
		}
	}

	_, err = offlineConn.Write(buildMySQLStmtExecutePacket(synthStmtID, 77, "SFO"))
	require.NoError(t, err)
	offExecWire := readMySQLResultPacketsForTest(t, offlineBR)
	offParsed := ParseMySQLWireResponse(offExecWire)
	require.NotNil(t, offParsed)
	require.Len(t, offParsed.Rows, 1)
	assert.Equal(t, "501", offParsed.Rows[0][0])
}

func TestMySQLMustMockBlocksZeroUpstreamDial(t *testing.T) {
	ctx := t.Context()

	replayTraceID, err := ParseTraceIDHex("66666666666666666666666666666666")
	require.NoError(t, err)

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zstd")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ReplayMustMockZstdBytes)
	}))
	defer backendSrv.Close()

	reg := NewReplayRegistry(64, time.Minute)
	reg.Register(replayTraceID, ReplaySession{
		TraceID:         replayTraceID,
		Mode:            ModeReplay,
		RecordedTraceID: "dddddddddddddddddddddddddddddddd",
		ReplayID:        "rpl-mysql-mustmock",
	})
	tracker := NewWriteContextTracker(64, time.Minute)
	bridge := NewDataplaneBridge(tracker)
	routes := newEgressRouteMap()

	var dialAttempts atomic.Int32
	rt, err := NewRuntime(Config{
		Enabled:         true,
		AppID:           "mysql-svc",
		BackendURL:      backendSrv.URL,
		EgressProxyPort: reserveFreePort(t),
	},
		WithRuntimeCACertPath(""),
		WithRuntimeReplayRegistry(reg),
		WithRuntimeDataplaneBridge(bridge),
		WithRuntimeEgressTargetResolver(routes.lookup),
		WithRuntimeMySQLHandlerOptions(WithMySQLDialer(func(context.Context, string, string) (net.Conn, error) {
			dialAttempts.Add(1)
			return nil, net.ErrClosed
		})),
	)
	require.NoError(t, err)
	require.NoError(t, rt.Start(ctx))
	defer func() { _ = rt.Close() }()

	const cookie uint64 = 9300
	tracker.RecordWrite(SocketWriteContext{
		SockCookie: cookie,
		ByteOffset: 0,
		TraceID:    replayTraceID,
	})
	conn := dialTrackedEgress(t, rt.EgressAddr(), routes, EgressTarget{
		SockCookie: cookie,
		AddrPort:   netip.MustParseAddrPort("127.0.0.1:3306"),
	})
	defer conn.Close()
	br := bufio.NewReader(conn)

	_, _, _, err = readMySQLWirePacket(br)
	require.NoError(t, err)
	_, err = conn.Write(buildMySQLClientHandshakePacket(1, "ota_mysql"))
	require.NoError(t, err)
	_, _, _, err = readMySQLWirePacket(br)
	require.NoError(t, err)

	_, err = conn.Write(encodeMySQLWirePacket(0, append([]byte{mysqlComQuery}, []byte("SELECT 1")...)))
	require.NoError(t, err)
	errWire := readMySQLResultPacketsForTest(t, br)
	parsed := ParseMySQLWireResponse(errWire)
	require.NotNil(t, parsed)
	assert.Equal(t, "1105", parsed.ErrorCode)
	assert.Contains(t, parsed.ErrorMessage, "mustMock")
	assert.Equal(t, int32(0), dialAttempts.Load())
	assert.Equal(t, uint64(0), rt.MySQLHandler().Stats().UpstreamDials.Load())
	assert.Equal(t, uint64(1), rt.MySQLHandler().Stats().MustMockBlocks.Load())
}

func buildRESPCommand(args ...string) []byte {
	var buf bytes.Buffer
	buf.WriteByte('*')
	buf.WriteString(strconv.Itoa(len(args)))
	buf.WriteString("\r\n")
	for _, a := range args {
		buf.WriteByte('$')
		buf.WriteString(strconv.Itoa(len(a)))
		buf.WriteString("\r\n")
		buf.WriteString(a)
		buf.WriteString("\r\n")
	}
	return buf.Bytes()
}

func TestRedisRESP2RESP3AndPooledOfflineReplay(t *testing.T) {
	ctx := t.Context()

	liveTraceID, err := ParseTraceIDHex("77777777777777777777777777777777")
	require.NoError(t, err)
	replayTraceID, err := ParseTraceIDHex("88888888888888888888888888888888")
	require.NoError(t, err)
	const recordedTraceHex = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

	largeBlob := strings.Repeat("Z", 72000)

	redisUpstreamLn, err := ListenNonMPTCP(ctx, "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	redisUpstreamAddr := netip.MustParseAddrPort(redisUpstreamLn.Addr().String())

	go func() {
		conn, acceptErr := redisUpstreamLn.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		for {
			tokens, _, rErr := readRESPClientCommand(br)
			if rErr != nil || len(tokens) == 0 {
				return
			}
			cmd := strings.ToUpper(tokens[0])
			switch cmd {
			case "GET":
				switch tokens[1] {
				case "user:1":
					_, _ = conn.Write([]byte("$5\r\nalice\r\n"))
				case "blob:large":
					_, _ = conn.Write([]byte("$" + strconv.Itoa(len(largeBlob)) + "\r\n" + largeBlob + "\r\n"))
				default:
					_, _ = conn.Write([]byte("$-1\r\n"))
				}
			case "MGET":
				_, _ = conn.Write([]byte("*2\r\n$2\r\nv2\r\n$2\r\nv1\r\n"))
			default:
				_, _ = conn.Write([]byte("+OK\r\n"))
			}
		}
	}()

	var storedMocks sync.Map
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/storage/record/query":
			raw, rErr := io.ReadAll(r.Body)
			assert.NoError(t, rErr)
			reqMocker := decodePostedMockerForTest(t, raw)
			lookupKey := reqMocker.OperationName + "|" + reqMocker.TargetRequest.Body
			if hit, ok := storedMocks.Load(lookupKey); ok {
				w.Header().Set("Content-Type", "application/zstd")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(zstdCompressForTest(t, hit))
				return
			}
			w.Header().Set("Content-Type", "application/zstd")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(EmptyInstanceZstdBytes)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer backendSrv.Close()

	reg := NewReplayRegistry(128, time.Minute)
	tracker := NewWriteContextTracker(128, time.Minute)
	bridge := NewDataplaneBridge(tracker)
	routes := newEgressRouteMap()

	rt, err := NewRuntime(Config{
		Enabled:         true,
		AppID:           "redis-svc",
		BackendURL:      backendSrv.URL,
		EgressProxyPort: reserveFreePort(t),
	},
		WithRuntimeCACertPath(""),
		WithRuntimeReplayRegistry(reg),
		WithRuntimeDataplaneBridge(bridge),
		WithRuntimeEgressTargetResolver(routes.lookup),
	)
	require.NoError(t, err)
	require.NoError(t, rt.Start(ctx))
	defer func() { _ = rt.Close() }()

	const pooledCookie uint64 = 9401
	conn := dialTrackedEgress(t, rt.EgressAddr(), routes, EgressTarget{
		SockCookie: pooledCookie,
		AddrPort:   redisUpstreamAddr,
	})
	defer conn.Close()
	br := bufio.NewReader(conn)

	var clientOffset uint64
	sendCmd := func(traceID [16]byte, args ...string) RedisReply {
		raw := buildRESPCommand(args...)
		tracker.RecordWrite(SocketWriteContext{
			SockCookie: pooledCookie,
			ByteOffset: clientOffset,
			TraceID:    traceID,
		})
		n, wErr := conn.Write(raw)
		require.NoError(t, wErr)
		clientOffset += uint64(n)
		reply, _, rErr := readRESPReplyFrame(br, 0)
		require.NoError(t, rErr)
		return reply
	}

	r1 := sendCmd(liveTraceID, "GET", "user:1")
	assert.Equal(t, "alice", r1.Str)

	rMiss := sendCmd(liveTraceID, "GET", "user:missing")
	assert.True(t, rMiss.IsNil)

	rBig := sendCmd(liveTraceID, "GET", "blob:large")
	assert.Len(t, rBig.Str, 72000)

	rMget := sendCmd(liveTraceID, "MGET", "k2", "k1")
	require.Len(t, rMget.Elements, 2)

	enricher := NewSpanEnricher(Config{Enabled: true, AppID: "redis-svc", RecordRate: 1.0}, reg)
	enricher.SetExchangeCache(bridge.ExchangeCache())
	for idx, tc := range []struct {
		method string
		path   string
	}{
		{"GET", "GET user:1"},
		{"GET", "GET user:missing"},
		{"GET", "GET blob:large"},
		{"MGET", "MGET k2 k1"},
	} {
		sp := &request.Span{
			Type:   request.EventTypeRedisClient,
			Method: tc.method,
			Path:   tc.path,
		}
		spanID := [8]byte{1, 2, 3, 4, 5, 6, 7, byte(idx + 1)}
		enr := enricher.EnrichSpan(sp, liveTraceID, spanID, 1000, 2000)
		require.NotNil(t, enr.Mocker)
		storedMocks.Store(enr.Mocker.OperationName+"|"+enr.Mocker.TargetRequest.Body, enr.Mocker)
	}

	hgetallMocker, err := BuildRedisMocker(SpanMetadata{
		AppID:   "redis-svc",
		TraceID: recordedTraceHex,
	}, RedisExchange{
		Command:     "HGETALL",
		ClusterName: redisUpstreamAddr.String(),
		Keys:        []string{"profile:1"},
		Reply: &RedisReply{
			Type: "%",
			Elements: []RedisReply{
				{Type: "$", Bulk: []byte("name"), Str: "name"},
				{Type: "$", Bulk: []byte("alice"), Str: "alice"},
				{Type: "$", Bulk: []byte("tier"), Str: "tier"},
				{Type: "$", Bulk: []byte("gold"), Str: "gold"},
			},
		},
		OrderFree: true,
	})
	require.NoError(t, err)
	storedMocks.Store(hgetallMocker.OperationName+"|"+hgetallMocker.TargetRequest.Body, hgetallMocker)

	require.NoError(t, redisUpstreamLn.Close())

	reg.Register(replayTraceID, ReplaySession{
		TraceID:         replayTraceID,
		Mode:            ModeReplay,
		RecordedTraceID: recordedTraceHex,
		ReplayID:        "rpl-redis-1",
	})

	assert.Equal(t, "alice", sendCmd(replayTraceID, "GET", "user:1").Str)
	assert.True(t, sendCmd(replayTraceID, "GET", "user:missing").IsNil)
	assert.Len(t, sendCmd(replayTraceID, "GET", "blob:large").Str, 72000)

	reorderedMget := sendCmd(replayTraceID, "MGET", "k1", "k2")
	require.Len(t, reorderedMget.Elements, 2)
	assert.Equal(t, "v2", reorderedMget.Elements[0].Str)
	assert.Equal(t, "v1", reorderedMget.Elements[1].Str)

	hello3 := sendCmd(replayTraceID, "HELLO", "3")
	assert.Equal(t, "%", hello3.Type)

	hgetallReply := sendCmd(replayTraceID, "HGETALL", "profile:1")
	assert.Equal(t, "%", hgetallReply.Type)
	require.Len(t, hgetallReply.Elements, 4)
	assert.Equal(t, "alice", hgetallReply.Elements[1].Str)

	tracker.RecordWrite(SocketWriteContext{
		SockCookie: pooledCookie,
		ByteOffset: clientOffset,
		TraceID:    replayTraceID,
	})
	rawNilCmd := buildRESPCommand("GET", "user:missing")
	n, err := conn.Write(rawNilCmd)
	require.NoError(t, err)
	clientOffset += uint64(n)
	_, rawNilWire, err := readRESPReplyFrame(br, 0)
	require.NoError(t, err)
	assert.Equal(t, "_\r\n", string(rawNilWire))

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cookie := uint64(9500 + idx)
			c, dErr := tryDialTrackedEgress(rt.EgressAddr(), routes, EgressTarget{
				SockCookie: cookie,
				AddrPort:   redisUpstreamAddr,
			})
			if !assert.NoError(t, dErr) {
				return
			}
			defer c.Close()
			cbr := bufio.NewReader(c)
			var off uint64
			for _, cmdArgs := range [][]string{
				{"HELLO", "3"},
				{"SELECT", "0"},
				{"GET", "user:1"},
				{"MGET", "k1", "k2"},
				{"QUIT"},
			} {
				tracker.RecordWrite(SocketWriteContext{
					SockCookie: cookie,
					ByteOffset: off,
					TraceID:    replayTraceID,
				})
				raw := buildRESPCommand(cmdArgs...)
				wn, wErr := c.Write(raw)
				assert.NoError(t, wErr)
				off += uint64(wn)
				_, _, rErr := readRESPReplyFrame(cbr, 0)
				assert.NoError(t, rErr)
			}
		}(i)
	}
	wg.Wait()
}

func TestRedisMustMockBlocksZeroUpstreamDial(t *testing.T) {
	ctx := t.Context()

	replayTraceID, err := ParseTraceIDHex("99999999999999999999999999999999")
	require.NoError(t, err)

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zstd")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ReplayMustMockZstdBytes)
	}))
	defer backendSrv.Close()

	reg := NewReplayRegistry(64, time.Minute)
	reg.Register(replayTraceID, ReplaySession{
		TraceID:         replayTraceID,
		Mode:            ModeReplay,
		RecordedTraceID: "ffffffffffffffffffffffffffffffff",
		ReplayID:        "rpl-redis-mustmock",
	})
	tracker := NewWriteContextTracker(64, time.Minute)
	bridge := NewDataplaneBridge(tracker)
	routes := newEgressRouteMap()

	var dialAttempts atomic.Int32
	rt, err := NewRuntime(Config{
		Enabled:         true,
		AppID:           "redis-svc",
		BackendURL:      backendSrv.URL,
		EgressProxyPort: reserveFreePort(t),
	},
		WithRuntimeCACertPath(""),
		WithRuntimeReplayRegistry(reg),
		WithRuntimeDataplaneBridge(bridge),
		WithRuntimeEgressTargetResolver(routes.lookup),
		WithRuntimeRedisHandlerOptions(WithRedisDialer(func(context.Context, string, string) (net.Conn, error) {
			dialAttempts.Add(1)
			return nil, net.ErrClosed
		})),
	)
	require.NoError(t, err)
	require.NoError(t, rt.Start(ctx))
	defer func() { _ = rt.Close() }()

	const cookie uint64 = 9600
	tracker.RecordWrite(SocketWriteContext{
		SockCookie: cookie,
		ByteOffset: 0,
		TraceID:    replayTraceID,
	})
	conn := dialTrackedEgress(t, rt.EgressAddr(), routes, EgressTarget{
		SockCookie: cookie,
		AddrPort:   netip.MustParseAddrPort("127.0.0.1:6379"),
	})
	defer conn.Close()
	br := bufio.NewReader(conn)

	_, err = conn.Write(buildRESPCommand("GET", "secret:key"))
	require.NoError(t, err)
	reply, _, err := readRESPReplyFrame(br, 0)
	require.NoError(t, err)
	assert.Equal(t, "-", reply.Type)
	assert.Contains(t, reply.Str, "mustMock")
	assert.Equal(t, int32(0), dialAttempts.Load())
	assert.Equal(t, uint64(0), rt.RedisHandler().Stats().UpstreamDials.Load())
	assert.Equal(t, uint64(1), rt.RedisHandler().Stats().MustMockBlocks.Load())
}

func TestPostgresAndMySQLPrepareOnlyAndSessionSuppression(t *testing.T) {
	cache := NewHTTPExchangeCache(128, time.Minute)
	reg := NewReplayRegistry(128, time.Minute)
	enricher := NewSpanEnricher(Config{
		Enabled:    true,
		AppID:      "sql-svc",
		RecordRate: 1.0,
	}, reg)
	enricher.SetExchangeCache(cache)

	traceID := [16]byte{0x44, 0x55, 0x66, 1}
	sqlText := "SELECT id, fare_cents FROM flight_fares WHERE id = ?"
	cache.RecordDatabase(traceID, CapturedDatabaseExchange{
		DBName:     "otadb",
		SQL:        sqlText,
		Parameters: []any{"12"},
		Result: &DatabaseResult{
			Columns: []DatabaseColumn{{Name: "id"}, {Name: "fare_cents"}},
			Rows:    [][]any{{"12", "34500"}},
		},
	})

	mysqlPrepareSpan := &request.Span{
		Type:      request.EventTypeSQLClient,
		Method:    "SELECT",
		Path:      "flight_fares",
		Statement: sqlText,
		Softprobe: &request.SoftprobeCapture{
			SQLWireRequest: encodeMySQLWirePacket(0, append([]byte{mysqlComStmtPrepare}, []byte(sqlText)...)),
		},
	}
	prepRes := enricher.EnrichSpan(mysqlPrepareSpan, traceID, [8]byte{1}, 100, 200)
	assert.Nil(t, prepRes.Mocker)

	mysqlExecuteSpan := &request.Span{
		Type:      request.EventTypeSQLClient,
		Method:    "SELECT",
		Path:      "flight_fares",
		Statement: sqlText,
		Softprobe: &request.SoftprobeCapture{
			SQLWireRequest: buildMySQLStmtExecutePacket(1, 12, "LAX"),
		},
	}
	execRes := enricher.EnrichSpan(mysqlExecuteSpan, traceID, [8]byte{2}, 201, 300)
	require.NotNil(t, execRes.Mocker)
	assert.Equal(t, "otadb", execRes.Mocker.TargetRequest.AttributeString(AttrDBName))

	var pgPrepWire bytes.Buffer
	pgPrepWire.Write(buildPGParseFrame("stmt_1", "SELECT id FROM catalog_items WHERE id = $1", []uint32{pgOIDInt8}))
	pgPrepWire.Write(buildPGDescribeFrame('S', "stmt_1"))
	pgPrepWire.Write(buildPGSyncFrame())
	assert.True(t, isNonExecutionSQLWireRequest(pgPrepWire.Bytes()))

	resetSQL := "SELECT pg_advisory_unlock_all();\nCLOSE ALL;\nUNLISTEN *;\nRESET ALL;"
	assert.True(t, isSessionControlSQL(resetSQL))
	replyWire := encodeSyntheticPostgresSessionReply(resetSQL, true)
	br := bufio.NewReader(bytes.NewReader(replyWire))
	var cmdTags []string
	var sawReady bool
	for {
		mType, mPayload, _, err := readPostgresFrame(br)
		require.NoError(t, err)
		if mType == 'C' {
			tag, _, _ := readCString(mPayload, 0)
			cmdTags = append(cmdTags, tag)
		}
		if mType == 'Z' {
			sawReady = true
			break
		}
	}
	assert.True(t, sawReady)
	assert.Equal(t, []string{"SELECT 1", "CLOSE", "UNLISTEN", "RESET"}, cmdTags)

	assert.True(t, isSessionControlSQL("-- ping"))
	pingReply := encodeSyntheticPostgresSessionReply("-- ping", true)
	pingBR := bufio.NewReader(bytes.NewReader(pingReply))
	pType1, _, _, err := readPostgresFrame(pingBR)
	require.NoError(t, err)
	assert.Equal(t, byte('I'), pType1)
	pType2, _, _, err := readPostgresFrame(pingBR)
	require.NoError(t, err)
	assert.Equal(t, byte('Z'), pType2)

	inspectorListSpan := &request.Span{
		Type:     request.EventTypeHTTP,
		Method:   "GET",
		Path:     "/json/list",
		HostPort: 9229,
		Status:   http.StatusOK,
	}
	assert.Nil(t, enricher.EnrichSpan(inspectorListSpan, traceID, [8]byte{9}, 301, 400).Mocker)

	inspectorUpgradeSpan := &request.Span{
		Type:     request.EventTypeHTTP,
		Method:   "GET",
		Path:     "/bdefca03-103e-43d3-b398-cdf45e2be9ca",
		HostPort: 9229,
		Status:   http.StatusSwitchingProtocols,
	}
	assert.Nil(t, enricher.EnrichSpan(inspectorUpgradeSpan, traceID, [8]byte{10}, 401, 500).Mocker)
}

func TestPostgresPooledStaleWriteOffsetAndInFlightConsume(t *testing.T) {
	tracker := NewWriteContextTracker(64, time.Minute)
	trace1 := [16]byte{0x41, 1}
	trace2 := [16]byte{0x42, 2}

	tracker.RecordWrite(SocketWriteContext{
		SockCookie: 777,
		ByteOffset: 0,
		PayloadLen: 48,
		TraceID:    trace1,
	})
	_, ok := lookupWriteInFrameRange(tracker, 777, 48, 96)
	assert.False(t, ok)

	tracker.RecordWrite(SocketWriteContext{
		SockCookie: 777,
		ByteOffset: 48,
		PayloadLen: 48,
		TraceID:    trace2,
	})
	got, ok := lookupWriteInFrameRange(tracker, 777, 48, 96)
	require.True(t, ok)
	assert.Equal(t, trace2, got.TraceID)

	cache := NewHTTPExchangeCache(32, time.Minute)
	cache.BeginInFlightDB()
	go func() {
		time.Sleep(5 * time.Millisecond)
		cache.RecordDatabase(trace2, CapturedDatabaseExchange{
			DBName: "traveldb",
			SQL:    "SELECT id FROM catalog_items WHERE id = $1",
			Result: &DatabaseResult{
				Columns: []DatabaseColumn{{Name: "id", TypeOID: pgOIDInt8}},
				Rows:    [][]any{{"7"}},
			},
		})
		cache.EndInFlightDB()
	}()

	ex, found := cache.ConsumeDatabase(trace2, "SELECT id FROM catalog_items WHERE id = $1", "SELECT", "catalog_items")
	require.True(t, found)
	assert.Equal(t, "traveldb", ex.DBName)

	cache.RecordDatabase(trace1, CapturedDatabaseExchange{
		ClientPort: 54123,
		DBName:     "otadb",
		SQL:        "SELECT id, route_code FROM flight_fares WHERE id = ?",
		Parameters: []any{int64(9)},
		Result: &DatabaseResult{
			Columns: []DatabaseColumn{{Name: "id", MySQLType: mysqlTypeLongLong}},
			Rows:    [][]any{{float64(9)}},
		},
	})
	portMatched, found := cache.ConsumeDatabaseForConn(trace2, 54123, "SELECT id, route_code FROM flight_fares WHERE id = ?", "SELECT", "flight_fares")
	require.True(t, found)
	assert.Equal(t, "otadb", portMatched.DBName)
	_, duplicate := cache.ConsumeDatabase(trace1, "SELECT id, route_code FROM flight_fares WHERE id = ?", "SELECT", "flight_fares")
	assert.False(t, duplicate)

	coalescedAuthAndPrepare := append(
		encodeMySQLWirePacket(1, []byte("handshake-response-payload")),
		encodeMySQLWirePacket(0, append([]byte{mysqlComStmtPrepare}, []byte("SELECT id FROM flight_fares WHERE id = ?")...))...,
	)
	assert.True(t, isNonExecutionSQLWireRequest(coalescedAuthAndPrepare))
	assert.True(t, isMySQLPrepareOKWireResponse(encodeMySQLStmtPrepareOK(1, 1, "otadb", false)))

	traceA := [16]byte{0x51, 1}
	traceB := [16]byte{0x52, 2}
	cache.RecordDatabase(traceA, CapturedDatabaseExchange{
		ClientPort: 54124,
		DBName:     "traveldb",
		SQL:        "SELECT id FROM catalog_items WHERE id = $1",
		Parameters: []any{int64(3)},
	})
	cache.RecordDatabase(traceB, CapturedDatabaseExchange{
		ClientPort: 54124,
		DBName:     "traveldb",
		SQL:        "SELECT id FROM catalog_items WHERE id = $1",
		Parameters: []any{int64(4)},
	})
	gotB, found := cache.ConsumeDatabaseForConn(traceB, 54124, "SELECT id FROM catalog_items WHERE id = $1", "SELECT", "catalog_items")
	require.True(t, found)
	assert.Equal(t, []any{int64(4)}, gotB.Parameters)
	gotA, found := cache.ConsumeDatabaseForConn(traceA, 54124, "SELECT id FROM catalog_items WHERE id = $1", "SELECT", "catalog_items")
	require.True(t, found)
	assert.Equal(t, []any{int64(3)}, gotA.Parameters)

	for i := range 80 {
		tr := [16]byte{0x60, byte(i / 4)}
		key := "py:item:" + strconv.Itoa(i/4) + ":" + strconv.Itoa(i%4)
		cache.RecordRedis(tr, CapturedRedisExchange{
			ClientPort:  54125,
			Command:     "GET",
			ClusterName: "172.20.0.4:6379",
			Keys:        []string{key},
			Reply:       &RedisReply{Type: "$", Str: key},
		})
	}
	for i := 79; i >= 0; i-- {
		tr := [16]byte{0x60, byte(i / 4)}
		key := "py:item:" + strconv.Itoa(i/4) + ":" + strconv.Itoa(i%4)
		rex, rFound := cache.ConsumeRedisForConn(tr, 54125, "GET", []string{key})
		require.True(t, rFound)
		assert.Equal(t, "172.20.0.4:6379", rex.ClusterName)
		assert.Equal(t, []string{key}, rex.Keys)
	}
}

func reserveFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}
