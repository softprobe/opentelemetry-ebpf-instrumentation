// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	maxRESPFrameBytes   = 64 << 20
	maxRESPArrayItems   = 65536
	maxRESPNestingDepth = 16
)

type RedisHandlerOption func(*RedisProtocolHandler)

func WithRedisDialer(dialFn func(ctx context.Context, network, address string) (net.Conn, error)) RedisHandlerOption {
	return func(h *RedisProtocolHandler) {
		if dialFn != nil {
			h.dialContext = dialFn
		}
	}
}

func WithRedisExchangeCache(cache *HTTPExchangeCache) RedisHandlerOption {
	return func(h *RedisProtocolHandler) {
		if cache != nil {
			h.exchangeCache = cache
		}
	}
}

func WithRedisLogExporter(exp *LogExporter) RedisHandlerOption {
	return func(h *RedisProtocolHandler) {
		if exp != nil {
			h.logExporter = exp
		}
	}
}

type redisConnState struct {
	respVersion int
	upConn      net.Conn
	upReader    *bufio.Reader
}

type RedisProtocolHandler struct {
	cfg            Config
	replayRegistry *ReplayRegistry
	writeTracker   *WriteContextTracker
	exchangeCache  *HTTPExchangeCache
	logExporter    *LogExporter
	backendClient  *BackendClient
	dialContext    func(ctx context.Context, network, address string) (net.Conn, error)
	stats          *EgressStats
	log            *slog.Logger
}

func NewRedisProtocolHandler(
	cfg Config,
	replayRegistry *ReplayRegistry,
	writeTracker *WriteContextTracker,
	backendClient *BackendClient,
	opts ...RedisHandlerOption,
) *RedisProtocolHandler {
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

	h := &RedisProtocolHandler{
		cfg:            cfg,
		replayRegistry: replayRegistry,
		writeTracker:   writeTracker,
		exchangeCache:  SharedDataplaneBridge().ExchangeCache(),
		backendClient:  backendClient,
		dialContext:    dialer.DialContext,
		stats:          &EgressStats{},
		log:            slog.With("component", "softprobe.RedisProtocolHandler"),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(h)
		}
	}
	return h
}

func (h *RedisProtocolHandler) Name() string {
	return "redis"
}

func (h *RedisProtocolHandler) Stats() *EgressStats {
	return h.stats
}

func (h *RedisProtocolHandler) CanHandle(preamble []byte, origPort uint16) bool {
	if len(preamble) == 0 {
		return origPort == 6379
	}
	if isTLSClientHello(preamble) {
		return false
	}
	if len(preamble) >= 2 && preamble[0] == '*' && preamble[1] >= '1' && preamble[1] <= '9' {
		return true
	}
	if looksLikeInlineRedisCommand(preamble, origPort == 6379) {
		return true
	}
	return origPort == 6379 && !looksLikeHTTPPreface(preamble)
}

func looksLikeInlineRedisCommand(preamble []byte, isRedisPort bool) bool {
	upper := strings.ToUpper(string(preamble))
	for _, prefix := range []string{
		"PING\r\n",
		"PING ",
		"QUIT\r\n",
		"HELLO",
		"AUTH ",
		"SELECT ",
		"MGET ",
		"MSET ",
		"HGET ",
		"HSET ",
		"HMGET ",
		"HGETALL ",
		"SET ",
		"DEL ",
		"EXISTS ",
		"INCR ",
		"DECR ",
	} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	if isRedisPort && strings.HasPrefix(upper, "GET ") && !strings.HasPrefix(upper, "GET /") {
		return true
	}
	return false
}

func (h *RedisProtocolHandler) HandleConnection(ctx context.Context, oc OutgoingConnectionContext) error {
	state := &redisConnState{
		respVersion: 2,
	}
	defer func() {
		if state.upConn != nil {
			_ = state.upConn.Close()
		}
	}()

	prevOffset := rawConsumedBytes(oc.ClientConn, oc.BufReader)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if _, err := oc.BufReader.Peek(1); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		startOffset := prevOffset
		if oc.BufReader.Buffered() == 0 {
			startOffset = max(prevOffset, rawConsumedBytes(oc.ClientConn, oc.BufReader))
		}
		tokens, rawCmd, err := readRESPClientCommand(oc.BufReader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		endOffset := rawConsumedBytes(oc.ClientConn, oc.BufReader)
		prevOffset = endOffset
		if len(tokens) == 0 {
			continue
		}

		cmd, keys, fields := splitRedisCommandTokens(tokens)
		traceID, serverSpanID, sess, isReplay := h.resolveSocketSession(ctx, oc.SockCookie, startOffset, endOffset)
		if !isReplay || sess == nil {
			if err := h.forwardLiveCommand(ctx, oc, state, cmd, keys, fields, rawCmd, traceID, startOffset, endOffset); err != nil {
				return err
			}
			continue
		}

		quit, err := h.handleReplayCommand(ctx, oc, state, tokens, cmd, keys, fields, rawCmd, traceID, serverSpanID, sess, startOffset, endOffset)
		if err != nil {
			return err
		}
		if quit {
			return nil
		}
	}
}

func (h *RedisProtocolHandler) resolveSocketSession(
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
			if sess, replay := h.replayRegistry.Lookup(wctx.TraceID); replay && sess != nil {
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
				if sess, replay := h.replayRegistry.Lookup(wctx.TraceID); replay && sess != nil {
					return wctx.TraceID, wctx.ServerSpanID, sess, true
				}
				return wctx.TraceID, wctx.ServerSpanID, nil, false
			}
		}
	}
	return [16]byte{}, [8]byte{}, nil, false
}

func (h *RedisProtocolHandler) resolvePostForwardTrace(
	ctx context.Context,
	sockCookie uint64,
	fallback [16]byte,
	startOffset uint64,
	endOffset uint64,
) [16]byte {
	if fallback != ([16]byte{}) {
		return fallback
	}
	if sockCookie == 0 || h.writeTracker == nil {
		return [16]byte{}
	}
	if wctx, ok := lookupWriteInFrameRange(h.writeTracker, sockCookie, startOffset, endOffset); ok && wctx.TraceID != ([16]byte{}) {
		return wctx.TraceID
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			break
		}
		time.Sleep(writeContextPollStep)
		if wctx, ok := lookupWriteInFrameRange(h.writeTracker, sockCookie, startOffset, endOffset); ok && wctx.TraceID != ([16]byte{}) {
			return wctx.TraceID
		}
	}
	return [16]byte{}
}

func (h *RedisProtocolHandler) ensureLiveConn(ctx context.Context, oc OutgoingConnectionContext, state *redisConnState) error {
	if state.upConn != nil {
		return nil
	}
	dialCtx, cancel := context.WithTimeout(ctx, defaultUpstreamDialTTL)
	defer cancel()

	h.stats.UpstreamDials.Add(1)
	upConn, err := h.dialContext(dialCtx, "tcp", oc.OrigDst.String())
	if err != nil {
		return err
	}
	state.upConn = upConn
	state.upReader = bufio.NewReaderSize(upConn, defaultProxyBufSize)
	return nil
}

func (h *RedisProtocolHandler) forwardLiveCommand(
	ctx context.Context,
	oc OutgoingConnectionContext,
	state *redisConnState,
	cmd string,
	keys []string,
	fields []string,
	rawCmd []byte,
	traceID [16]byte,
	startOffset uint64,
	endOffset uint64,
) error {
	h.exchangeCache.BeginInFlightRedis()
	inFlight := true
	defer func() {
		if inFlight {
			h.exchangeCache.EndInFlightRedis()
		}
	}()

	if err := h.ensureLiveConn(ctx, oc, state); err != nil {
		return err
	}
	h.stats.LiveForwards.Add(1)
	if _, err := state.upConn.Write(rawCmd); err != nil {
		_ = state.upConn.Close()
		state.upConn = nil
		state.upReader = nil
		return err
	}

	reply, rawReply, err := readRESPReplyFrame(state.upReader, 0)
	if err != nil {
		_ = state.upConn.Close()
		state.upConn = nil
		state.upReader = nil
		return err
	}

	if cmd == "HELLO" && reply.Type != "-" {
		if proto := extractHelloProto(rawCmd); proto == 2 || proto == 3 {
			state.respVersion = proto
		}
	}

	if !isRedisSessionCommand(cmd) && h.exchangeCache != nil {
		resolvedTrace := h.resolvePostForwardTrace(ctx, oc.SockCookie, traceID, startOffset, endOffset)
		clientPort := remoteTCPPort(oc.ClientConn)
		if resolvedTrace != ([16]byte{}) || clientPort != 0 {
			isReplay := false
			if h.replayRegistry != nil && resolvedTrace != ([16]byte{}) {
				_, isReplay = h.replayRegistry.Lookup(resolvedTrace)
			}
			if !isReplay {
				replyCopy := reply
				h.exchangeCache.RecordRedis(resolvedTrace, CapturedRedisExchange{
					ClientPort:  clientPort,
					Command:     cmd,
					ClusterName: oc.OrigDst.String(),
					Keys:        keys,
					Fields:      fields,
					Reply:       &replyCopy,
				})
			}
		}
	}
	inFlight = false
	h.exchangeCache.EndInFlightRedis()

	_, err = oc.ClientConn.Write(rawReply)
	return err
}

func (h *RedisProtocolHandler) handleReplayCommand(
	ctx context.Context,
	oc OutgoingConnectionContext,
	state *redisConnState,
	tokens []string,
	cmd string,
	keys []string,
	fields []string,
	rawCmd []byte,
	traceID [16]byte,
	serverSpanID [8]byte,
	sess *ReplaySession,
	startOffset uint64,
	endOffset uint64,
) (bool, error) {
	switch cmd {
	case "QUIT":
		_, err := oc.ClientConn.Write([]byte("+OK\r\n"))
		return true, err
	case "HELLO":
		proto := state.respVersion
		if len(tokens) >= 2 {
			parsed, err := strconv.Atoi(tokens[1])
			if err != nil || (parsed != 2 && parsed != 3) {
				_, wErr := oc.ClientConn.Write([]byte("-NOPROTO sorry this protocol version is not supported\r\n"))
				return false, wErr
			}
			proto = parsed
			state.respVersion = parsed
		}
		_, err := oc.ClientConn.Write(encodeSyntheticHelloReply(proto))
		return false, err
	case "AUTH", "SELECT", "CLIENT", "RESET", "READONLY", "READWRITE":
		_, err := oc.ClientConn.Write([]byte("+OK\r\n"))
		return false, err
	case "COMMAND":
		_, err := oc.ClientConn.Write([]byte("*0\r\n"))
		return false, err
	case "INFO", "CONFIG":
		_, err := oc.ClientConn.Write([]byte("$0\r\n\r\n"))
		return false, err
	case "CLUSTER":
		_, err := oc.ClientConn.Write([]byte("-ERR This instance has cluster support disabled\r\n"))
		return false, err
	}

	hostAndPort := oc.OrigDst.String()
	localIgnored := sess.ShouldIgnoreMock(ServiceKeyRedis, cmd, hostAndPort) ||
		sess.ShouldIgnoreMock(CategoryRedis.Name, cmd, hostAndPort)

	if h.backendClient == nil {
		if localIgnored {
			h.stats.SkipMockForwards.Add(1)
			return false, h.forwardLiveCommand(ctx, oc, state, cmd, keys, fields, rawCmd, traceID, startOffset, endOffset)
		}
		h.stats.EmptyMissBlocks.Add(1)
		_, err := oc.ClientConn.Write([]byte("-ERR softprobe backend client unavailable\r\n"))
		return false, err
	}

	traceIDHex := sess.RecordedTraceID
	if traceIDHex == "" {
		traceIDHex = FormatTraceIDHex(sess.TraceID)
	}
	segmentID := sess.SegmentID
	if segmentID == "" && serverSpanID != ([8]byte{}) {
		segmentID = FormatSpanIDHex(serverSpanID)
	}

	now := time.Now()
	meta := SpanMetadata{
		AppID:             h.cfg.AppID,
		RecordEnvironment: recordEnvironmentCode(h.cfg.Env),
		RecordVersion:     defaultRecordVersion,
		TraceID:           traceIDHex,
		ReplayID:          sess.ReplayID,
		SegmentID:         segmentID,
		CreationTimeMs:    now.UnixMilli(),
	}

	queryMocker, err := BuildRedisMocker(meta, RedisExchange{
		Command:     cmd,
		ClusterName: hostAndPort,
		Keys:        keys,
		Fields:      fields,
		OrderFree:   true,
	})
	if err != nil {
		h.stats.EmptyMissBlocks.Add(1)
		_, wErr := oc.ClientConn.Write(encodeRESPError("ERR " + err.Error()))
		return false, wErr
	}
	if queryMocker.TargetResponse == nil {
		queryMocker.TargetResponse = &Target{}
	}
	queryMocker.TargetResponse.SetAttribute(AttrRealCallAware, "1")
	if localIgnored {
		queryMocker.TargetResponse.SetAttribute(AttrLocalRelease, "1")
	}

	qCtx, cancel := context.WithTimeout(ctx, defaultUpstreamDialTTL)
	qRes, qErr := h.backendClient.QueryRecord(qCtx, queryMocker, MockStrategyRedis)
	cancel()
	if qErr != nil {
		if localIgnored {
			h.stats.SkipMockForwards.Add(1)
			return false, h.forwardLiveCommand(ctx, oc, state, cmd, keys, fields, rawCmd, traceID, startOffset, endOffset)
		}
		h.stats.EmptyMissBlocks.Add(1)
		_, wErr := oc.ClientConn.Write([]byte("-ERR softprobe backend query failed\r\n"))
		return false, wErr
	}

	switch qRes.Outcome {
	case QueryOutcomeHit:
		reply, err := DecodeRedisReply(qRes.Mocker)
		if err != nil {
			h.stats.EmptyMissBlocks.Add(1)
			_, wErr := oc.ClientConn.Write(encodeRESPError("ERR " + err.Error()))
			return false, wErr
		}
		h.stats.MockHits.Add(1)
		_, err = oc.ClientConn.Write(encodeRESPReply(reply, state.respVersion))
		return false, err
	case QueryOutcomeSkipMock:
		h.stats.SkipMockForwards.Add(1)
		return false, h.forwardLiveCommand(ctx, oc, state, cmd, keys, fields, rawCmd, traceID, startOffset, endOffset)
	case QueryOutcomeMustMock:
		h.stats.MustMockBlocks.Add(1)
		_, err := oc.ClientConn.Write([]byte("-ERR softprobe mustMock miss\r\n"))
		return false, err
	default:
		if localIgnored {
			h.stats.SkipMockForwards.Add(1)
			return false, h.forwardLiveCommand(ctx, oc, state, cmd, keys, fields, rawCmd, traceID, startOffset, endOffset)
		}
		h.stats.EmptyMissBlocks.Add(1)
		_, err := oc.ClientConn.Write([]byte("-ERR softprobe replay mock miss\r\n"))
		return false, err
	}
}

func extractHelloProto(rawCmd []byte) int {
	tokens := parseRESPArrayStrings(rawCmd)
	if len(tokens) < 2 {
		if line, _, ok := readRESPWireLine(rawCmd, 0); ok {
			tokens = strings.Fields(string(line))
		}
	}
	if len(tokens) >= 2 {
		if p, err := strconv.Atoi(tokens[1]); err == nil {
			return p
		}
	}
	return 0
}

func encodeSyntheticHelloReply(proto int) []byte {
	var buf bytes.Buffer
	if proto == 3 {
		buf.WriteString("%7\r\n")
	} else {
		buf.WriteString("*14\r\n")
	}
	writeBulk := func(s string) {
		buf.WriteByte('$')
		buf.WriteString(strconv.Itoa(len(s)))
		buf.WriteString("\r\n")
		buf.WriteString(s)
		buf.WriteString("\r\n")
	}
	writeInt := func(v int) {
		buf.WriteByte(':')
		buf.WriteString(strconv.Itoa(v))
		buf.WriteString("\r\n")
	}

	writeBulk("server")
	writeBulk("redis")
	writeBulk("version")
	writeBulk("7.2.0")
	writeBulk("proto")
	writeInt(proto)
	writeBulk("id")
	writeInt(1)
	writeBulk("mode")
	writeBulk("standalone")
	writeBulk("role")
	writeBulk("master")
	writeBulk("modules")
	buf.WriteString("*0\r\n")
	return buf.Bytes()
}

func encodeRESPError(msg string) []byte {
	clean := strings.NewReplacer("\r", " ", "\n", " ").Replace(strings.TrimSpace(msg))
	if clean == "" {
		clean = "ERR replay error"
	}
	return []byte("-" + clean + "\r\n")
}

func encodeRESPReply(reply *RedisReply, respVersion int) []byte {
	var buf bytes.Buffer
	writeRESPReply(&buf, reply, respVersion)
	return buf.Bytes()
}

func writeRESPReply(buf *bytes.Buffer, reply *RedisReply, respVersion int) {
	if reply == nil {
		if respVersion == 3 {
			buf.WriteString("_\r\n")
		} else {
			buf.WriteString("$-1\r\n")
		}
		return
	}
	if reply.IsNil {
		if respVersion == 3 {
			buf.WriteString("_\r\n")
			return
		}
		if reply.Type == "*" {
			buf.WriteString("*-1\r\n")
			return
		}
		buf.WriteString("$-1\r\n")
		return
	}

	switch reply.Type {
	case "+":
		clean := strings.NewReplacer("\r", " ", "\n", " ").Replace(reply.Str)
		buf.WriteByte('+')
		buf.WriteString(clean)
		buf.WriteString("\r\n")
	case "-":
		clean := strings.NewReplacer("\r", " ", "\n", " ").Replace(reply.Str)
		buf.WriteByte('-')
		buf.WriteString(clean)
		buf.WriteString("\r\n")
	case ":":
		buf.WriteByte(':')
		buf.WriteString(strconv.FormatInt(reply.Int, 10))
		buf.WriteString("\r\n")
	case ",":
		clean := strings.NewReplacer("\r", "", "\n", "").Replace(reply.Str)
		if respVersion == 3 {
			buf.WriteByte(',')
			buf.WriteString(clean)
			buf.WriteString("\r\n")
		} else {
			writeRESPBulkBytes(buf, []byte(clean))
		}
	case "%":
		if respVersion == 3 && len(reply.Elements)%2 == 0 {
			buf.WriteByte('%')
			buf.WriteString(strconv.Itoa(len(reply.Elements) / 2))
			buf.WriteString("\r\n")
		} else {
			buf.WriteByte('*')
			buf.WriteString(strconv.Itoa(len(reply.Elements)))
			buf.WriteString("\r\n")
		}
		for i := range reply.Elements {
			writeRESPReply(buf, &reply.Elements[i], respVersion)
		}
	case "~":
		if respVersion == 3 {
			buf.WriteByte('~')
		} else {
			buf.WriteByte('*')
		}
		buf.WriteString(strconv.Itoa(len(reply.Elements)))
		buf.WriteString("\r\n")
		for i := range reply.Elements {
			writeRESPReply(buf, &reply.Elements[i], respVersion)
		}
	case "*":
		buf.WriteByte('*')
		buf.WriteString(strconv.Itoa(len(reply.Elements)))
		buf.WriteString("\r\n")
		for i := range reply.Elements {
			writeRESPReply(buf, &reply.Elements[i], respVersion)
		}
	default:
		data := reply.Bulk
		if data == nil && reply.Str != "" {
			data = []byte(reply.Str)
		}
		writeRESPBulkBytes(buf, data)
	}
}

func writeRESPBulkBytes(buf *bytes.Buffer, data []byte) {
	buf.WriteByte('$')
	buf.WriteString(strconv.Itoa(len(data)))
	buf.WriteString("\r\n")
	if len(data) > 0 {
		buf.Write(data)
	}
	buf.WriteString("\r\n")
}

func readRESPClientCommand(r *bufio.Reader) ([]string, []byte, error) {
	first, err := r.Peek(1)
	if err != nil {
		return nil, nil, err
	}

	var raw bytes.Buffer
	if first[0] != '*' {
		line, rawLine, err := readRESPLineFromReader(r)
		if err != nil {
			return nil, nil, err
		}
		raw.Write(rawLine)
		return strings.Fields(string(line)), raw.Bytes(), nil
	}

	hdr, rawHdr, err := readRESPLineFromReader(r)
	if err != nil {
		return nil, nil, err
	}
	raw.Write(rawHdr)
	if len(hdr) < 2 || hdr[0] != '*' {
		return nil, nil, errors.New("malformed RESP multibulk header")
	}
	count, err := strconv.Atoi(string(hdr[1:]))
	if err != nil || count < 0 || count > maxRESPArrayItems {
		return nil, nil, fmt.Errorf("invalid RESP argument count: %q", string(hdr))
	}
	if count == 0 {
		return nil, raw.Bytes(), nil
	}

	tokens := make([]string, 0, count)
	for range count {
		bulkHdr, rawBulkHdr, err := readRESPLineFromReader(r)
		if err != nil {
			return nil, nil, err
		}
		raw.Write(rawBulkHdr)
		if len(bulkHdr) < 2 || bulkHdr[0] != '$' {
			return nil, nil, fmt.Errorf("expected RESP bulk argument, got %q", string(bulkHdr))
		}
		bulkLen, err := strconv.Atoi(string(bulkHdr[1:]))
		if err != nil || bulkLen < 0 || bulkLen > maxRESPFrameBytes {
			return nil, nil, fmt.Errorf("invalid RESP bulk argument length: %q", string(bulkHdr))
		}
		payload := make([]byte, bulkLen+2)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, nil, err
		}
		if payload[bulkLen] != '\r' || payload[bulkLen+1] != '\n' {
			return nil, nil, errors.New("missing CRLF after RESP bulk argument")
		}
		raw.Write(payload)
		tokens = append(tokens, string(payload[:bulkLen]))
	}
	return tokens, raw.Bytes(), nil
}

func readRESPReplyFrame(r *bufio.Reader, depth int) (RedisReply, []byte, error) {
	if depth > maxRESPNestingDepth {
		return RedisReply{}, nil, errors.New("RESP nesting depth exceeded")
	}
	line, rawLine, err := readRESPLineFromReader(r)
	if err != nil {
		return RedisReply{}, nil, err
	}
	if len(line) == 0 {
		return RedisReply{}, nil, errors.New("empty RESP reply line")
	}

	var raw bytes.Buffer
	raw.Write(rawLine)

	switch line[0] {
	case '+':
		return RedisReply{Type: "+", Str: string(line[1:])}, raw.Bytes(), nil
	case '-':
		return RedisReply{Type: "-", Str: string(line[1:])}, raw.Bytes(), nil
	case ':':
		v, err := strconv.ParseInt(string(line[1:]), 10, 64)
		if err != nil {
			return RedisReply{}, nil, err
		}
		return RedisReply{Type: ":", Int: v}, raw.Bytes(), nil
	case ',':
		return RedisReply{Type: ",", Str: string(line[1:])}, raw.Bytes(), nil
	case '_':
		return RedisReply{Type: "$", IsNil: true}, raw.Bytes(), nil
	case '#':
		val := int64(0)
		if len(line) >= 2 && line[1] == 't' {
			val = 1
		}
		return RedisReply{Type: ":", Int: val}, raw.Bytes(), nil
	case '$', '=', '!':
		bulkLen, err := strconv.Atoi(string(line[1:]))
		if err != nil {
			return RedisReply{}, nil, err
		}
		if bulkLen < 0 {
			return RedisReply{Type: "$", IsNil: true}, raw.Bytes(), nil
		}
		if bulkLen > maxRESPFrameBytes {
			return RedisReply{}, nil, fmt.Errorf("RESP bulk reply exceeds limit: %d", bulkLen)
		}
		payload := make([]byte, bulkLen+2)
		if _, err := io.ReadFull(r, payload); err != nil {
			return RedisReply{}, nil, err
		}
		raw.Write(payload)
		data := make([]byte, bulkLen)
		copy(data, payload[:bulkLen])
		if line[0] == '!' {
			return RedisReply{Type: "-", Str: string(data)}, raw.Bytes(), nil
		}
		return RedisReply{
			Type: "$",
			Bulk: data,
			Str:  string(data),
		}, raw.Bytes(), nil
	case '*', '~':
		arrLen, err := strconv.Atoi(string(line[1:]))
		if err != nil {
			return RedisReply{}, nil, err
		}
		if arrLen < 0 {
			return RedisReply{Type: "*", IsNil: true}, raw.Bytes(), nil
		}
		if arrLen > maxRESPArrayItems {
			return RedisReply{}, nil, fmt.Errorf("RESP array exceeds limit: %d", arrLen)
		}
		elems := make([]RedisReply, 0, arrLen)
		for range arrLen {
			elem, elemRaw, err := readRESPReplyFrame(r, depth+1)
			if err != nil {
				return RedisReply{}, nil, err
			}
			raw.Write(elemRaw)
			elems = append(elems, elem)
		}
		typ := "*"
		if line[0] == '~' {
			typ = "~"
		}
		return RedisReply{Type: typ, Elements: elems}, raw.Bytes(), nil
	case '%':
		pairCount, err := strconv.Atoi(string(line[1:]))
		if err != nil {
			return RedisReply{}, nil, err
		}
		if pairCount < 0 {
			return RedisReply{Type: "%", IsNil: true}, raw.Bytes(), nil
		}
		if pairCount > maxRESPArrayItems/2 {
			return RedisReply{}, nil, fmt.Errorf("RESP map exceeds limit: %d", pairCount)
		}
		total := pairCount * 2
		elems := make([]RedisReply, 0, total)
		for range total {
			elem, elemRaw, err := readRESPReplyFrame(r, depth+1)
			if err != nil {
				return RedisReply{}, nil, err
			}
			raw.Write(elemRaw)
			elems = append(elems, elem)
		}
		return RedisReply{Type: "%", Elements: elems}, raw.Bytes(), nil
	case '|':
		pairCount, err := strconv.Atoi(string(line[1:]))
		if err != nil || pairCount < 0 || pairCount > maxRESPArrayItems/2 {
			return RedisReply{}, nil, fmt.Errorf("invalid RESP attribute count: %q", string(line))
		}
		for range pairCount * 2 {
			_, attrRaw, err := readRESPReplyFrame(r, depth+1)
			if err != nil {
				return RedisReply{}, nil, err
			}
			raw.Write(attrRaw)
		}
		reply, nextRaw, err := readRESPReplyFrame(r, depth+1)
		if err != nil {
			return RedisReply{}, nil, err
		}
		raw.Write(nextRaw)
		return reply, raw.Bytes(), nil
	default:
		return RedisReply{Type: "+", Str: string(line)}, raw.Bytes(), nil
	}
}

func readRESPLineFromReader(r *bufio.Reader) ([]byte, []byte, error) {
	var raw bytes.Buffer
	for {
		chunk, err := r.ReadSlice('\n')
		raw.Write(chunk)
		if raw.Len() > maxRESPFrameBytes {
			return nil, nil, errors.New("RESP line exceeds limit")
		}
		if err == nil {
			b := raw.Bytes()
			if len(b) < 2 || b[len(b)-2] != '\r' {
				return nil, nil, errors.New("malformed RESP line ending")
			}
			return b[:len(b)-2], b, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, nil, err
		}
	}
}
