// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/net/http2"
)

const (
	HeaderSoftprobeError = "X-Softprobe-Error"
	ErrorCodeMustMock    = "MUST_MOCK"
	ErrorCodeMockMiss    = "MOCK_MISS"
	ErrorCodeQueryError  = "QUERY_ERROR"

	writeContextPollBudget = 15 * time.Millisecond
	writeContextPollStep   = 250 * time.Microsecond
	defaultUpstreamTimeout = 30 * time.Second
)

type CountingConn struct {
	net.Conn
	bytesRead atomic.Uint64
}

func NewCountingConn(c net.Conn) *CountingConn {
	return &CountingConn{Conn: c}
}

func (c *CountingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.bytesRead.Add(uint64(n))
	}
	return n, err
}

func (c *CountingConn) BytesRead() uint64 {
	return c.bytesRead.Load()
}

type prebufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (p *prebufferedConn) Read(b []byte) (int, error) {
	return p.reader.Read(b)
}

type OutgoingConnectionContext struct {
	ClientConn *CountingConn
	BufReader  *bufio.Reader
	SockCookie uint64
	OrigDst    netip.AddrPort
	CallerPID  uint32
}

type OutgoingProtocolHandler interface {
	Name() string
	CanHandle(preamble []byte, origPort uint16) bool
	HandleConnection(ctx context.Context, conn OutgoingConnectionContext) error
}

type ServerFirstProtocolHandler interface {
	OutgoingProtocolHandler
	IsServerFirstPort(origPort uint16) bool
}

type EgressStats struct {
	LiveForwards     atomic.Uint64
	MockHits         atomic.Uint64
	MustMockBlocks   atomic.Uint64
	SkipMockForwards atomic.Uint64
	EmptyMissBlocks  atomic.Uint64
	UpstreamDials    atomic.Uint64
}

type HTTPHandlerOption func(*HTTPProtocolHandler)

func WithUpstreamTLSConfig(cfg *tls.Config) HTTPHandlerOption {
	return func(h *HTTPProtocolHandler) {
		h.upstreamBaseTLS = cfg
	}
}

func WithEgressDialer(dialFn func(ctx context.Context, network, address string) (net.Conn, error)) HTTPHandlerOption {
	return func(h *HTTPProtocolHandler) {
		if dialFn != nil {
			h.dialContext = dialFn
		}
	}
}

func WithHTTPExchangeCache(cache *HTTPExchangeCache) HTTPHandlerOption {
	return func(h *HTTPProtocolHandler) {
		if cache != nil {
			h.exchangeCache = cache
		}
	}
}

func WithHTTPLogExporter(exp *LogExporter) HTTPHandlerOption {
	return func(h *HTTPProtocolHandler) {
		if exp != nil {
			h.logExporter = exp
		}
	}
}

type HTTPProtocolHandler struct {
	cfg             Config
	ca              *EphemeralCA
	replayRegistry  *ReplayRegistry
	writeTracker    *WriteContextTracker
	exchangeCache   *HTTPExchangeCache
	logExporter     *LogExporter
	backendClient   *BackendClient
	upstreamBaseTLS *tls.Config
	dialContext     func(ctx context.Context, network, address string) (net.Conn, error)
	stats           *EgressStats
	log             *slog.Logger

	transportsMu sync.Mutex
	transports   map[upstreamKey]*http.Transport
}

type upstreamKey struct {
	origDst    netip.AddrPort
	useTLS     bool
	serverName string
}

func NewHTTPProtocolHandler(
	cfg Config,
	ca *EphemeralCA,
	replayRegistry *ReplayRegistry,
	writeTracker *WriteContextTracker,
	backendClient *BackendClient,
	opts ...HTTPHandlerOption,
) *HTTPProtocolHandler {
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

	h := &HTTPProtocolHandler{
		cfg:            cfg,
		ca:             ca,
		replayRegistry: replayRegistry,
		writeTracker:   writeTracker,
		exchangeCache:  SharedDataplaneBridge().ExchangeCache(),
		backendClient:  backendClient,
		dialContext:    dialer.DialContext,
		stats:          &EgressStats{},
		log:            slog.With("component", "softprobe.HTTPProtocolHandler"),
		transports:     make(map[upstreamKey]*http.Transport),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

func (h *HTTPProtocolHandler) Name() string {
	return "http_tls"
}

func (h *HTTPProtocolHandler) Stats() *EgressStats {
	return h.stats
}

func (h *HTTPProtocolHandler) Close() {
	h.transportsMu.Lock()
	defer h.transportsMu.Unlock()
	for k, tr := range h.transports {
		tr.CloseIdleConnections()
		delete(h.transports, k)
	}
}

func (h *HTTPProtocolHandler) CanHandle(preamble []byte, _ uint16) bool {
	if isTLSClientHello(preamble) {
		return h.ca != nil
	}
	return looksLikeHTTPPreface(preamble)
}

func isTLSClientHello(preamble []byte) bool {
	return len(preamble) >= 3 && preamble[0] == 0x16 && preamble[1] == 0x03 && preamble[2] <= 0x04
}

func (h *HTTPProtocolHandler) HandleConnection(ctx context.Context, oc OutgoingConnectionContext) error {
	peek, err := oc.BufReader.Peek(min(defaultProxyBufSize, 8))
	if err != nil && len(peek) == 0 {
		return nil
	}

	if isTLSClientHello(peek) {
		return h.handleTLSConnection(ctx, oc)
	}

	if strings.HasPrefix(string(peek), "PRI ") {
		return h.serveHTTP2Connection(ctx, &prebufferedConn{Conn: oc.ClientConn, reader: oc.BufReader}, oc, false, "", 0)
	}
	return h.serveHTTP1Loop(ctx, oc.ClientConn, oc.BufReader, nil, oc, false, "", 0)
}

func (h *HTTPProtocolHandler) handleTLSConnection(ctx context.Context, oc OutgoingConnectionContext) error {
	var sniMu sync.Mutex
	var clientSNI string

	fallbackHost := oc.OrigDst.Addr().String()
	tlsCfg := h.ca.ServerTLSConfig(fallbackHost, func(hello *tls.ClientHelloInfo) {
		sniMu.Lock()
		clientSNI = strings.TrimSpace(hello.ServerName)
		sniMu.Unlock()
	})

	tlsConn := tls.Server(&prebufferedConn{Conn: oc.ClientConn, reader: oc.BufReader}, tlsCfg)
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("tls handshake with client: %w", err)
	}
	postHandshakeRawOffset := rawConsumedBytes(oc.ClientConn, oc.BufReader)

	sniMu.Lock()
	negotiatedSNI := clientSNI
	sniMu.Unlock()
	if negotiatedSNI == "" {
		negotiatedSNI = strings.TrimSpace(tlsConn.ConnectionState().ServerName)
	}
	alpn := tlsConn.ConnectionState().NegotiatedProtocol

	if alpn == "h2" {
		return h.serveHTTP2Connection(ctx, tlsConn, oc, true, negotiatedSNI, postHandshakeRawOffset)
	}

	tlsBuf := bufio.NewReaderSize(tlsConn, defaultProxyBufSize)
	plainPeek, err := tlsBuf.Peek(min(defaultProxyBufSize, 8))
	if err != nil && len(plainPeek) == 0 {
		return nil
	}
	if strings.HasPrefix(string(plainPeek), "PRI ") {
		return h.serveHTTP2Connection(ctx, &prebufferedConn{Conn: tlsConn, reader: tlsBuf}, oc, true, negotiatedSNI, postHandshakeRawOffset)
	}
	if !looksLikeHTTPPreface(plainPeek) {
		return h.spliceNonHTTPTLS(ctx, tlsConn, tlsBuf, oc.OrigDst, negotiatedSNI)
	}

	return h.serveHTTP1Loop(ctx, tlsConn, tlsBuf, oc.BufReader, oc, true, negotiatedSNI, postHandshakeRawOffset)
}

func (h *HTTPProtocolHandler) spliceNonHTTPTLS(
	ctx context.Context,
	clientTLS net.Conn,
	clientBuf *bufio.Reader,
	origDst netip.AddrPort,
	sni string,
) error {
	if !origDst.IsValid() {
		return errors.New("missing original destination for TLS passthrough")
	}
	h.stats.UpstreamDials.Add(1)
	rawUpstream, err := h.dialContext(ctx, "tcp", origDst.String())
	if err != nil {
		return err
	}
	upCfg := h.cloneUpstreamTLSConfig(sni, origDst.Addr().String(), false)
	upTLS := tls.Client(rawUpstream, upCfg)
	defer func() { _ = upTLS.Close() }()
	if err := upTLS.HandshakeContext(ctx); err != nil {
		return err
	}
	spliceConnections(clientTLS, clientBuf, upTLS)
	return nil
}

func rawConsumedBytes(cc *CountingConn, rawPrebuf *bufio.Reader) uint64 {
	total := cc.BytesRead()
	if rawPrebuf != nil {
		buffered := uint64(rawPrebuf.Buffered())
		if total >= buffered {
			return total - buffered
		}
	}
	return total
}

func (h *HTTPProtocolHandler) serveHTTP1Loop(
	ctx context.Context,
	rwConn net.Conn,
	reqBuf *bufio.Reader,
	outerPrebuf *bufio.Reader,
	oc OutgoingConnectionContext,
	isTLS bool,
	sni string,
	initialRawOffset uint64,
) error {
	rawPrebuf := outerPrebuf
	if !isTLS {
		rawPrebuf = reqBuf
	}

	prevRawOffset := initialRawOffset
	for {
		rawStart := prevRawOffset
		if reqBuf.Buffered() == 0 {
			rawStart = max(prevRawOffset, rawConsumedBytes(oc.ClientConn, rawPrebuf))
		}
		req, err := http.ReadRequest(reqBuf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return nil
		}

		reqBody, bodyErr := readFullBody(req.Body)
		_ = req.Body.Close()
		if bodyErr != nil {
			return bodyErr
		}
		rawEnd := rawConsumedBytes(oc.ClientConn, rawPrebuf)
		prevRawOffset = rawEnd

		resp, closeAfter, err := h.mediateRequest(ctx, req, reqBody, oc, isTLS, sni, rawStart, rawEnd)
		if err != nil {
			errResp := synthesizeErrorResponse(req, "UPSTREAM_ERROR", err.Error())
			normalizeHTTP1WireResponse(req, errResp)
			_ = errResp.Write(rwConn)
			return err
		}
		normalizeHTTP1WireResponse(req, resp)
		writeErr := resp.Write(rwConn)
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		if writeErr != nil || closeAfter || req.Close || resp.Close {
			return writeErr
		}
	}
}

func (h *HTTPProtocolHandler) serveHTTP2Connection(
	ctx context.Context,
	conn net.Conn,
	oc OutgoingConnectionContext,
	isTLS bool,
	sni string,
	initialRawOffset uint64,
) error {
	var offsetMu sync.Mutex
	lastRawOffset := initialRawOffset

	h2Srv := &http2.Server{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		reqBody, err := readFullBody(req.Body)
		if req.Body != nil {
			_ = req.Body.Close()
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		offsetMu.Lock()
		rawStart := lastRawOffset
		rawEnd := oc.ClientConn.BytesRead()
		if rawEnd > lastRawOffset {
			lastRawOffset = rawEnd
		}
		offsetMu.Unlock()

		resp, _, mediateErr := h.mediateRequest(req.Context(), req, reqBody, oc, isTLS, sni, rawStart, rawEnd)
		if mediateErr != nil {
			resp = synthesizeErrorResponse(req, "UPSTREAM_ERROR", mediateErr.Error())
		}
		defer func() {
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
		}()

		for k, vals := range resp.Header {
			if isHopByHopH2Header(k) {
				continue
			}
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if resp.Body != nil {
			_, _ = io.Copy(w, resp.Body)
		}
	})

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)

	h2Srv.ServeConn(conn, &http2.ServeConnOpts{
		Context: ctx,
		Handler: handler,
	})
	return nil
}

func normalizeHTTP1WireResponse(req *http.Request, resp *http.Response) {
	if resp == nil {
		return
	}
	minor := 1
	if req != nil && req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		minor = 0
	}
	resp.ProtoMajor = 1
	resp.ProtoMinor = minor
	if minor == 0 {
		resp.Proto = "HTTP/1.0"
	} else {
		resp.Proto = "HTTP/1.1"
	}
	codeStr := strconv.Itoa(resp.StatusCode)
	reason := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(resp.Status), codeStr))
	if reason == "" {
		reason = http.StatusText(resp.StatusCode)
	}
	if reason != "" {
		resp.Status = codeStr + " " + reason
	} else {
		resp.Status = codeStr
	}
}

func isHopByHopH2Header(k string) bool {
	switch strings.ToLower(k) {
	case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func (h *HTTPProtocolHandler) mediateRequest(
	ctx context.Context,
	req *http.Request,
	rawReqBody []byte,
	oc OutgoingConnectionContext,
	isTLS bool,
	sni string,
	rawStart uint64,
	rawEnd uint64,
) (*http.Response, bool, error) {
	traceID, serverSpanID, hasTrace := h.resolveOutboundTrace(ctx, req.Header, oc.SockCookie, rawStart, rawEnd)
	if !hasTrace {
		resp, wireRespBody, err := h.forwardLiveRequestWithBody(ctx, req, rawReqBody, oc.OrigDst, isTLS, sni)
		if err == nil && resp != nil {
			if resolvedID, ok := h.resolvePostForwardTrace(ctx, oc.SockCookie, rawStart, rawEnd); ok {
				h.recordLiveExchange(resolvedID, req, rawReqBody, resp, wireRespBody)
			}
		}
		return resp, false, err
	}

	sess, isReplay := h.replayRegistry.Lookup(traceID)
	if !isReplay || sess == nil {
		resp, wireRespBody, err := h.forwardLiveRequestWithBody(ctx, req, rawReqBody, oc.OrigDst, isTLS, sni)
		if err == nil && resp != nil {
			h.recordLiveExchange(traceID, req, rawReqBody, resp, wireRespBody)
		}
		return resp, false, err
	}

	return h.handleReplayOutbound(ctx, req, rawReqBody, oc, isTLS, sni, sess, serverSpanID)
}

func (h *HTTPProtocolHandler) resolvePostForwardTrace(
	ctx context.Context,
	sockCookie uint64,
	rawStart uint64,
	rawEnd uint64,
) ([16]byte, bool) {
	if sockCookie == 0 || h.writeTracker == nil {
		return [16]byte{}, false
	}
	pollEnd := max(rawEnd, 1)
	if wctx, ok := h.writeTracker.LookupInRange(sockCookie, rawStart, pollEnd); ok && wctx.TraceID != ([16]byte{}) {
		return wctx.TraceID, true
	}
	deadline := time.Now().Add(5 * time.Millisecond)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			break
		}
		time.Sleep(writeContextPollStep)
		if wctx, ok := h.writeTracker.LookupInRange(sockCookie, rawStart, pollEnd); ok && wctx.TraceID != ([16]byte{}) {
			return wctx.TraceID, true
		}
	}
	return [16]byte{}, false
}

func (h *HTTPProtocolHandler) recordLiveExchange(
	traceID [16]byte,
	req *http.Request,
	rawReqBody []byte,
	resp *http.Response,
	wireRespBody []byte,
) {
	if h.exchangeCache == nil || traceID == ([16]byte{}) || req == nil || resp == nil {
		return
	}
	if h.replayRegistry != nil {
		if _, isReplay := h.replayRegistry.Lookup(traceID); isReplay {
			return
		}
	}

	reqPath := "/"
	rawQuery := ""
	if req.URL != nil {
		if req.URL.Path != "" {
			reqPath = req.URL.Path
		}
		rawQuery = req.URL.RawQuery
	}

	decodedReq, _ := decodeHTTPBody(rawReqBody, req.Header.Get("Content-Encoding"), h.cfg.MaxBodyBytes)
	decodedResp, wasDecoded := decodeHTTPBody(wireRespBody, resp.Header.Get("Content-Encoding"), h.cfg.MaxBodyBytes)

	cleanHeader := resp.Header.Clone()
	if wasDecoded {
		cleanHeader.Del("Content-Encoding")
		cleanHeader.Del("Transfer-Encoding")
		cleanHeader.Set("Content-Length", strconv.Itoa(len(decodedResp)))
	}
	flatHeaders, tupleHeaders := flattenAndTupleHTTPHeader(cleanHeader)

	codeStr := strconv.Itoa(resp.StatusCode)
	statusReason := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(resp.Status), codeStr))
	if statusReason == "" {
		statusReason = http.StatusText(resp.StatusCode)
	}

	h.exchangeCache.RecordHTTPClient(traceID, req.Method, reqPath, CapturedHTTPClientExchange{
		QueryString:  rawQuery,
		ContentType:  req.Header.Get("Content-Type"),
		RequestBody:  decodedReq,
		StatusCode:   resp.StatusCode,
		StatusReason: statusReason,
		RespHeaders:  flatHeaders,
		HeaderTuples: tupleHeaders,
		ResponseBody: decodedResp,
	})
}

func (h *HTTPProtocolHandler) resolveOutboundTrace(
	ctx context.Context,
	headers http.Header,
	sockCookie uint64,
	rawStart uint64,
	rawEnd uint64,
) ([16]byte, [8]byte, bool) {
	var (
		fallbackTraceID [16]byte
		fallbackSpanID  [8]byte
		hasFallback     bool
	)
	if headers != nil {
		if rawTS := strings.TrimSpace(headers.Get(HeaderTracestate)); rawTS != "" {
			if ts, ok := ParseTracestate(rawTS); ok && ts.RecordedTraceID != "" {
				if parsed, err := ParseTraceIDHex(ts.RecordedTraceID); err == nil {
					if h.replayRegistry == nil || h.replayRegistry.Len() == 0 {
						return parsed, [8]byte{}, true
					}
					if _, ok := h.replayRegistry.Lookup(parsed); ok {
						return parsed, [8]byte{}, true
					}
					fallbackTraceID = parsed
					hasFallback = true
				}
			}
		}
		if rawTP := strings.TrimSpace(headers.Get(HeaderTraceparent)); rawTP != "" {
			if tc, err := ParseTraceparent(rawTP); err == nil {
				if h.replayRegistry == nil || h.replayRegistry.Len() == 0 {
					return tc.TraceID, tc.SpanID, true
				}
				if _, ok := h.replayRegistry.Lookup(tc.TraceID); ok {
					return tc.TraceID, tc.SpanID, true
				}
				if !hasFallback {
					fallbackTraceID = tc.TraceID
					fallbackSpanID = tc.SpanID
					hasFallback = true
				}
			}
		}
	}

	if sockCookie == 0 || h.writeTracker == nil {
		return fallbackTraceID, fallbackSpanID, hasFallback
	}

	if wctx, ok := h.writeTracker.LookupInRange(sockCookie, rawStart, rawEnd); ok && wctx.TraceID != ([16]byte{}) {
		return wctx.TraceID, wctx.ServerSpanID, true
	}

	if h.replayRegistry != nil && h.replayRegistry.Len() > 0 {
		deadline := time.Now().Add(writeContextPollBudget)
		for time.Now().Before(deadline) {
			if ctx.Err() != nil {
				break
			}
			time.Sleep(writeContextPollStep)
			pollEnd := max(rawEnd, 1)
			if wctx, ok := h.writeTracker.LookupInRange(sockCookie, rawStart, pollEnd); ok && wctx.TraceID != ([16]byte{}) {
				return wctx.TraceID, wctx.ServerSpanID, true
			}
		}
	}

	return fallbackTraceID, fallbackSpanID, hasFallback
}

func (h *HTTPProtocolHandler) handleReplayOutbound(
	ctx context.Context,
	req *http.Request,
	rawReqBody []byte,
	oc OutgoingConnectionContext,
	isTLS bool,
	sni string,
	sess *ReplaySession,
	serverSpanID [8]byte,
) (*http.Response, bool, error) {
	reqPath := "/"
	rawQuery := ""
	if req.URL != nil {
		if req.URL.Path != "" {
			reqPath = req.URL.Path
		}
		rawQuery = req.URL.RawQuery
	}

	hostAndPort := req.Host
	if hostAndPort == "" && oc.OrigDst.IsValid() {
		hostAndPort = oc.OrigDst.String()
	}

	localIgnored := sess.ShouldIgnoreMock(ServiceKeyHTTP, reqPath, hostAndPort) ||
		sess.ShouldIgnoreMock(CategoryHTTPClient.Name, reqPath, hostAndPort)

	if h.backendClient == nil {
		if localIgnored {
			h.stats.SkipMockForwards.Add(1)
			h.emitReplayAgentLog(sess, serverSpanID, "INFO", fmt.Sprintf("softprobe replay local-ignore forwarded HttpClient %s %s", req.Method, reqPath))
			resp, err := h.forwardLiveRequest(ctx, req, rawReqBody, oc.OrigDst, isTLS, sni)
			return resp, false, err
		}
		h.stats.EmptyMissBlocks.Add(1)
		h.emitReplayAgentLog(sess, serverSpanID, "WARN", fmt.Sprintf("softprobe replay mock miss HttpClient %s %s", req.Method, reqPath))
		return synthesizeErrorResponse(req, ErrorCodeMockMiss, fmt.Sprintf("replay mock miss for %s %s", req.Method, reqPath)), false, nil
	}

	decodedReqBody, _ := decodeHTTPBody(rawReqBody, req.Header.Get("Content-Encoding"), h.cfg.MaxBodyBytes)
	traceIDHex := sess.RecordedTraceID
	if traceIDHex == "" {
		traceIDHex = FormatTraceIDHex(sess.TraceID)
	}
	segmentID := sess.SegmentID
	if segmentID == "" && serverSpanID != ([8]byte{}) {
		segmentID = FormatSpanIDHex(serverSpanID)
	}

	now := time.Now()
	queryMocker, err := BuildHTTPClientMocker(SpanMetadata{
		AppID:             h.cfg.AppID,
		TraceID:           traceIDHex,
		ReplayID:          sess.ReplayID,
		SegmentID:         segmentID,
		CreationTimeMs:    now.UnixMilli(),
		RecordEnvironment: recordEnvironmentCode(h.cfg.Env),
		RecordVersion:     defaultRecordVersion,
	}, HTTPClientExchange{
		Method:        req.Method,
		OperationName: reqPath,
		QueryString:   rawQuery,
		ContentType:   req.Header.Get("Content-Type"),
		RequestBody:   decodedReqBody,
	})
	if err != nil {
		h.stats.EmptyMissBlocks.Add(1)
		h.emitReplayAgentLog(sess, serverSpanID, "WARN", fmt.Sprintf("softprobe replay query build error HttpClient %s %s", req.Method, reqPath))
		return synthesizeErrorResponse(req, ErrorCodeQueryError, err.Error()), false, nil
	}
	if queryMocker.TargetResponse == nil {
		queryMocker.TargetResponse = &Target{}
	}
	queryMocker.TargetResponse.SetAttribute(AttrRealCallAware, "1")
	if localIgnored {
		queryMocker.TargetResponse.SetAttribute(AttrLocalRelease, "1")
	}

	qRes, qErr := h.backendClient.QueryRecord(ctx, queryMocker, MockStrategyHTTPClient)
	if qErr != nil {
		if localIgnored {
			h.stats.SkipMockForwards.Add(1)
			h.emitReplayAgentLog(sess, serverSpanID, "INFO", fmt.Sprintf("softprobe replay local-ignore forwarded HttpClient %s %s", req.Method, reqPath))
			resp, fwdErr := h.forwardLiveRequest(ctx, req, rawReqBody, oc.OrigDst, isTLS, sni)
			return resp, false, fwdErr
		}
		h.stats.EmptyMissBlocks.Add(1)
		h.emitReplayAgentLog(sess, serverSpanID, "WARN", fmt.Sprintf("softprobe replay query failed HttpClient %s %s", req.Method, reqPath))
		return synthesizeErrorResponse(req, ErrorCodeQueryError, qErr.Error()), false, nil
	}

	switch qRes.Outcome {
	case QueryOutcomeHit:
		wrapper, decodeErr := DecodeHTTPClientResponse(qRes.Mocker)
		if decodeErr != nil {
			h.stats.EmptyMissBlocks.Add(1)
			h.emitReplayAgentLog(sess, serverSpanID, "WARN", fmt.Sprintf("softprobe replay decode failed HttpClient %s %s", req.Method, reqPath))
			return synthesizeErrorResponse(req, ErrorCodeQueryError, decodeErr.Error()), false, nil
		}
		h.stats.MockHits.Add(1)
		h.emitReplayAgentLog(sess, serverSpanID, "INFO", fmt.Sprintf("softprobe replay mock hit HttpClient %s %s", req.Method, reqPath))
		return buildSynthesizedHTTPResponse(req, wrapper), false, nil

	case QueryOutcomeMustMock:
		h.stats.MustMockBlocks.Add(1)
		h.emitReplayAgentLog(sess, serverSpanID, "WARN", fmt.Sprintf("softprobe replay MUST_MOCK blocked HttpClient %s %s", req.Method, reqPath))
		return synthesizeErrorResponse(req, ErrorCodeMustMock, fmt.Sprintf("outbound %s %s blocked by MUST_MOCK policy", req.Method, reqPath)), false, nil

	case QueryOutcomeSkipMock:
		h.stats.SkipMockForwards.Add(1)
		h.emitReplayAgentLog(sess, serverSpanID, "INFO", fmt.Sprintf("softprobe replay skip-mock forwarded HttpClient %s %s", req.Method, reqPath))
		realResp, fwdErr := h.forwardLiveRequest(ctx, req, rawReqBody, oc.OrigDst, isTLS, sni)
		if fwdErr != nil {
			return nil, true, fwdErr
		}
		if qRes.RealCallID != "" {
			h.reportRealCallResponse(ctx, req, decodedReqBody, realResp, qRes.RealCallID, traceIDHex, sess.ReplayID, segmentID, reqPath, rawQuery)
		}
		return realResp, false, nil

	default:
		if localIgnored {
			h.stats.SkipMockForwards.Add(1)
			h.emitReplayAgentLog(sess, serverSpanID, "INFO", fmt.Sprintf("softprobe replay local-ignore forwarded HttpClient %s %s", req.Method, reqPath))
			realResp, fwdErr := h.forwardLiveRequest(ctx, req, rawReqBody, oc.OrigDst, isTLS, sni)
			return realResp, false, fwdErr
		}
		h.stats.EmptyMissBlocks.Add(1)
		h.emitReplayAgentLog(sess, serverSpanID, "WARN", fmt.Sprintf("softprobe replay mock miss HttpClient %s %s", req.Method, reqPath))
		return synthesizeErrorResponse(req, ErrorCodeMockMiss, fmt.Sprintf("replay mock miss for %s %s", req.Method, reqPath)), false, nil
	}
}

func (h *HTTPProtocolHandler) emitReplayAgentLog(sess *ReplaySession, spanID [8]byte, severity, body string) {
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

func (h *HTTPProtocolHandler) reportRealCallResponse(
	ctx context.Context,
	req *http.Request,
	decodedReqBody []byte,
	realResp *http.Response,
	realCallID string,
	traceIDHex string,
	replayID string,
	segmentID string,
	reqPath string,
	rawQuery string,
) {
	wireBody, err := readFullBody(realResp.Body)
	if realResp.Body != nil {
		_ = realResp.Body.Close()
	}
	realResp.Body = io.NopCloser(bytes.NewReader(wireBody))
	if err != nil {
		return
	}

	decodedResp, wasDecoded := decodeHTTPBody(wireBody, realResp.Header.Get("Content-Encoding"), h.cfg.MaxBodyBytes)
	cleanHeader := realResp.Header.Clone()
	if wasDecoded {
		cleanHeader.Del("Content-Encoding")
		cleanHeader.Del("Transfer-Encoding")
		cleanHeader.Set("Content-Length", strconv.Itoa(len(decodedResp)))
	}
	flatHeaders, tupleHeaders := flattenAndTupleHTTPHeader(cleanHeader)

	wrapper := &HTTPResponseWrapper{
		Status:     realResp.StatusCode,
		StatusCode: realResp.StatusCode,
		Reason:     http.StatusText(realResp.StatusCode),
		Headers:    flatHeaders,
		HeaderList: tupleHeaders,
		BodyBase64: base64.StdEncoding.EncodeToString(decodedResp),
	}
	if len(decodedResp) > 0 && utf8.Valid(decodedResp) {
		wrapper.Body = string(decodedResp)
	}

	now := time.Now()
	realMocker, buildErr := BuildHTTPClientMocker(SpanMetadata{
		AppID:             h.cfg.AppID,
		TraceID:           traceIDHex,
		ReplayID:          replayID,
		SegmentID:         segmentID,
		CreationTimeMs:    now.UnixMilli(),
		RecordEnvironment: recordEnvironmentCode(h.cfg.Env),
		RecordVersion:     defaultRecordVersion,
	}, HTTPClientExchange{
		Method:        req.Method,
		OperationName: reqPath,
		QueryString:   rawQuery,
		ContentType:   req.Header.Get("Content-Type"),
		RequestBody:   decodedReqBody,
		Response:      wrapper,
	})
	if buildErr != nil {
		return
	}
	realMocker.ID = realCallID

	reportCtx, cancel := context.WithTimeout(ctx, defaultSaveResultTTL)
	defer cancel()
	if reportErr := h.backendClient.ReportRealCallResult(reportCtx, realMocker); reportErr != nil {
		h.log.Debug("failed reporting realCallResult", "real_call_id", realCallID, "error", reportErr)
	}
}

func (h *HTTPProtocolHandler) forwardLiveRequest(
	ctx context.Context,
	req *http.Request,
	rawReqBody []byte,
	origDst netip.AddrPort,
	isTLS bool,
	sni string,
) (*http.Response, error) {
	resp, _, err := h.forwardLiveRequestWithBody(ctx, req, rawReqBody, origDst, isTLS, sni)
	return resp, err
}

func (h *HTTPProtocolHandler) forwardLiveRequestWithBody(
	ctx context.Context,
	req *http.Request,
	rawReqBody []byte,
	origDst netip.AddrPort,
	isTLS bool,
	sni string,
) (*http.Response, []byte, error) {
	if !origDst.IsValid() {
		return nil, nil, errors.New("missing original destination for outbound HTTP call")
	}
	h.stats.LiveForwards.Add(1)

	scheme := "http"
	if isTLS {
		scheme = "https"
	}

	serverName := sni
	if serverName == "" && req.Host != "" {
		serverName = normalizeCertHost(req.Host)
	}

	targetAuthority := req.Host
	if targetAuthority == "" {
		if serverName != "" {
			targetAuthority = net.JoinHostPort(serverName, strconv.Itoa(int(origDst.Port())))
		} else {
			targetAuthority = origDst.String()
		}
	}

	reqURI := "/"
	if req.URL != nil && req.URL.RequestURI() != "" {
		reqURI = req.URL.RequestURI()
	}
	fullURL := scheme + "://" + targetAuthority + reqURI

	fwdCtx, cancel := context.WithTimeout(ctx, defaultUpstreamTimeout)
	outReq, err := http.NewRequestWithContext(fwdCtx, req.Method, fullURL, bytes.NewReader(rawReqBody))
	if err != nil {
		cancel()
		return nil, nil, err
	}
	outReq.Host = targetAuthority
	outReq.ContentLength = int64(len(rawReqBody))
	copyForwardHeaders(outReq.Header, req.Header)

	tr := h.transportFor(origDst, isTLS, serverName)
	resp, err := tr.RoundTrip(outReq)
	if err != nil {
		cancel()
		return nil, nil, err
	}

	bodyBytes, readErr := readFullBody(resp.Body)
	_ = resp.Body.Close()
	cancel()
	if readErr != nil {
		return nil, nil, readErr
	}

	resp.TransferEncoding = nil
	resp.Header.Del("Transfer-Encoding")
	resp.ContentLength = int64(len(bodyBytes))
	resp.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return resp, bodyBytes, nil
}

func (h *HTTPProtocolHandler) transportFor(origDst netip.AddrPort, useTLS bool, serverName string) *http.Transport {
	key := upstreamKey{
		origDst:    origDst,
		useTLS:     useTLS,
		serverName: serverName,
	}
	h.transportsMu.Lock()
	defer h.transportsMu.Unlock()

	if existing, ok := h.transports[key]; ok {
		return existing
	}

	targetAddr := origDst.String()
	tr := &http.Transport{
		DisableCompression:  true,
		ForceAttemptHTTP2:   useTLS,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     60 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			h.stats.UpstreamDials.Add(1)
			return h.dialContext(ctx, "tcp", targetAddr)
		},
	}
	if useTLS {
		tr.TLSClientConfig = h.cloneUpstreamTLSConfig(serverName, origDst.Addr().String(), true)
	}
	h.transports[key] = tr
	return tr
}

func (h *HTTPProtocolHandler) cloneUpstreamTLSConfig(serverName, fallbackIP string, allowHTTP2 bool) *tls.Config {
	var cfg *tls.Config
	if h.upstreamBaseTLS != nil {
		cfg = h.upstreamBaseTLS.Clone()
	} else {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if cfg.ServerName == "" {
		if serverName != "" {
			cfg.ServerName = serverName
		} else {
			cfg.ServerName = fallbackIP
		}
	}
	if allowHTTP2 && len(cfg.NextProtos) == 0 {
		cfg.NextProtos = []string{"http/1.1", "h2"}
	}
	return cfg
}

func buildSynthesizedHTTPResponse(req *http.Request, wrapper *HTTPResponseWrapper) *http.Response {
	statusCode := http.StatusOK
	var payload []byte
	var reason string
	headers := make(http.Header)

	if wrapper != nil {
		code := wrapper.Status
		if code == 0 {
			code = wrapper.StatusCode
		}
		if code > 0 {
			statusCode = code
		}
		reason = strings.TrimSpace(wrapper.Reason)
		payload, _ = wrapper.PayloadBytes()

		if len(wrapper.HeaderList) > 0 {
			for _, item := range wrapper.HeaderList {
				if shouldSkipSynthesizedHeader(item.Name, payload) {
					continue
				}
				headers.Add(item.Name, item.Value)
			}
		} else if len(wrapper.Headers) > 0 {
			for k, v := range wrapper.Headers {
				if shouldSkipSynthesizedHeader(k, payload) {
					continue
				}
				headers.Set(k, v)
			}
		}
	}

	if reason == "" {
		reason = http.StatusText(statusCode)
	}
	statusText := strconv.Itoa(statusCode)
	if reason != "" {
		statusText = statusText + " " + reason
	}

	protoMajor, protoMinor := 1, 1
	proto := "HTTP/1.1"
	if req != nil && req.ProtoMajor > 0 {
		protoMajor = req.ProtoMajor
		protoMinor = req.ProtoMinor
		proto = req.Proto
	}

	headers.Set("Content-Length", strconv.Itoa(len(payload)))
	return &http.Response{
		Status:        statusText,
		StatusCode:    statusCode,
		Proto:         proto,
		ProtoMajor:    protoMajor,
		ProtoMinor:    protoMinor,
		Header:        headers,
		Body:          io.NopCloser(bytes.NewReader(payload)),
		ContentLength: int64(len(payload)),
		Request:       req,
	}
}

func shouldSkipSynthesizedHeader(name string, payload []byte) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "transfer-encoding", "content-length", "connection", "keep-alive", "proxy-connection", "upgrade":
		return true
	case "content-encoding":
		return sniffPayloadEncoding(payload) == ""
	default:
		return false
	}
}

func synthesizeErrorResponse(req *http.Request, code, message string) *http.Response {
	doc := map[string]string{
		"error":   "softprobe_egress_replay_error",
		"code":    code,
		"message": message,
	}
	payload, _ := json.Marshal(doc)

	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set(HeaderSoftprobeError, code)
	headers.Set("Content-Length", strconv.Itoa(len(payload)))

	protoMajor, protoMinor := 1, 1
	proto := "HTTP/1.1"
	if req != nil && req.ProtoMajor > 0 {
		protoMajor = req.ProtoMajor
		protoMinor = req.ProtoMinor
		proto = req.Proto
	}

	return &http.Response{
		Status:        "502 Bad Gateway",
		StatusCode:    http.StatusBadGateway,
		Proto:         proto,
		ProtoMajor:    protoMajor,
		ProtoMinor:    protoMinor,
		Header:        headers,
		Body:          io.NopCloser(bytes.NewReader(payload)),
		ContentLength: int64(len(payload)),
		Request:       req,
	}
}

func copyForwardHeaders(dst, src http.Header) {
	if src == nil {
		return
	}
	maps.Copy(dst, src.Clone())
	dst.Del("Proxy-Connection")
}

func readFullBody(rc io.ReadCloser) ([]byte, error) {
	if rc == nil {
		return nil, nil
	}
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	return data, nil
}
