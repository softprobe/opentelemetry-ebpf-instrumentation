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
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultProxyBufSize    = 32768
	defaultUpstreamDialTTL = 5 * time.Second
	defaultSaveResultTTL   = 5 * time.Second
)

type IngressOption func(*IngressListener)

func WithIngressTargetResolver(fn func(net.Conn) (string, error)) IngressOption {
	return func(l *IngressListener) {
		l.resolveTarget = fn
	}
}

func WithIngressDialer(dialFn func(ctx context.Context, network, address string) (net.Conn, error)) IngressOption {
	return func(l *IngressListener) {
		if dialFn != nil {
			l.dialContext = dialFn
		}
	}
}

func WithIngressLogExporter(exp *LogExporter) IngressOption {
	return func(l *IngressListener) {
		if exp != nil {
			l.logExporter = exp
		}
	}
}

type IngressListener struct {
	cfg            Config
	replayRegistry *ReplayRegistry
	backendClient  *BackendClient
	bridge         *DataplaneBridge
	logExporter    *LogExporter
	resolveTarget  func(net.Conn) (string, error)
	dialContext    func(ctx context.Context, network, address string) (net.Conn, error)
	log            *slog.Logger

	mu          sync.Mutex
	ln          net.Listener
	activeConns map[net.Conn]struct{}
	closing     bool
	wg          sync.WaitGroup
	stopOnce    sync.Once
	stopped     chan struct{}
}

func NewIngressListener(
	cfg Config,
	replayRegistry *ReplayRegistry,
	backendClient *BackendClient,
	bridge *DataplaneBridge,
	opts ...IngressOption,
) *IngressListener {
	cfg = cfg.WithDefaults()
	if replayRegistry == nil {
		replayRegistry = SharedReplayRegistry()
	}
	if bridge == nil {
		bridge = SharedDataplaneBridge()
	}
	var dialer net.Dialer
	dialer.Timeout = defaultUpstreamDialTTL
	dialer.SetMultipathTCP(false)

	l := &IngressListener{
		cfg:            cfg,
		replayRegistry: replayRegistry,
		backendClient:  backendClient,
		bridge:         bridge,
		dialContext:    dialer.DialContext,
		log:            slog.With("component", "softprobe.IngressListener"),
		activeConns:    make(map[net.Conn]struct{}),
		stopped:        make(chan struct{}),
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

func (l *IngressListener) Start(ctx context.Context) error {
	addr := fmt.Sprintf("127.0.0.1:%d", l.cfg.IngressProxyPort)
	ln, err := ListenNonMPTCP(ctx, "tcp4", addr)
	if err != nil {
		return fmt.Errorf("listening on softprobe ingress %s: %w", addr, err)
	}

	l.mu.Lock()
	l.ln = ln
	l.mu.Unlock()

	if err := l.bridge.SetIngressListener(ln); err != nil {
		l.log.Warn("initial sockmap registration deferred or failed", "error", err)
	}

	l.wg.Add(1)
	go l.acceptLoop(ctx, ln)
	return nil
}

func (l *IngressListener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln == nil {
		return nil
	}
	return l.ln.Addr()
}

func (l *IngressListener) Close() error {
	var closeErr error
	l.stopOnce.Do(func() {
		close(l.stopped)
		_ = l.bridge.SetIngressListener(nil)
		l.mu.Lock()
		l.closing = true
		ln := l.ln
		l.ln = nil
		conns := make([]net.Conn, 0, len(l.activeConns))
		for c := range l.activeConns {
			conns = append(conns, c)
		}
		l.activeConns = nil
		l.mu.Unlock()
		if ln != nil {
			closeErr = ln.Close()
		}
		for _, c := range conns {
			_ = c.Close()
		}
	})
	l.wg.Wait()
	return closeErr
}

func (l *IngressListener) trackConn(c net.Conn, add bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if add {
		if l.closing || l.activeConns == nil {
			return false
		}
		l.activeConns[c] = struct{}{}
		return true
	}
	if l.activeConns != nil {
		delete(l.activeConns, c)
	}
	return true
}

func (l *IngressListener) acceptLoop(ctx context.Context, ln net.Listener) {
	defer l.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-l.stopped:
				return
			case <-ctx.Done():
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			l.log.Debug("softprobe ingress accept error", "error", err)
			continue
		}

		if !l.trackConn(conn, true) {
			_ = conn.Close()
			return
		}

		l.wg.Add(1)
		go func(c net.Conn) {
			defer l.wg.Done()
			defer l.trackConn(c, false)
			l.handleConn(ctx, c)
		}(conn)
	}
}

func (l *IngressListener) targetAddress(inConn net.Conn) (string, error) {
	if l.resolveTarget != nil {
		return l.resolveTarget(inConn)
	}
	listenerPort := extractPortFromAddr(l.Addr())
	dstPort := extractPortFromAddr(inConn.LocalAddr())
	if dstPort == 0 || dstPort == listenerPort {
		return "", fmt.Errorf("cannot forward ingress connection targeting proxy listener port %d", dstPort)
	}
	return fmt.Sprintf("127.0.0.1:%d", dstPort), nil
}

func (l *IngressListener) handleConn(ctx context.Context, inConn net.Conn) {
	defer func() { _ = inConn.Close() }()

	targetAddr, err := l.targetAddress(inConn)
	if err != nil {
		l.log.Debug("dropping ingress connection without target port", "error", err)
		return
	}

	inBuf := bufio.NewReaderSize(inConn, defaultProxyBufSize)
	_ = inConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	peek, err := inBuf.Peek(min(defaultProxyBufSize, 4))
	_ = inConn.SetReadDeadline(time.Time{})
	var netErr net.Error
	isTimeout := errors.As(err, &netErr) && netErr.Timeout()
	if err != nil && !isTimeout && len(peek) == 0 {
		return
	}

	if !looksLikeHTTPPreface(peek) || strings.HasPrefix(string(peek), "PRI ") {
		appConn, dialErr := l.dialContext(ctx, "tcp4", targetAddr)
		if dialErr != nil {
			l.log.Debug("failed dialing target app for passthrough", "target", targetAddr, "error", dialErr)
			return
		}
		defer func() { _ = appConn.Close() }()
		spliceConnections(inConn, inBuf, appConn)
		return
	}

	var (
		appConn net.Conn
		appBuf  *bufio.Reader
	)
	closeAppConn := func() {
		if appConn != nil {
			_ = appConn.Close()
			appConn = nil
			appBuf = nil
		}
	}
	defer closeAppConn()

	ensureAppConn := func() error {
		if appConn != nil {
			return nil
		}
		dialed, dialErr := l.dialContext(ctx, "tcp4", targetAddr)
		if dialErr != nil {
			return dialErr
		}
		appConn = dialed
		appBuf = bufio.NewReaderSize(appConn, defaultProxyBufSize)
		return nil
	}

	for {
		req, readErr := http.ReadRequest(inBuf)
		if readErr != nil {
			return
		}

		if err := ensureAppConn(); err != nil {
			_ = req.Body.Close()
			l.writeGatewayError(inConn, req)
			return
		}

		meta, isReplay := ExtractInboundReplay(req.Header)
		if !isReplay {
			upgrade := isUpgradeRequest(req)
			if writeErr := req.Write(appConn); writeErr != nil {
				_ = req.Body.Close()
				return
			}
			_ = req.Body.Close()
			if upgrade {
				spliceConnections(inConn, inBuf, appConn)
				return
			}

			resp, respErr := http.ReadResponse(appBuf, req)
			if respErr != nil {
				return
			}
			writeRespErr := resp.Write(inConn)
			_ = resp.Body.Close()
			if writeRespErr != nil || req.Close || resp.Close {
				return
			}
			continue
		}

		if cont := l.handleReplayRequest(ctx, inConn, appConn, appBuf, req, meta); !cont {
			return
		}
	}
}

func (l *IngressListener) handleReplayRequest(
	ctx context.Context,
	inConn net.Conn,
	appConn net.Conn,
	appBuf *bufio.Reader,
	req *http.Request,
	meta InboundReplayMetadata,
) bool {
	meta = ensureReplayTraceContext(req, meta)

	sess, _ := l.replayRegistry.RegisterInbound(meta)
	if sess == nil {
		sess = &ReplaySession{
			TraceID:         meta.TraceContext.TraceID,
			Mode:            ModeReplay,
			RecordedTraceID: meta.RecordedTraceID,
			ReplayID:        meta.ReplayID,
			SegmentID:       meta.SegmentID,
		}
	}
	l.log.Debug("ingress registered replay request",
		"method", req.Method,
		"path", req.URL.Path,
		"trace_id", FormatTraceIDHex(sess.TraceID),
		"recorded_trace_id", sess.RecordedTraceID,
		"replay_id", sess.ReplayID,
		"traceparent", req.Header.Get(HeaderTraceparent),
	)

	var capturedReq bytes.Buffer
	origBody := req.Body
	if origBody != nil {
		req.Body = &boundedTeeReadCloser{
			rc:  origBody,
			dst: &capturedReq,
			max: l.cfg.MaxBodyBytes,
		}
	}

	startTime := time.Now()
	writeErr := req.Write(appConn)
	if origBody != nil {
		_ = origBody.Close()
	}
	if writeErr != nil {
		return false
	}

	resp, respErr := http.ReadResponse(appBuf, req)
	if respErr != nil {
		return false
	}
	wireRespBody, bodyErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if bodyErr != nil {
		return false
	}
	endTime := time.Now()

	l.commitReplayServletResult(ctx, inConn, req, capturedReq.Bytes(), resp, wireRespBody, meta, sess, startTime, endTime)
	l.emitReplayServletLog(req, resp.StatusCode, meta, sess)

	if sess.ReplayID != "" {
		resp.Header.Set(HeaderReplayID, sess.ReplayID)
	}
	resp.TransferEncoding = nil
	resp.Header.Del("Transfer-Encoding")
	resp.ContentLength = int64(len(wireRespBody))
	resp.Header.Set("Content-Length", strconv.Itoa(len(wireRespBody)))
	resp.Body = io.NopCloser(bytes.NewReader(wireRespBody))

	if err := resp.Write(inConn); err != nil {
		return false
	}
	return !req.Close && !resp.Close
}

func (l *IngressListener) emitReplayServletLog(
	req *http.Request,
	statusCode int,
	meta InboundReplayMetadata,
	sess *ReplaySession,
) {
	if l.logExporter == nil || req == nil || sess == nil {
		return
	}
	logTraceID := meta.TraceContext.TraceID
	if sess.RecordedTraceID != "" {
		if parsed, err := ParseTraceIDHex(sess.RecordedTraceID); err == nil {
			logTraceID = parsed
		}
	}
	if logTraceID == ([16]byte{}) {
		logTraceID = sess.TraceID
	}
	reqPath := "/"
	if req.URL != nil && req.URL.Path != "" {
		reqPath = req.URL.Path
	}
	l.logExporter.Enqueue(LogRecordInput{
		TraceID:      logTraceID,
		SpanID:       meta.TraceContext.SpanID,
		Source:       LogSourceAgent,
		ReplayID:     sess.ReplayID,
		SeverityText: "INFO",
		Body:         fmt.Sprintf("softprobe replayed Servlet %s %s status=%d", req.Method, reqPath, statusCode),
	})
}

func (l *IngressListener) commitReplayServletResult(
	ctx context.Context,
	inConn net.Conn,
	req *http.Request,
	rawReqBody []byte,
	resp *http.Response,
	wireRespBody []byte,
	meta InboundReplayMetadata,
	sess *ReplaySession,
	startTime time.Time,
	endTime time.Time,
) {
	if l.backendClient == nil {
		return
	}

	decodedReqBody, reqDecoded := decodeHTTPBody(rawReqBody, req.Header.Get("Content-Encoding"), l.cfg.MaxBodyBytes)
	decodedRespBody, respDecoded := decodeHTTPBody(wireRespBody, resp.Header.Get("Content-Encoding"), l.cfg.MaxBodyBytes)

	reqHeaders := flattenHTTPHeader(req.Header)
	if req.Host != "" {
		if reqHeaders == nil {
			reqHeaders = make(map[string]string, 1)
		}
		if _, ok := reqHeaders["Host"]; !ok {
			reqHeaders["Host"] = req.Host
		}
	}
	reqHeaders = normalizeDecodedHeaderMap(reqHeaders, len(decodedReqBody), reqDecoded)
	respHeaders := normalizeDecodedHeaderMap(flattenHTTPHeader(resp.Header), len(decodedRespBody), respDecoded)

	spanIDHex := FormatSpanIDHex(meta.TraceContext.SpanID)
	segmentID := sess.SegmentID
	if segmentID == "" {
		segmentID = spanIDHex
	}
	traceIDHex := sess.RecordedTraceID
	if traceIDHex == "" {
		traceIDHex = FormatTraceIDHex(meta.TraceContext.TraceID)
	}

	reqPath := "/"
	rawQuery := ""
	if req.URL != nil {
		if req.URL.Path != "" {
			reqPath = req.URL.Path
		}
		rawQuery = req.URL.RawQuery
	}

	remoteHost := ""
	if inConn != nil && inConn.RemoteAddr() != nil {
		if h, _, err := net.SplitHostPort(inConn.RemoteAddr().String()); err == nil {
			remoteHost = h
		} else {
			remoteHost = inConn.RemoteAddr().String()
		}
	}

	var tags map[string]string
	if l.cfg.Env != "" {
		tags = map[string]string{"env": l.cfg.Env}
	}

	mocker := BuildServletMocker(SpanMetadata{
		AppID:             l.cfg.AppID,
		TraceID:           traceIDHex,
		ReplayID:          sess.ReplayID,
		SpanID:            spanIDHex,
		SegmentID:         segmentID,
		CreationTimeMs:    startTime.UnixMilli(),
		StartTimeNanos:    startTime.UnixNano(),
		EndTimeNanos:      endTime.UnixNano(),
		RecordEnvironment: recordEnvironmentCode(l.cfg.Env),
		RecordVersion:     defaultRecordVersion,
		Tags:              tags,
	}, ServletExchange{
		Method:          req.Method,
		RequestPath:     reqPath,
		OperationName:   reqPath,
		QueryString:     rawQuery,
		RemoteAddr:      remoteHost,
		RequestHeaders:  reqHeaders,
		RequestBody:     decodedReqBody,
		StatusCode:      resp.StatusCode,
		ResponseHeaders: respHeaders,
		ResponseBody:    string(decodedRespBody),
	})

	saveCtx, cancel := context.WithTimeout(ctx, defaultSaveResultTTL)
	defer cancel()
	if _, err := l.backendClient.SaveReplayServletResult(saveCtx, mocker); err != nil {
		l.log.Warn("failed saving replay servlet result", "trace_id", traceIDHex, "replay_id", sess.ReplayID, "error", err)
	}
}

func ensureReplayTraceContext(req *http.Request, meta InboundReplayMetadata) InboundReplayMetadata {
	var targetTraceID [16]byte
	hasTargetTrace := false
	if meta.RecordedTraceID != "" {
		if parsed, err := ParseTraceIDHex(meta.RecordedTraceID); err == nil {
			targetTraceID = parsed
			hasTargetTrace = true
		}
	}
	if !hasTargetTrace && meta.HasTraceContext {
		targetTraceID = meta.TraceContext.TraceID
		meta.RecordedTraceID = FormatTraceIDHex(targetTraceID)
		hasTargetTrace = true
	}
	if !hasTargetTrace {
		targetTraceID = randomNonZeroTraceID()
		meta.RecordedTraceID = FormatTraceIDHex(targetTraceID)
	}

	spanID := meta.TraceContext.SpanID
	if !meta.HasTraceContext || spanID == ([8]byte{}) {
		if meta.ReplayID != "" {
			if parsedSpan, err := ParseSpanIDHex(meta.ReplayID); err == nil {
				spanID = parsedSpan
			}
		}
		if spanID == ([8]byte{}) {
			spanID = randomNonZeroSpanID()
		}
	}
	flags := meta.TraceContext.Flags
	if !meta.HasTraceContext || (flags&0x01) == 0 {
		flags |= 0x01
	}

	needHeaderRewrite := !meta.HasTraceContext || meta.TraceContext.TraceID != targetTraceID
	meta.TraceContext = TraceContext{
		Version: 0x00,
		TraceID: targetTraceID,
		SpanID:  spanID,
		Flags:   flags,
	}
	meta.HasTraceContext = true
	if meta.ReplayID == "" {
		meta.ReplayID = FormatSpanIDHex(spanID)
	}
	if needHeaderRewrite && req != nil && req.Header != nil {
		req.Header.Set(HeaderTraceparent, FormatTraceparent(meta.TraceContext))
	}
	return meta
}

func isUpgradeRequest(req *http.Request) bool {
	if req == nil || req.Header == nil {
		return false
	}
	if req.Header.Get("Upgrade") != "" {
		return true
	}
	for _, v := range req.Header.Values("Connection") {
		for part := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "upgrade") {
				return true
			}
		}
	}
	return false
}

func (l *IngressListener) writeGatewayError(inConn net.Conn, req *http.Request) {
	body := []byte(`{"error":"softprobe ingress upstream unavailable"}`)
	resp := &http.Response{
		StatusCode:    http.StatusBadGateway,
		Status:        "502 Bad Gateway",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
		Request:       req,
	}
	resp.Header.Set("Content-Type", "application/json")
	_ = resp.Write(inConn)
}

type boundedTeeReadCloser struct {
	rc  io.ReadCloser
	dst *bytes.Buffer
	max int
}

func (b *boundedTeeReadCloser) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 && b.dst != nil && b.max > 0 {
		rem := b.max - b.dst.Len()
		if rem > 0 {
			toWrite := min(n, rem)
			_, _ = b.dst.Write(p[:toWrite])
		}
	}
	return n, err
}

func (b *boundedTeeReadCloser) Close() error {
	return b.rc.Close()
}
