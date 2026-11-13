// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"maps"
	"math"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/hashicorp/golang-lru/v2/expirable"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	defaultSegmentCacheSize = 8192
	defaultSegmentCacheTTL  = 5 * time.Minute
	defaultRecordVersion    = "obi-1.0"
)

type segmentEntry struct {
	spanID        string
	authoritative bool
}

type EnrichResult struct {
	Mocker           *SpMocker
	Attributes       map[string]any
	IsEntryPoint     bool
	SuppressedReplay bool
}

type SpanEnricher struct {
	cfg            Config
	replayRegistry *ReplayRegistry
	exchangeCache  *HTTPExchangeCache
	logExporter    *LogExporter
	mu             sync.Mutex
	segments       *expirable.LRU[[16]byte, segmentEntry]
}

func NewSpanEnricher(cfg Config, replayRegistry *ReplayRegistry) *SpanEnricher {
	normalized := cfg.WithDefaults()
	return &SpanEnricher{
		cfg:            normalized,
		replayRegistry: replayRegistry,
		exchangeCache:  SharedDataplaneBridge().ExchangeCache(),
		logExporter:    NewLogExporter(normalized, replayRegistry),
		segments:       expirable.NewLRU[[16]byte, segmentEntry](defaultSegmentCacheSize, nil, defaultSegmentCacheTTL),
	}
}

func (e *SpanEnricher) SetExchangeCache(cache *HTTPExchangeCache) {
	if e == nil {
		return
	}
	e.exchangeCache = cache
}

func (e *SpanEnricher) SetLogExporter(exp *LogExporter) {
	if e == nil {
		return
	}
	if e.logExporter != nil && e.logExporter != exp {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = e.logExporter.Close(closeCtx)
		cancel()
	}
	e.logExporter = exp
}

func (e *SpanEnricher) Close(ctx context.Context) error {
	if e == nil || e.logExporter == nil {
		return nil
	}
	return e.logExporter.Close(ctx)
}

func (e *SpanEnricher) AppID() string {
	if e == nil {
		return ""
	}
	return e.cfg.AppID
}

func isServerHTTPSpan(span *request.Span) bool {
	return span != nil && span.Type == request.EventTypeHTTP && !span.IsClientSpan()
}

func (e *SpanEnricher) ObserveServerSpan(span *request.Span, traceID [16]byte, spanID [8]byte) {
	if e == nil || !e.cfg.Enabled || !isServerHTTPSpan(span) {
		return
	}
	if traceID == ([16]byte{}) || spanID == ([8]byte{}) {
		return
	}
	if span.Softprobe != nil && len(span.Softprobe.RequestHeaders) > 0 {
		canonicalReqHeaders := canonicalizeHeaderMultiMap(span.Softprobe.RequestHeaders)
		if inboundMeta, isReplay := ExtractInboundReplay(canonicalReqHeaders); isReplay {
			if e.replayRegistry != nil {
				if !inboundMeta.HasTraceContext {
					inboundMeta.TraceContext = TraceContext{
						Version: 0x00,
						TraceID: traceID,
						SpanID:  spanID,
						Flags:   span.TraceFlags,
					}
					inboundMeta.HasTraceContext = true
					if inboundMeta.RecordedTraceID == "" {
						inboundMeta.RecordedTraceID = FormatTraceIDHex(traceID)
					}
				}
				e.replayRegistry.RegisterInbound(inboundMeta)
			}
			return
		}
	}
	e.recordRootSegment(traceID, FormatSpanIDHex(spanID))
}

func (e *SpanEnricher) EnrichSpan(span *request.Span, traceID [16]byte, spanID [8]byte, startUnixNano, endUnixNano int64) EnrichResult {
	if e == nil || !e.cfg.Enabled || span == nil {
		return EnrichResult{}
	}
	if traceID == ([16]byte{}) || spanID == ([8]byte{}) {
		return EnrichResult{}
	}

	isServerHTTP := isServerHTTPSpan(span)
	if isServerHTTP {
		if isInternalInspectorSpan(span) {
			return EnrichResult{}
		}
		e.ObserveServerSpan(span, traceID, spanID)
		if span.Softprobe != nil && len(span.Softprobe.RequestHeaders) > 0 {
			canonicalReqHeaders := canonicalizeHeaderMultiMap(span.Softprobe.RequestHeaders)
			if _, isReplay := ExtractInboundReplay(canonicalReqHeaders); isReplay {
				return EnrichResult{IsEntryPoint: true, SuppressedReplay: true}
			}
		}
	}

	if e.replayRegistry != nil {
		if _, isReplay := e.replayRegistry.Lookup(traceID); isReplay {
			return EnrichResult{IsEntryPoint: isServerHTTP, SuppressedReplay: true}
		}
	}

	if !e.shouldSampleTrace(traceID) {
		return EnrichResult{IsEntryPoint: isServerHTTP}
	}

	traceIDHex := FormatTraceIDHex(traceID)
	spanIDHex := FormatSpanIDHex(spanID)

	var (
		parentSpanIDHex string
		segmentIDHex    string
	)
	if isServerHTTP {
		if e.cfg.ExcludeErrorResponses && span.Status >= 400 {
			return EnrichResult{IsEntryPoint: true}
		}
		parentSpanIDHex = ""
		segmentIDHex = spanIDHex
	} else {
		if span.ParentSpanID.IsValid() {
			parentSpanIDHex = FormatSpanIDHex([8]byte(span.ParentSpanID))
		}
		segmentIDHex = e.resolveChildSegment(traceID, parentSpanIDHex, spanIDHex)
	}

	creationTimeMs := startUnixNano / int64(time.Millisecond)
	if creationTimeMs <= 0 {
		creationTimeMs = time.Now().UnixMilli()
	}

	var tags map[string]string
	if e.cfg.Env != "" {
		tags = map[string]string{"env": e.cfg.Env}
	}

	appID := e.cfg.AppID
	if appID == "" {
		appID = span.Service.UID.Name
	}

	meta := SpanMetadata{
		AppID:             appID,
		TraceID:           traceIDHex,
		SpanID:            spanIDHex,
		ParentSpanID:      parentSpanIDHex,
		SegmentID:         segmentIDHex,
		CreationTimeMs:    creationTimeMs,
		StartTimeNanos:    startUnixNano,
		EndTimeNanos:      endUnixNano,
		RecordEnvironment: recordEnvironmentCode(e.cfg.Env),
		RecordVersion:     defaultRecordVersion,
		Tags:              tags,
	}

	var (
		mocker *SpMocker
		err    error
	)
	switch {
	case isServerHTTP:
		mocker = e.buildServletMocker(meta, span)
	case span.Type == request.EventTypeHTTPClient || (span.Type == request.EventTypeHTTP && span.IsClientSpan()):
		mocker, err = e.buildHTTPClientMocker(traceID, meta, span)
	case span.Type == request.EventTypeSQLClient:
		mocker, err = e.buildDatabaseMocker(traceID, meta, span)
	case span.Type == request.EventTypeRedisClient:
		mocker, err = e.buildRedisMocker(traceID, meta, span)
	default:
		return EnrichResult{}
	}
	if err != nil || mocker == nil {
		return EnrichResult{IsEntryPoint: isServerHTTP}
	}

	attrs, err := BuildOTLPSpanAttributes(mocker)
	if err != nil {
		return EnrichResult{IsEntryPoint: isServerHTTP}
	}
	if e.logExporter != nil {
		e.logExporter.Enqueue(LogRecordInput{
			TraceID:      traceID,
			SpanID:       spanID,
			Source:       LogSourceAgent,
			SeverityText: "INFO",
			Body:         fmt.Sprintf("softprobe recorded %s %s", mocker.CategoryType.Name, mocker.OperationName),
		})
	}
	return EnrichResult{
		Mocker:       mocker,
		Attributes:   attrs,
		IsEntryPoint: isServerHTTP,
	}
}

func (e *SpanEnricher) shouldSampleTrace(traceID [16]byte) bool {
	rate := e.cfg.RecordRate
	if rate <= 0 {
		return false
	}
	if rate >= 1.0 {
		return true
	}
	threshold := uint64(rate * float64(math.MaxUint64))
	sampleVal := binary.BigEndian.Uint64(traceID[:8])
	return sampleVal <= threshold
}

func (e *SpanEnricher) recordRootSegment(traceID [16]byte, spanIDHex string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.segments.Add(traceID, segmentEntry{
		spanID:        spanIDHex,
		authoritative: true,
	})
}

func (e *SpanEnricher) resolveChildSegment(traceID [16]byte, parentSpanIDHex, selfSpanIDHex string) string {
	e.mu.Lock()
	defer e.mu.Unlock()

	if existing, ok := e.segments.Get(traceID); ok && existing.authoritative && existing.spanID != "" {
		return existing.spanID
	}
	if parentSpanIDHex != "" {
		if existing, ok := e.segments.Get(traceID); !ok || existing.spanID == "" {
			e.segments.Add(traceID, segmentEntry{
				spanID:        parentSpanIDHex,
				authoritative: false,
			})
		}
		return parentSpanIDHex
	}
	if existing, ok := e.segments.Get(traceID); ok && existing.spanID != "" {
		return existing.spanID
	}
	return selfSpanIDHex
}

func (e *SpanEnricher) buildServletMocker(meta SpanMetadata, span *request.Span) *SpMocker {
	reqPath := stripQuery(span.Path)
	if reqPath == "" {
		reqPath = stripQuery(span.FullPath)
	}
	if reqPath == "" {
		reqPath = "/"
	}

	var (
		queryString  string
		reqHeaders   map[string]string
		respHeaders  map[string]string
		reqEncoding  string
		respEncoding string
		reqBody      []byte
		rawRespBody  []byte
	)
	if span.Softprobe != nil {
		queryString = span.Softprobe.RawQuery
		reqHeaders = flattenHeaders(span.Softprobe.RequestHeaders)
		respHeaders = flattenHeaders(span.Softprobe.ResponseHeaders)
		reqEncoding = headerFirstValueCI(span.Softprobe.RequestHeaders, "Content-Encoding")
		respEncoding = headerFirstValueCI(span.Softprobe.ResponseHeaders, "Content-Encoding")
		reqBody = span.Softprobe.RequestBody
		rawRespBody = span.Softprobe.ResponseBody
	}
	if queryString == "" {
		queryString = queryFromPath(span.FullPath)
	}
	if len(reqHeaders) == 0 && len(span.RequestHeaders) > 0 {
		reqHeaders = flattenHeaders(span.RequestHeaders)
	}
	if reqEncoding == "" && len(span.RequestHeaders) > 0 {
		reqEncoding = headerFirstValueCI(span.RequestHeaders, "Content-Encoding")
	}
	if len(respHeaders) == 0 && len(span.ResponseHeaders) > 0 {
		respHeaders = flattenHeaders(span.ResponseHeaders)
	}
	if respEncoding == "" && len(span.ResponseHeaders) > 0 {
		respEncoding = headerFirstValueCI(span.ResponseHeaders, "Content-Encoding")
	}
	if len(reqBody) == 0 && span.RequestBodyContent != "" {
		reqBody = []byte(span.RequestBodyContent)
	}
	if len(rawRespBody) == 0 && span.ResponseBodyContent != "" {
		rawRespBody = []byte(span.ResponseBodyContent)
	}

	reqBody, _ = decodeHTTPBody(reqBody, reqEncoding, e.cfg.MaxBodyBytes)
	decodedResp, respDecoded := decodeHTTPBody(rawRespBody, respEncoding, e.cfg.MaxBodyBytes)
	if respDecoded && len(respHeaders) > 0 {
		respHeaders = stripDecodedHeadersMap(respHeaders, len(decodedResp))
	}

	return BuildServletMocker(meta, ServletExchange{
		Method:          span.Method,
		RequestPath:     reqPath,
		OperationName:   reqPath,
		QueryString:     queryString,
		RemoteAddr:      span.Peer,
		RequestHeaders:  reqHeaders,
		RequestBody:     reqBody,
		StatusCode:      span.Status,
		ResponseHeaders: respHeaders,
		ResponseBody:    string(decodedResp),
	})
}

func (e *SpanEnricher) buildHTTPClientMocker(traceID [16]byte, meta SpanMetadata, span *request.Span) (*SpMocker, error) {
	opName := stripQuery(span.Path)
	if opName == "" {
		opName = stripQuery(span.FullPath)
	}
	if opName == "" {
		opName = "/"
	}

	var (
		queryString  string
		contentType  string
		reqEncoding  string
		respEncoding string
		reqBody      []byte
		respBody     []byte
		statusReason string
		respHeaders  map[string]string
		headerTuples []HeaderTuple
	)
	if span.Softprobe != nil {
		queryString = span.Softprobe.RawQuery
		contentType = headerFirstValueCI(span.Softprobe.RequestHeaders, "Content-Type")
		reqEncoding = headerFirstValueCI(span.Softprobe.RequestHeaders, "Content-Encoding")
		respEncoding = headerFirstValueCI(span.Softprobe.ResponseHeaders, "Content-Encoding")
		reqBody = span.Softprobe.RequestBody
		respBody = span.Softprobe.ResponseBody
		statusReason = span.Softprobe.StatusReason
		respHeaders, headerTuples = flattenAndTupleHeaders(span.Softprobe.ResponseHeaders)
	}
	if queryString == "" {
		queryString = queryFromPath(span.FullPath)
	}
	if contentType == "" && len(span.RequestHeaders) > 0 {
		contentType = headerFirstValueCI(span.RequestHeaders, "Content-Type")
	}
	if reqEncoding == "" && len(span.RequestHeaders) > 0 {
		reqEncoding = headerFirstValueCI(span.RequestHeaders, "Content-Encoding")
	}
	if respEncoding == "" && len(span.ResponseHeaders) > 0 {
		respEncoding = headerFirstValueCI(span.ResponseHeaders, "Content-Encoding")
	}
	if len(reqBody) == 0 && span.RequestBodyContent != "" {
		reqBody = []byte(span.RequestBodyContent)
	}
	if len(respBody) == 0 && span.ResponseBodyContent != "" {
		respBody = []byte(span.ResponseBodyContent)
	}
	if len(respHeaders) == 0 && len(span.ResponseHeaders) > 0 {
		respHeaders, headerTuples = flattenAndTupleHeaders(span.ResponseHeaders)
	}

	reqBody, _ = decodeHTTPBody(reqBody, reqEncoding, e.cfg.MaxBodyBytes)
	decodedResp, respDecoded := decodeHTTPBody(respBody, respEncoding, e.cfg.MaxBodyBytes)
	respBody = decodedResp
	if respDecoded {
		respHeaders = stripDecodedHeadersMap(respHeaders, len(respBody))
		headerTuples = stripDecodedHeaderTuples(headerTuples, len(respBody))
	}

	statusCode := span.Status
	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	if e.exchangeCache != nil {
		if captured, ok := e.exchangeCache.ConsumeHTTPClient(traceID, span.Method, opName); ok {
			if captured.QueryString != "" {
				queryString = captured.QueryString
			}
			if captured.ContentType != "" {
				contentType = captured.ContentType
			}
			if len(captured.RequestBody) >= len(reqBody) {
				reqBody = captured.RequestBody
			}
			if len(captured.ResponseBody) >= len(respBody) {
				respBody = captured.ResponseBody
				if len(captured.RespHeaders) > 0 || len(captured.HeaderTuples) > 0 {
					respHeaders = captured.RespHeaders
					headerTuples = captured.HeaderTuples
				}
			}
			if captured.StatusCode > 0 {
				statusCode = captured.StatusCode
			}
			if captured.StatusReason != "" {
				statusReason = captured.StatusReason
			}
		}
	}

	if statusReason == "" {
		statusReason = http.StatusText(statusCode)
	}

	wrapper := &HTTPResponseWrapper{
		Status:     statusCode,
		StatusCode: statusCode,
		Reason:     statusReason,
		Headers:    respHeaders,
		HeaderList: headerTuples,
		BodyBase64: base64.StdEncoding.EncodeToString(respBody),
	}
	if len(respBody) > 0 && utf8.Valid(respBody) {
		wrapper.Body = string(respBody)
	}

	return BuildHTTPClientMocker(meta, HTTPClientExchange{
		Method:        span.Method,
		OperationName: opName,
		QueryString:   queryString,
		ContentType:   contentType,
		RequestBody:   reqBody,
		Response:      wrapper,
	})
}

func stripDecodedHeadersMap(in map[string]string, decodedLen int) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	hasContentLen := false
	for k, v := range in {
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "content-encoding", "transfer-encoding":
			continue
		case "content-length":
			out[k] = strconv.Itoa(decodedLen)
			hasContentLen = true
		default:
			out[k] = v
		}
	}
	if !hasContentLen {
		out["Content-Length"] = strconv.Itoa(decodedLen)
	}
	return out
}

func stripDecodedHeaderTuples(in []HeaderTuple, decodedLen int) []HeaderTuple {
	if len(in) == 0 {
		return nil
	}
	out := make([]HeaderTuple, 0, len(in))
	hasContentLen := false
	for _, item := range in {
		switch strings.ToLower(strings.TrimSpace(item.Name)) {
		case "content-encoding", "transfer-encoding":
			continue
		case "content-length":
			out = append(out, HeaderTuple{Name: item.Name, Value: strconv.Itoa(decodedLen)})
			hasContentLen = true
		default:
			out = append(out, item)
		}
	}
	if !hasContentLen {
		out = append(out, HeaderTuple{Name: "Content-Length", Value: strconv.Itoa(decodedLen)})
	}
	return out
}

func spanClientPort(span *request.Span, egressProxyPort int) uint16 {
	if span == nil {
		return 0
	}
	if egressProxyPort <= 0 {
		egressProxyPort = DefaultEgressProxyPort
	}
	if span.HostPort == egressProxyPort && span.PeerPort > 0 && span.PeerPort <= 65535 && span.PeerPort != egressProxyPort {
		return uint16(span.PeerPort)
	}
	if span.PeerPort == egressProxyPort && span.HostPort > 0 && span.HostPort <= 65535 && span.HostPort != egressProxyPort {
		return uint16(span.HostPort)
	}
	return 0
}

func isNonExecutionSQLCommand(cmd string) bool {
	switch strings.ToUpper(strings.TrimSpace(cmd)) {
	case "STMT_PREPARE", "STMT_CLOSE", "STMT_RESET", "PING", "INIT_DB", "QUIT":
		return true
	default:
		return false
	}
}

func (e *SpanEnricher) buildDatabaseMocker(traceID [16]byte, meta SpanMetadata, span *request.Span) (*SpMocker, error) {
	if isNonExecutionSQLCommand(span.SQLCommand) {
		return nil, nil
	}
	if span.Softprobe != nil {
		if isNonExecutionSQLWireRequest(span.Softprobe.SQLWireRequest) || isMySQLPrepareOKWireResponse(span.Softprobe.SQLWireResponse) {
			return nil, nil
		}
	}
	dbName := span.DBNamespace
	sqlText := span.Statement
	if sqlText == "" {
		sqlText = span.Path
	}
	if sqlText != "" && isSessionControlSQL(sqlText) {
		return nil, nil
	}

	var (
		params []any
		result *DatabaseResult
	)
	if e.exchangeCache != nil {
		clientPort := spanClientPort(span, e.cfg.EgressProxyPort)
		if captured, ok := e.exchangeCache.ConsumeDatabaseForConn(traceID, clientPort, span.Statement, span.Method, span.Path); ok {
			if captured.DBName != "" {
				dbName = captured.DBName
			}
			if captured.SQL != "" {
				sqlText = captured.SQL
			}
			params = captured.Parameters
			result = captured.Result
		}
	}
	if isSessionControlSQL(sqlText) {
		return nil, nil
	}
	if dbName == "" {
		dbName = "default"
	}

	if span.Softprobe != nil {
		if len(params) == 0 && len(span.Softprobe.SQLWireRequest) > 0 {
			params = ParsePostgresWireRequestParams(span.Softprobe.SQLWireRequest)
		}
		if result == nil && len(span.Softprobe.SQLWireResponse) > 0 {
			switch request.SQLKind(span.SubType) {
			case request.DBMySQL:
				result = ParseMySQLWireResponse(span.Softprobe.SQLWireResponse)
			default:
				result = ParsePostgresWireResponse(span.Softprobe.SQLWireResponse)
				if result == nil {
					result = ParseMySQLWireResponse(span.Softprobe.SQLWireResponse)
				}
			}
		}
	}
	if result == nil {
		result = &DatabaseResult{}
	}
	if span.SQLError != nil && result.ErrorMessage == "" {
		result.ErrorCode = span.SQLError.ResponseStatusCode()
		result.ErrorMessage = span.SQLError.Message
	} else if span.DBError.Description != "" && result.ErrorMessage == "" {
		result.ErrorCode = span.DBError.ErrorCode
		result.ErrorMessage = span.DBError.Description
	}

	return BuildDatabaseMocker(meta, DatabaseExchange{
		DBName:     dbName,
		SQL:        sqlText,
		Parameters: params,
		Result:     result,
	})
}

func (e *SpanEnricher) buildRedisMocker(traceID [16]byte, meta SpanMetadata, span *request.Span) (*SpMocker, error) {
	var wireReq, wireResp []byte
	if span.Softprobe != nil {
		wireReq = span.Softprobe.RedisWireReq
		wireResp = span.Softprobe.RedisWireResp
	}
	cmd, keys, fields := ParseRedisWireCommandArgs(wireReq, span.Method, span.Path)
	if isRedisSessionCommand(cmd) {
		return nil, nil
	}

	var (
		reply       *RedisReply
		clusterName string
	)
	clientPort := spanClientPort(span, e.cfg.EgressProxyPort)
	if e.exchangeCache != nil {
		if captured, ok := e.exchangeCache.ConsumeRedisForConn(traceID, clientPort, cmd, keys); ok {
			if captured.ClusterName != "" {
				clusterName = captured.ClusterName
			}
			if len(captured.Keys) > 0 {
				keys = captured.Keys
			}
			if len(captured.Fields) > 0 {
				fields = captured.Fields
			}
			if captured.Reply != nil {
				reply = captured.Reply
			}
		}
	}
	if reply == nil && len(wireResp) > 0 {
		reply = ParseRedisWireReply(wireResp)
	}
	if reply == nil && span.DBError.Description != "" {
		reply = &RedisReply{Type: "-", Str: span.DBError.Description}
	}

	if clusterName == "" && clientPort != 0 {
		if target, ok := SharedDataplaneBridge().LookupEgressTarget(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(clientPort)}); ok && target.AddrPort.IsValid() {
			clusterName = target.AddrPort.String()
		}
	}
	if clusterName == "" && span.Host != "" && (e.cfg.EgressProxyPort == 0 || span.HostPort != e.cfg.EgressProxyPort) {
		clusterName = span.Host
		if span.HostPort > 0 {
			clusterName = clusterName + ":" + strconv.Itoa(span.HostPort)
		}
	}
	if clusterName == "" {
		clusterName = "default"
	}

	return BuildRedisMocker(meta, RedisExchange{
		Command:     cmd,
		ClusterName: clusterName,
		Keys:        keys,
		Fields:      fields,
		Reply:       reply,
		OrderFree:   true,
	})
}

func isInternalInspectorSpan(span *request.Span) bool {
	if span == nil || span.HostPort != 9229 {
		return false
	}
	if span.Status == http.StatusSwitchingProtocols {
		return true
	}
	return strings.HasPrefix(span.Path, "/json")
}

func recordEnvironmentCode(env string) int {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "test", "staging", "dev":
		return 1
	default:
		return 0
	}
}

func stripQuery(p string) string {
	before, _, _ := strings.Cut(p, "?")
	return before
}

func queryFromPath(p string) string {
	if _, after, ok := strings.Cut(p, "?"); ok {
		return after
	}
	return ""
}

func canonicalizeHeaderMultiMap(in map[string][]string) http.Header {
	out := make(http.Header, len(in))
	for k, vals := range in {
		for _, v := range vals {
			out.Add(k, v)
		}
	}
	return out
}

func flattenHeaders(in map[string][]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, vals := range in {
		if len(vals) > 0 {
			out[k] = strings.Join(vals, ", ")
		}
	}
	return out
}

func flattenAndTupleHeaders(in map[string][]string) (map[string]string, []HeaderTuple) {
	if len(in) == 0 {
		return nil, nil
	}
	flat := make(map[string]string, len(in))
	keys := slices.Sorted(maps.Keys(in))
	var tuples []HeaderTuple
	for _, k := range keys {
		vals := in[k]
		if len(vals) == 0 {
			continue
		}
		flat[k] = strings.Join(vals, ", ")
		for _, v := range vals {
			tuples = append(tuples, HeaderTuple{Name: k, Value: v})
		}
	}
	return flat, tuples
}

func headerFirstValueCI(in map[string][]string, target string) string {
	for k, vals := range in {
		if strings.EqualFold(k, target) && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}
