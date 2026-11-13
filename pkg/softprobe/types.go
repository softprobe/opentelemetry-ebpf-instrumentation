// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type TrafficMode string

const (
	ModePassthrough TrafficMode = "passthrough"
	ModeRecord      TrafficMode = "record"
	ModeReplay      TrafficMode = "replay"
	ModeFullReplay  TrafficMode = "full-replay"
)

const (
	HeaderTraceparent         = "traceparent"
	HeaderTracestate          = "tracestate"
	HeaderScheduleReplay      = "sp-schedule-replay"
	HeaderSegmentID           = "sp-segment-id"
	HeaderIgnoreDependencies  = "sp-ignore-dependencies"
	HeaderExclusionOperations = "X-SP-Exclusion-Operations"
	HeaderInclusionOperations = "X-SP-Inclusion-Operations"
	HeaderMockStrategyCode    = "X-SP-Mock-Strategy-Code"
	HeaderMustMock            = "mustMock"
	HeaderAppID               = "sp-app-id"
	HeaderReplayID            = "sp-replay-id"
	HeaderRecordID            = "sp-record-id"
	HeaderTargetTraceID       = "sp-target-trace-id"
)

const (
	SpanKindServer = "SERVER"
	SpanKindClient = "CLIENT"

	JavaStringType          = "java.lang.String"
	HTTPResponseWrapperType = "io.softprobe.inst.httpclient.common.HttpResponseWrapper"
	DatabaseResultType      = "io.softprobe.obi.db.WireResultSet"
	RedisReplyType          = "io.softprobe.obi.redis.RespReply"

	AttrContentType   = "ContentType"
	AttrHTTPMethod    = "HttpMethod"
	AttrQueryString   = "QueryString"
	AttrRequestPath   = "RequestPath"
	AttrHeaders       = "Headers"
	AttrRemoteAddr    = "RemoteAddr"
	AttrDBName        = "dbName"
	AttrDBParameters  = "parameters"
	AttrClusterName   = "clusterName"
	AttrSerializer    = "spSerializer"
	AttrRecordedNull  = "sp.recordedNull"
	AttrOrderFreeSlot = "spOrderFreeSlot"
	AttrOrderFreeHit  = "spOrderFreeHit"
	AttrSkipMock      = "skipMock"
	AttrMustMock      = "mustMock"
	AttrRealCallAware = "spRealCallAware"
	AttrLocalRelease  = "spLocalRelease"
	AttrRealCallID    = "spRealCallId"

	ServiceKeyHTTP     = "http"
	ServiceKeyDatabase = "database"
	ServiceKeyRedis    = "redis"
)

type MockCategoryType struct {
	Name           string `json:"name"`
	EntryPoint     bool   `json:"entryPoint"`
	SkipComparison bool   `json:"skipComparison"`
}

var (
	CategoryServlet    = MockCategoryType{Name: "Servlet", EntryPoint: true, SkipComparison: false}
	CategoryHTTPClient = MockCategoryType{Name: "HttpClient", EntryPoint: false, SkipComparison: false}
	CategoryDatabase   = MockCategoryType{Name: "Database", EntryPoint: false, SkipComparison: false}
	CategoryRedis      = MockCategoryType{Name: "Redis", EntryPoint: false, SkipComparison: false}
)

func CategoryByName(name string) (MockCategoryType, bool) {
	switch name {
	case CategoryServlet.Name:
		return CategoryServlet, true
	case CategoryHTTPClient.Name:
		return CategoryHTTPClient, true
	case CategoryDatabase.Name:
		return CategoryDatabase, true
	case CategoryRedis.Name:
		return CategoryRedis, true
	default:
		return MockCategoryType{}, false
	}
}

type Target struct {
	Body       string         `json:"body,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Type       string         `json:"type,omitempty"`
}

func (t *Target) Attribute(key string) (any, bool) {
	if t == nil || t.Attributes == nil {
		return nil, false
	}
	v, ok := t.Attributes[key]
	return v, ok
}

func (t *Target) AttributeString(key string) string {
	v, ok := t.Attribute(key)
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func (t *Target) AttributeBool(key string) bool {
	v, ok := t.Attribute(key)
	if !ok || v == nil {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true")
	default:
		return false
	}
}

func (t *Target) SetAttribute(key string, value any) {
	if t == nil {
		return
	}
	if t.Attributes == nil {
		t.Attributes = make(map[string]any)
	}
	t.Attributes[key] = value
}

type SpMocker struct {
	ID                string            `json:"id,omitempty"`
	CategoryType      MockCategoryType  `json:"categoryType"`
	ReplayID          string            `json:"replayId,omitempty"`
	TraceID           string            `json:"traceId,omitempty"`
	AppID             string            `json:"appId,omitempty"`
	RecordEnvironment int               `json:"recordEnvironment"`
	SessionID         string            `json:"sessionId,omitempty"`
	SpanID            string            `json:"spanId,omitempty"`
	ParentSpanID      string            `json:"parentSpanId,omitempty"`
	SegmentID         string            `json:"segmentId,omitempty"`
	SpanKind          string            `json:"spanKind,omitempty"`
	StartTimeNanos    int64             `json:"startTimeNanos,omitempty"`
	EndTimeNanos      int64             `json:"endTimeNanos,omitempty"`
	CreationTime      int64             `json:"creationTime"`
	UpdateTime        int64             `json:"updateTime,omitempty"`
	ExpirationTime    int64             `json:"expirationTime,omitempty"`
	OperationName     string            `json:"operationName,omitempty"`
	RecordVersion     string            `json:"recordVersion,omitempty"`
	Tags              map[string]string `json:"tags,omitempty"`
	UseMock           *bool             `json:"useMock,omitempty"`
	// nil omits seq so sp-backend treats the mocker as unnumbered rather than seq 0.
	Seq              *int    `json:"seq,omitempty"`
	SpanCountStarted *int    `json:"spanCountStarted,omitempty"`
	SpanCountDropped *int    `json:"spanCountDropped,omitempty"`
	TargetRequest    *Target `json:"targetRequest,omitempty"`
	TargetResponse   *Target `json:"targetResponse,omitempty"`
}

type HeaderTuple struct {
	Name  string `json:"f"`
	Value string `json:"s"`
}

type HTTPResponseWrapper struct {
	Status     int
	StatusCode int
	StatusLine string
	Reason     string
	Headers    map[string]string
	HeaderList []HeaderTuple
	Body       string
	BodyBase64 string
}

// MarshalJSON emits both the Java HttpResponseWrapper fields consumed by
// SpanDisplayAdapter (statusCode, statusLine, reason, headers as f/s tuples, content)
// and direct Go fields (status, body, bodyBase64).
func (w HTTPResponseWrapper) MarshalJSON() ([]byte, error) {
	code := w.Status
	if code == 0 {
		code = w.StatusCode
	}
	reason := w.Reason
	if reason == "" && code > 0 {
		reason = http.StatusText(code)
	}
	statusLine := w.StatusLine
	if statusLine == "" && code > 0 {
		if reason != "" {
			statusLine = fmt.Sprintf("HTTP/1.1 %d %s", code, reason)
		} else {
			statusLine = fmt.Sprintf("HTTP/1.1 %d", code)
		}
	}

	rawBytes, err := w.PayloadBytes()
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString(rawBytes)
	bodyText := w.Body
	if bodyText == "" && len(rawBytes) > 0 && utf8.Valid(rawBytes) {
		bodyText = string(rawBytes)
	}

	tuples := w.HeaderList
	if len(tuples) == 0 && len(w.Headers) > 0 {
		keys := slices.Sorted(maps.Keys(w.Headers))
		tuples = make([]HeaderTuple, 0, len(keys))
		for _, k := range keys {
			tuples = append(tuples, HeaderTuple{Name: k, Value: w.Headers[k]})
		}
	}

	wire := struct {
		Status     int           `json:"status"`
		StatusCode int           `json:"statusCode"`
		StatusLine string        `json:"statusLine,omitempty"`
		Reason     string        `json:"reason,omitempty"`
		Headers    []HeaderTuple `json:"headers,omitempty"`
		Body       string        `json:"body,omitempty"`
		BodyBase64 string        `json:"bodyBase64,omitempty"`
		Content    string        `json:"content,omitempty"`
	}{
		Status:     code,
		StatusCode: code,
		StatusLine: statusLine,
		Reason:     reason,
		Headers:    tuples,
		Body:       bodyText,
		BodyBase64: b64,
		Content:    b64,
	}
	return json.Marshal(wire)
}

func (w *HTTPResponseWrapper) UnmarshalJSON(data []byte) error {
	var wire struct {
		Status     int             `json:"status"`
		StatusCode int             `json:"statusCode"`
		StatusLine string          `json:"statusLine"`
		Reason     string          `json:"reason"`
		Headers    json.RawMessage `json:"headers"`
		Body       string          `json:"body"`
		BodyBase64 string          `json:"bodyBase64"`
		Content    string          `json:"content"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}

	code := wire.Status
	if code == 0 {
		code = wire.StatusCode
	}
	if code == 0 && wire.StatusLine != "" {
		code = parseHTTPStatusFromLine(wire.StatusLine)
	}

	var tuples []HeaderTuple
	headerMap := make(map[string]string)
	if len(wire.Headers) > 0 && !bytes.Equal(bytes.TrimSpace(wire.Headers), []byte("null")) {
		trimmed := bytes.TrimSpace(wire.Headers)
		switch trimmed[0] {
		case '[':
			if err := json.Unmarshal(trimmed, &tuples); err != nil {
				return fmt.Errorf("decoding HttpResponseWrapper header tuples: %w", err)
			}
			for _, t := range tuples {
				if t.Name != "" {
					headerMap[t.Name] = t.Value
				}
			}
		case '{':
			var multi map[string]any
			if err := json.Unmarshal(trimmed, &multi); err != nil {
				return fmt.Errorf("decoding HttpResponseWrapper header map: %w", err)
			}
			keys := slices.Sorted(maps.Keys(multi))
			for _, k := range keys {
				switch v := multi[k].(type) {
				case string:
					headerMap[k] = v
					tuples = append(tuples, HeaderTuple{Name: k, Value: v})
				case []any:
					vals := make([]string, 0, len(v))
					for _, item := range v {
						s := fmt.Sprint(item)
						vals = append(vals, s)
						tuples = append(tuples, HeaderTuple{Name: k, Value: s})
					}
					headerMap[k] = strings.Join(vals, ", ")
				}
			}
		}
	}

	b64 := wire.BodyBase64
	if b64 == "" {
		b64 = wire.Content
	}
	bodyText := wire.Body
	if bodyText == "" && b64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return fmt.Errorf("decoding HttpResponseWrapper base64 body: %w", err)
		}
		if utf8.Valid(decoded) {
			bodyText = string(decoded)
		}
	}
	if b64 == "" && bodyText != "" {
		b64 = base64.StdEncoding.EncodeToString([]byte(bodyText))
	}

	w.Status = code
	w.StatusCode = code
	w.StatusLine = wire.StatusLine
	w.Reason = wire.Reason
	w.Headers = headerMap
	w.HeaderList = tuples
	w.Body = bodyText
	w.BodyBase64 = b64
	return nil
}

func (w HTTPResponseWrapper) PayloadBytes() ([]byte, error) {
	if w.BodyBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(w.BodyBase64)
		if err != nil {
			return nil, fmt.Errorf("invalid HttpResponseWrapper bodyBase64: %w", err)
		}
		return decoded, nil
	}
	if w.Body != "" {
		return []byte(w.Body), nil
	}
	return nil, nil
}

func parseHTTPStatusFromLine(line string) int {
	trimmed := strings.TrimSpace(line)
	if code, err := strconv.Atoi(trimmed); err == nil {
		return code
	}
	for part := range strings.SplitSeq(trimmed, " ") {
		if len(part) == 3 {
			if code, err := strconv.Atoi(part); err == nil {
				return code
			}
		}
	}
	return 0
}

type DatabaseColumn struct {
	Name     string `json:"name"`
	DataType string `json:"dataType,omitempty"`
	TypeOID  uint32 `json:"typeOid,omitempty"`
}

type DatabaseResult struct {
	Columns      []DatabaseColumn `json:"columns,omitempty"`
	Rows         [][]any          `json:"rows,omitempty"`
	RowsAffected int64            `json:"rowsAffected,omitempty"`
	LastInsertID int64            `json:"lastInsertId,omitempty"`
	CommandTag   string           `json:"commandTag,omitempty"`
	ErrorMessage string           `json:"errorMessage,omitempty"`
	ErrorCode    string           `json:"errorCode,omitempty"`
}

type RedisMultiKey struct {
	Key   any `json:"key,omitempty"`
	Field any `json:"field,omitempty"`
}

type RedisReply struct {
	Type     string       `json:"type"`
	Str      string       `json:"str,omitempty"`
	Int      int64        `json:"int,omitempty"`
	Bulk     []byte       `json:"bulk,omitempty"`
	IsNil    bool         `json:"isNil,omitempty"`
	Elements []RedisReply `json:"elements,omitempty"`
}

type MockStrategyCode int

const (
	MockStrategyTryFindLastValue   MockStrategyCode = 0
	MockStrategyBreakRecordedCount MockStrategyCode = 1
	MockStrategyStrictMatch        MockStrategyCode = 2

	MockStrategyDatabase   = MockStrategyTryFindLastValue
	MockStrategyHTTPClient = MockStrategyBreakRecordedCount
	MockStrategyRedis      = MockStrategyStrictMatch
)

func (s MockStrategyCode) HeaderValue() string {
	return strconv.Itoa(int(s))
}

type QueryOutcome uint8

const (
	QueryOutcomeHit QueryOutcome = iota + 1
	QueryOutcomeMustMock
	QueryOutcomeSkipMock
	QueryOutcomeEmptyMiss
)

func (o QueryOutcome) String() string {
	switch o {
	case QueryOutcomeHit:
		return "hit"
	case QueryOutcomeMustMock:
		return "must_mock"
	case QueryOutcomeSkipMock:
		return "skip_mock"
	case QueryOutcomeEmptyMiss:
		return "empty_miss"
	default:
		return "unknown"
	}
}

type QueryResult struct {
	Outcome    QueryOutcome
	Mocker     *SpMocker
	RealCallID string
}

func (r QueryResult) IsHit() bool       { return r.Outcome == QueryOutcomeHit }
func (r QueryResult) IsMustMock() bool  { return r.Outcome == QueryOutcomeMustMock }
func (r QueryResult) IsSkipMock() bool  { return r.Outcome == QueryOutcomeSkipMock }
func (r QueryResult) IsEmptyMiss() bool { return r.Outcome == QueryOutcomeEmptyMiss }

type TraceContext struct {
	Version byte
	TraceID [16]byte
	SpanID  [8]byte
	Flags   byte
}

func (tc TraceContext) TraceIDHex() string {
	return FormatTraceIDHex(tc.TraceID)
}

func (tc TraceContext) SpanIDHex() string {
	return FormatSpanIDHex(tc.SpanID)
}

func ParseTraceIDHex(raw string) ([16]byte, error) {
	var out [16]byte
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) != 32 || !isLowerHex(trimmed) {
		return out, fmt.Errorf("invalid 32-char lowercase hex trace ID %q", raw)
	}
	if _, err := hex.Decode(out[:], []byte(trimmed)); err != nil {
		return out, fmt.Errorf("decoding trace ID %q: %w", raw, err)
	}
	if out == ([16]byte{}) {
		return out, errors.New("trace ID must not be all zeros")
	}
	return out, nil
}

func FormatTraceIDHex(id [16]byte) string {
	return hex.EncodeToString(id[:])
}

func ParseSpanIDHex(raw string) ([8]byte, error) {
	var out [8]byte
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) != 16 || !isLowerHex(trimmed) {
		return out, fmt.Errorf("invalid 16-char lowercase hex span ID %q", raw)
	}
	if _, err := hex.Decode(out[:], []byte(trimmed)); err != nil {
		return out, fmt.Errorf("decoding span ID %q: %w", raw, err)
	}
	if out == ([8]byte{}) {
		return out, errors.New("span ID must not be all zeros")
	}
	return out, nil
}

func FormatSpanIDHex(id [8]byte) string {
	return hex.EncodeToString(id[:])
}

func ParseTraceparent(raw string) (TraceContext, error) {
	var tc TraceContext
	parts := strings.Split(strings.TrimSpace(raw), "-")
	if len(parts) < 4 {
		return tc, fmt.Errorf("invalid traceparent %q", raw)
	}
	if len(parts[0]) != 2 || !isLowerHex(parts[0]) {
		return tc, fmt.Errorf("invalid traceparent version %q", parts[0])
	}
	verBytes, err := hex.DecodeString(parts[0])
	if err != nil || verBytes[0] == 0xff {
		return tc, fmt.Errorf("unsupported traceparent version %q", parts[0])
	}
	if verBytes[0] == 0x00 && len(parts) != 4 {
		return tc, fmt.Errorf("traceparent v00 requires 4 fields, got %d", len(parts))
	}
	traceID, err := ParseTraceIDHex(parts[1])
	if err != nil {
		return tc, err
	}
	spanID, err := ParseSpanIDHex(parts[2])
	if err != nil {
		return tc, err
	}
	if len(parts[3]) != 2 || !isLowerHex(parts[3]) {
		return tc, fmt.Errorf("invalid traceparent flags %q", parts[3])
	}
	flagBytes, err := hex.DecodeString(parts[3])
	if err != nil {
		return tc, fmt.Errorf("decoding traceparent flags: %w", err)
	}
	return TraceContext{
		Version: verBytes[0],
		TraceID: traceID,
		SpanID:  spanID,
		Flags:   flagBytes[0],
	}, nil
}

func FormatTraceparent(tc TraceContext) string {
	return fmt.Sprintf("%02x-%s-%s-%02x", tc.Version, FormatTraceIDHex(tc.TraceID), FormatSpanIDHex(tc.SpanID), tc.Flags)
}

func isLowerHex(s string) bool {
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

type SpTracestate struct {
	Mode            TrafficMode
	RecordedTraceID string
	ReplayID        string
}

func ParseTracestate(raw string) (SpTracestate, bool) {
	for member := range strings.SplitSeq(raw, ",") {
		member = strings.TrimSpace(member)
		if member == "" {
			continue
		}
		key, val, ok := strings.Cut(member, "=")
		if !ok || strings.TrimSpace(key) != "sp" {
			continue
		}
		var out SpTracestate
		var found bool
		for token := range strings.SplitSeq(strings.TrimSpace(val), ";") {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			k, v, hasSep := strings.Cut(token, ":")
			if !hasSep {
				continue
			}
			switch k {
			case "mode":
				switch TrafficMode(v) {
				case ModeReplay, ModeFullReplay, ModeRecord, ModePassthrough:
					out.Mode = TrafficMode(v)
					found = true
				}
			case "tid":
				out.RecordedTraceID = v
				found = true
			case "rid":
				out.ReplayID = v
				found = true
			}
		}
		return out, found
	}
	return SpTracestate{}, false
}

func FormatTracestate(existing string, sp SpTracestate) string {
	var sb strings.Builder
	mode := sp.Mode
	if mode == "" {
		mode = ModeReplay
	}
	sb.WriteString("sp=mode:")
	sb.WriteString(string(mode))
	if sp.RecordedTraceID != "" {
		sb.WriteString(";tid:")
		sb.WriteString(sp.RecordedTraceID)
	}
	if sp.ReplayID != "" {
		sb.WriteString(";rid:")
		sb.WriteString(sp.ReplayID)
	}

	var others []string
	for member := range strings.SplitSeq(existing, ",") {
		trimmed := strings.TrimSpace(member)
		if trimmed == "" {
			continue
		}
		key, _, ok := strings.Cut(trimmed, "=")
		if ok && strings.TrimSpace(key) == "sp" {
			continue
		}
		others = append(others, trimmed)
	}
	if len(others) == 0 {
		return sb.String()
	}
	return sb.String() + "," + strings.Join(others, ",")
}

type OperationFilterMap map[string][]string

type InboundReplayMetadata struct {
	TraceContext        TraceContext
	HasTraceContext     bool
	Mode                TrafficMode
	ScheduleReplay      string
	RecordedTraceID     string
	ReplayID            string
	SegmentID           string
	IgnoreDependencies  bool
	ExclusionOperations OperationFilterMap
	InclusionOperations OperationFilterMap
}

func ExtractInboundReplay(headers http.Header) (InboundReplayMetadata, bool) {
	if len(headers) == 0 {
		return InboundReplayMetadata{}, false
	}

	var meta InboundReplayMetadata
	if tp := headers.Get(HeaderTraceparent); tp != "" {
		if tc, err := ParseTraceparent(tp); err == nil {
			meta.TraceContext = tc
			meta.HasTraceContext = true
		}
	}

	ts, hasTS := ParseTracestate(headers.Get(HeaderTracestate))
	scheduleHeader := strings.TrimSpace(headers.Get(HeaderScheduleReplay))
	replayHeader := strings.TrimSpace(headers.Get(HeaderReplayID))

	isReplay := (hasTS && (ts.Mode == ModeReplay || ts.Mode == ModeFullReplay)) ||
		scheduleHeader != "" ||
		replayHeader != ""
	if !isReplay {
		return InboundReplayMetadata{}, false
	}

	meta.Mode = ts.Mode
	if meta.Mode == "" {
		meta.Mode = ModeReplay
	}
	meta.ScheduleReplay = scheduleHeader
	meta.RecordedTraceID = firstNonEmpty(
		ts.RecordedTraceID,
		strings.TrimSpace(headers.Get(HeaderRecordID)),
		strings.TrimSpace(headers.Get(HeaderTargetTraceID)),
	)
	if meta.RecordedTraceID == "" && meta.HasTraceContext {
		meta.RecordedTraceID = meta.TraceContext.TraceIDHex()
	}
	meta.ReplayID = firstNonEmpty(ts.ReplayID, replayHeader)
	meta.SegmentID = strings.TrimSpace(headers.Get(HeaderSegmentID))
	meta.IgnoreDependencies = strings.EqualFold(strings.TrimSpace(headers.Get(HeaderIgnoreDependencies)), "true")
	meta.ExclusionOperations = ParseOperationFilterHeader(headers.Get(HeaderExclusionOperations))
	meta.InclusionOperations = ParseOperationFilterHeader(headers.Get(HeaderInclusionOperations))
	return meta, true
}

func ParseOperationFilterHeader(raw string) OperationFilterMap {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	switch trimmed[0] {
	case '{':
		var byService map[string][]string
		if err := json.Unmarshal([]byte(trimmed), &byService); err == nil {
			normalized := make(OperationFilterMap, len(byService))
			for k, ops := range byService {
				normalized[strings.ToLower(strings.TrimSpace(k))] = ops
			}
			return normalized
		}
	case '[':
		var ops []string
		if err := json.Unmarshal([]byte(trimmed), &ops); err == nil {
			return OperationFilterMap{"*": ops}
		}
	}
	var ops []string
	for part := range strings.SplitSeq(trimmed, ",") {
		if p := strings.TrimSpace(part); p != "" {
			ops = append(ops, p)
		}
	}
	if len(ops) == 0 {
		return nil
	}
	return OperationFilterMap{"*": ops}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

type AgentStatusPayload struct {
	AppID          string   `json:"appId"`
	Host           string   `json:"host"`
	AgentStatus    string   `json:"agentStatus"`
	HealthState    *int     `json:"healthState,omitempty"`
	CurrentRate    string   `json:"currentRate,omitempty"`
	DecelerateCode *int     `json:"decelerateCode,omitempty"`
	CPUUsage       *float64 `json:"cpuUsage,omitempty"`
	MemoryUsage    *float64 `json:"memoryUsage,omitempty"`
	SceneDedup     *bool    `json:"sceneDedup,omitempty"`
}

type AgentStatusResult struct {
	StatusCode   int
	LastModified string
	NotModified  bool
	RecordedAt   time.Time
}
