// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

const (
	OTLPAttrAppID              = "sp_app_id"
	OTLPAttrCategoryType       = "sp_category_type"
	OTLPAttrTraceID            = "sp_trace_id"
	OTLPAttrSpanID             = "sp_span_id"
	OTLPAttrParentSpanID       = "sp_parent_span_id"
	OTLPAttrSegmentID          = "sp_segment_id"
	OTLPAttrSpanKind           = "sp_span_kind"
	OTLPAttrOperationName      = "sp_operation_name"
	OTLPAttrOperation          = "sp_operation"
	OTLPAttrMocker             = "sp_mocker"
	OTLPAttrCreationTime       = "sp_creation_time"
	OTLPAttrRecordEnvironment  = "sp_record_environment"
	OTLPAttrSessionID          = "sp_session_id"
	OTLPAttrRecordVersion      = "sp_record_version"
	OTLPAttrReplayID           = "sp_replay_id"
	OTLPAttrTargetRequestJSON  = "sp_target_request_json"
	OTLPAttrTargetResponseJSON = "sp_target_response_json"
	OTLPAttrTagsJSON           = "sp_tags_json"
	OTLPAttrSeq                = "sp_seq"
	OTLPAttrSpanCountStarted   = "sp_span_count_started"
	OTLPAttrSpanCountDropped   = "sp_span_count_dropped"

	DatabaseQueryOperationName = "query"
)

const (
	OrderFreeSlotKey   = "key"
	OrderFreeSlotField = "field"
)

type SpanMetadata struct {
	AppID             string
	TraceID           string
	ReplayID          string
	SpanID            string
	ParentSpanID      string
	SegmentID         string
	CreationTimeMs    int64
	StartTimeNanos    int64
	EndTimeNanos      int64
	RecordEnvironment int
	RecordVersion     string
	SessionID         string
	Tags              map[string]string
}

type ServletExchange struct {
	Method          string
	RequestPath     string
	OperationName   string
	QueryString     string
	RemoteAddr      string
	RequestHeaders  map[string]string
	RequestBody     []byte
	StatusCode      int
	ResponseHeaders map[string]string
	ResponseBody    string
}

type HTTPClientExchange struct {
	Method        string
	OperationName string
	QueryString   string
	ContentType   string
	RequestBody   []byte
	TargetAppID   string
	Response      *HTTPResponseWrapper
}

type DatabaseExchange struct {
	DBName     string
	SQL        string
	Parameters []any
	Result     *DatabaseResult
}

type RedisExchange struct {
	Command     string
	ClusterName string
	Keys        []string
	Fields      []string
	Reply       *RedisReply
	OrderFree   bool
}

func BuildServletMocker(meta SpanMetadata, ex ServletExchange) *SpMocker {
	op := ex.OperationName
	if op == "" {
		op = ex.RequestPath
	}
	reqAttrs := map[string]any{
		AttrHTTPMethod:  ex.Method,
		AttrRequestPath: ex.RequestPath,
		AttrHeaders:     cloneStringMap(ex.RequestHeaders),
	}
	if ex.QueryString != "" {
		reqAttrs[AttrQueryString] = ex.QueryString
	}
	if ex.RemoteAddr != "" {
		reqAttrs[AttrRemoteAddr] = ex.RemoteAddr
	}

	var reqBody string
	if len(ex.RequestBody) > 0 {
		reqBody = base64.StdEncoding.EncodeToString(ex.RequestBody)
	}

	respAttrs := map[string]any{
		AttrHeaders: cloneStringMap(ex.ResponseHeaders),
	}

	m := baseMocker(CategoryServlet, SpanKindServer, op, meta)
	m.TargetRequest = &Target{
		Body:       reqBody,
		Attributes: reqAttrs,
	}
	m.TargetResponse = &Target{
		Body:       ex.ResponseBody,
		Attributes: respAttrs,
		Type:       JavaStringType,
	}
	return m
}

func BuildHTTPClientMocker(meta SpanMetadata, ex HTTPClientExchange) (*SpMocker, error) {
	reqAttrs := map[string]any{
		AttrHTTPMethod: ex.Method,
	}
	if ex.QueryString != "" {
		reqAttrs[AttrQueryString] = ex.QueryString
	} else {
		reqAttrs[AttrQueryString] = nil
	}
	if ex.ContentType != "" {
		reqAttrs[AttrContentType] = ex.ContentType
	}
	if ex.TargetAppID != "" {
		reqAttrs["Operation"] = ex.OperationName
		reqAttrs[HeaderAppID] = ex.TargetAppID
	}

	reqBody := ex.QueryString
	if len(ex.RequestBody) > 0 {
		reqBody = base64.StdEncoding.EncodeToString(ex.RequestBody)
	}

	m := baseMocker(CategoryHTTPClient, SpanKindClient, ex.OperationName, meta)
	m.TargetRequest = &Target{
		Body:       reqBody,
		Attributes: reqAttrs,
		Type:       JavaStringType,
	}

	if ex.Response != nil {
		respBytes, err := json.Marshal(*ex.Response)
		if err != nil {
			return nil, fmt.Errorf("marshaling HttpResponseWrapper: %w", err)
		}
		m.TargetResponse = &Target{
			Body: string(respBytes),
			Attributes: map[string]any{
				AttrSerializer: "jackson",
			},
			Type: HTTPResponseWrapperType,
		}
	} else {
		m.TargetResponse = &Target{}
	}
	return m, nil
}

func DecodeHTTPClientResponse(m *SpMocker) (*HTTPResponseWrapper, error) {
	if m == nil || m.TargetResponse == nil || m.TargetResponse.Body == "" {
		return nil, errors.New("missing HttpClient targetResponse body")
	}
	var wrapper HTTPResponseWrapper
	if err := json.Unmarshal([]byte(m.TargetResponse.Body), &wrapper); err != nil {
		return nil, fmt.Errorf("decoding HttpClient response wrapper: %w", err)
	}
	return &wrapper, nil
}

func NormalizeSQL(sql string) string {
	var sb strings.Builder
	sb.Grow(len(sql))
	var quote byte
	pendingSpace := false
	for i := range len(sql) {
		c := sql[i]
		if quote != 0 {
			sb.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			if pendingSpace && sb.Len() > 0 {
				sb.WriteByte(' ')
			}
			pendingSpace = false
			quote = c
			sb.WriteByte(c)
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			pendingSpace = true
			continue
		}
		if pendingSpace && sb.Len() > 0 {
			sb.WriteByte(' ')
		}
		pendingSpace = false
		sb.WriteByte(c)
	}
	return sb.String()
}

func BuildDatabaseMocker(meta SpanMetadata, ex DatabaseExchange) (*SpMocker, error) {
	paramsJSON := "[]"
	if len(ex.Parameters) > 0 {
		raw, err := json.Marshal(ex.Parameters)
		if err != nil {
			return nil, fmt.Errorf("marshaling database parameters: %w", err)
		}
		paramsJSON = string(raw)
	}

	reqAttrs := map[string]any{
		AttrDBName:       ex.DBName,
		AttrDBParameters: paramsJSON,
	}

	// operationName is fixed to "query" without "@" so DatabaseParseService
	// canonicalizes db@table@Action@query identically on record and replay.
	m := baseMocker(CategoryDatabase, SpanKindClient, DatabaseQueryOperationName, meta)
	m.TargetRequest = &Target{
		Body:       NormalizeSQL(ex.SQL),
		Attributes: reqAttrs,
	}

	if ex.Result != nil {
		respBytes, err := json.Marshal(ex.Result)
		if err != nil {
			return nil, fmt.Errorf("marshaling database result: %w", err)
		}
		m.TargetResponse = &Target{
			Body: string(respBytes),
			Type: DatabaseResultType,
		}
	} else {
		m.TargetResponse = &Target{}
	}
	return m, nil
}

func DecodeDatabaseResult(m *SpMocker) (*DatabaseResult, error) {
	if m == nil || m.TargetResponse == nil || m.TargetResponse.Body == "" {
		return nil, errors.New("missing Database targetResponse body")
	}
	var res DatabaseResult
	if err := json.Unmarshal([]byte(m.TargetResponse.Body), &res); err != nil {
		return nil, fmt.Errorf("decoding DatabaseResult: %w", err)
	}
	return &res, nil
}

func CanonicalizeRedisMultiKey(command string, keys, fields []string, sortOrderFree bool) (RedisMultiKey, string) {
	cmd := strings.ToUpper(strings.TrimSpace(command))
	slot := redisOrderFreeSlot(cmd)

	keyCopy := slices.Clone(keys)
	fieldCopy := slices.Clone(fields)
	var declaredSlot string
	if slot == OrderFreeSlotKey && len(keyCopy) >= 2 && tokensCanJoinLosslessly(keyCopy) {
		declaredSlot = OrderFreeSlotKey
		if sortOrderFree {
			slices.Sort(keyCopy)
		}
	} else if slot == OrderFreeSlotField && len(fieldCopy) >= 2 && tokensCanJoinLosslessly(fieldCopy) {
		declaredSlot = OrderFreeSlotField
		if sortOrderFree {
			slices.Sort(fieldCopy)
		}
	}

	var mk RedisMultiKey
	if len(keyCopy) > 0 {
		mk.Key = strings.Join(keyCopy, ";")
	}
	if len(fieldCopy) > 0 {
		mk.Field = strings.Join(fieldCopy, ";")
	}
	return mk, declaredSlot
}

func redisOrderFreeSlot(command string) string {
	switch command {
	case "MGET", "DEL", "EXISTS", "SUNION":
		return OrderFreeSlotKey
	case "HMGET", "HDEL", "SADD", "SREM", "ZREM":
		return OrderFreeSlotField
	default:
		return ""
	}
}

func tokensCanJoinLosslessly(tokens []string) bool {
	for _, t := range tokens {
		if strings.ContainsRune(t, ';') || strings.ContainsRune(t, '\uFFFD') {
			return false
		}
	}
	return true
}

func BuildRedisMocker(meta SpanMetadata, ex RedisExchange) (*SpMocker, error) {
	cmd := strings.ToUpper(strings.TrimSpace(ex.Command))
	mk, declaredSlot := CanonicalizeRedisMultiKey(cmd, ex.Keys, ex.Fields, ex.OrderFree)
	reqBody, err := json.Marshal(mk)
	if err != nil {
		return nil, fmt.Errorf("marshaling RedisMultiKey: %w", err)
	}

	reqAttrs := map[string]any{
		AttrClusterName: ex.ClusterName,
	}
	if declaredSlot != "" {
		reqAttrs[AttrOrderFreeSlot] = declaredSlot
	}

	m := baseMocker(CategoryRedis, SpanKindClient, cmd, meta)
	m.TargetRequest = &Target{
		Body:       string(reqBody),
		Attributes: reqAttrs,
		Type:       JavaStringType,
	}

	if ex.Reply != nil {
		respAttrs := make(map[string]any)
		var respBody string
		if ex.Reply.IsNil {
			respAttrs[AttrRecordedNull] = true
		} else {
			raw, err := json.Marshal(ex.Reply)
			if err != nil {
				return nil, fmt.Errorf("marshaling RedisReply: %w", err)
			}
			respBody = string(raw)
		}
		m.TargetResponse = &Target{
			Body:       respBody,
			Attributes: respAttrs,
			Type:       RedisReplyType,
		}
	} else {
		m.TargetResponse = &Target{}
	}
	return m, nil
}

func DecodeRedisReply(m *SpMocker) (*RedisReply, error) {
	if m == nil || m.TargetResponse == nil {
		return nil, errors.New("missing Redis targetResponse")
	}
	if m.TargetResponse.AttributeBool(AttrRecordedNull) {
		return &RedisReply{Type: "$", IsNil: true}, nil
	}
	if m.TargetResponse.Body == "" {
		return nil, errors.New("missing Redis targetResponse body")
	}
	var reply RedisReply
	if err := json.Unmarshal([]byte(m.TargetResponse.Body), &reply); err != nil {
		return nil, fmt.Errorf("decoding RedisReply: %w", err)
	}
	return &reply, nil
}

func BuildOTLPSpanAttributes(m *SpMocker) (map[string]any, error) {
	if m == nil {
		return nil, errors.New("nil SpMocker")
	}

	reqTarget := m.TargetRequest
	if reqTarget == nil {
		reqTarget = &Target{}
	}
	respTarget := m.TargetResponse
	if respTarget == nil {
		respTarget = &Target{}
	}

	reqJSON, err := json.Marshal(reqTarget)
	if err != nil {
		return nil, fmt.Errorf("marshaling sp_target_request_json: %w", err)
	}
	respJSON, err := json.Marshal(respTarget)
	if err != nil {
		return nil, fmt.Errorf("marshaling sp_target_response_json: %w", err)
	}
	mockerJSON, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshaling sp_mocker: %w", err)
	}

	attrs := map[string]any{
		OTLPAttrAppID:              m.AppID,
		OTLPAttrCategoryType:       m.CategoryType.Name,
		OTLPAttrTraceID:            m.TraceID,
		OTLPAttrSpanID:             m.SpanID,
		OTLPAttrParentSpanID:       m.ParentSpanID,
		OTLPAttrSegmentID:          m.SegmentID,
		OTLPAttrSpanKind:           m.SpanKind,
		OTLPAttrOperationName:      m.OperationName,
		OTLPAttrOperation:          m.OperationName,
		OTLPAttrMocker:             string(mockerJSON),
		OTLPAttrCreationTime:       m.CreationTime,
		OTLPAttrRecordEnvironment:  m.RecordEnvironment,
		OTLPAttrRecordVersion:      m.RecordVersion,
		OTLPAttrTargetRequestJSON:  string(reqJSON),
		OTLPAttrTargetResponseJSON: string(respJSON),
	}
	if m.SessionID != "" {
		attrs[OTLPAttrSessionID] = m.SessionID
	}
	if m.ReplayID != "" {
		attrs[OTLPAttrReplayID] = m.ReplayID
	}
	if len(m.Tags) > 0 {
		tagsJSON, err := json.Marshal(m.Tags)
		if err != nil {
			return nil, fmt.Errorf("marshaling sp_tags_json: %w", err)
		}
		attrs[OTLPAttrTagsJSON] = string(tagsJSON)
	}
	if m.Seq != nil {
		attrs[OTLPAttrSeq] = *m.Seq
	}
	if m.SpanCountStarted != nil {
		attrs[OTLPAttrSpanCountStarted] = *m.SpanCountStarted
	}
	if m.SpanCountDropped != nil {
		attrs[OTLPAttrSpanCountDropped] = *m.SpanCountDropped
	}
	return attrs, nil
}

func baseMocker(cat MockCategoryType, spanKind, opName string, meta SpanMetadata) *SpMocker {
	parentSpanID := meta.ParentSpanID
	if cat.EntryPoint {
		parentSpanID = ""
	}
	segmentID := meta.SegmentID
	if segmentID == "" && cat.EntryPoint {
		segmentID = meta.SpanID
	}
	return &SpMocker{
		CategoryType:      cat,
		ReplayID:          meta.ReplayID,
		TraceID:           meta.TraceID,
		AppID:             meta.AppID,
		RecordEnvironment: meta.RecordEnvironment,
		SessionID:         meta.SessionID,
		SpanID:            meta.SpanID,
		ParentSpanID:      parentSpanID,
		SegmentID:         segmentID,
		SpanKind:          spanKind,
		StartTimeNanos:    meta.StartTimeNanos,
		EndTimeNanos:      meta.EndTimeNanos,
		CreationTime:      meta.CreationTimeMs,
		OperationName:     opName,
		RecordVersion:     meta.RecordVersion,
		Tags:              cloneStringMap(meta.Tags),
	}
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	return maps.Clone(in)
}
