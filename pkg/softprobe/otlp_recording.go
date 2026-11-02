// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func exportRecordingSpan(
	ctx context.Context,
	client *http.Client,
	endpoint *url.URL,
	mocker Mocker,
	scopeName string,
	spanName string,
	kind ptrace.SpanKind,
	flags uint32,
	start time.Time,
) error {
	traceID, err := decodeID(mocker.TraceID, traceIDLength, "trace ID")
	if err != nil {
		return err
	}
	spanID, err := decodeID(mocker.SpanID, spanIDLength, "span ID")
	if err != nil {
		return err
	}
	var parentSpanID []byte
	if mocker.ParentSpanID != "" {
		parentSpanID, err = decodeID(mocker.ParentSpanID, spanIDLength, "parent span ID")
		if err != nil {
			return err
		}
	}
	requestJSON, err := json.Marshal(mocker.TargetRequest)
	if err != nil {
		return fmt.Errorf("encode Softprobe request target: %w", err)
	}
	responseJSON, err := json.Marshal(mocker.TargetResponse)
	if err != nil {
		return fmt.Errorf("encode Softprobe response target: %w", err)
	}

	traces := ptrace.NewTraces()
	resourceSpans := traces.ResourceSpans().AppendEmpty()
	resourceSpans.Resource().Attributes().PutStr("service.name", mocker.AppID)
	scopeSpans := resourceSpans.ScopeSpans().AppendEmpty()
	scopeSpans.Scope().SetName(scopeName)
	span := scopeSpans.Spans().AppendEmpty()
	span.SetTraceID(pcommon.TraceID(traceID))
	span.SetSpanID(pcommon.SpanID(spanID))
	if len(parentSpanID) > 0 {
		span.SetParentSpanID(pcommon.SpanID(parentSpanID))
	}
	span.SetName(spanName)
	span.SetKind(kind)
	span.SetFlags(flags)
	span.SetStartTimestamp(pcommon.NewTimestampFromTime(start))
	span.SetEndTimestamp(pcommon.NewTimestampFromTime(time.Now()))
	attrs := span.Attributes()
	attrs.PutStr("sp_category_type", mocker.CategoryType.Name)
	attrs.PutStr("sp_trace_id", mocker.TraceID)
	attrs.PutStr("sp_span_id", mocker.SpanID)
	if mocker.ParentSpanID != "" {
		attrs.PutStr("sp_parent_span_id", mocker.ParentSpanID)
	}
	if mocker.SegmentID != "" {
		attrs.PutStr("sp_segment_id", mocker.SegmentID)
	}
	attrs.PutStr("sp_span_kind", mocker.SpanKind)
	attrs.PutStr("sp_app_id", mocker.AppID)
	attrs.PutStr("sp_operation_name", mocker.OperationName)
	attrs.PutInt("sp_creation_time", mocker.CreationTime)
	attrs.PutStr("sp_target_request_json", string(requestJSON))
	attrs.PutStr("sp_target_response_json", string(responseJSON))

	payload, err := (&ptrace.ProtoMarshaler{}).MarshalTraces(traces)
	if err != nil {
		return fmt.Errorf("encode OTLP recording: %w", err)
	}
	requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create OTLP recording request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send OTLP recording: %w", err)
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return fmt.Errorf("read OTLP recording response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("OTLP recording endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}

func decodeID(value string, size int, label string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != size {
		return nil, fmt.Errorf("invalid Softprobe %s", label)
	}
	return decoded, nil
}
