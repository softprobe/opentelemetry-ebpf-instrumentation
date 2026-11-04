// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"encoding/base64"
	"encoding/json"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	AttributeCategoryType       = "sp_category_type"
	AttributeTraceID            = "sp_trace_id"
	AttributeSpanID             = "sp_span_id"
	AttributeParentSpanID       = "sp_parent_span_id"
	AttributeSegmentID          = "sp_segment_id"
	AttributeSpanKind           = "sp_span_kind"
	AttributeAppID              = "sp_app_id"
	AttributeOperationName      = "sp_operation_name"
	AttributeCreationTime       = "sp_creation_time"
	AttributeTargetRequest      = "sp_target_request_json"
	AttributeTargetResponse     = "sp_target_response_json"
	AttributeRawRequestPayload  = "obi.softprobe.payload.request"
	AttributeRawResponsePayload = "obi.softprobe.payload.response"
)

// AttributesForSpan attaches captured wire payloads to OBI spans and adapts
// HTTP client spans to the existing Softprobe recording contract. Other
// protocols retain their raw payload attributes until a protocol-specific
// replay contract is available.
func AttributesForSpan(span *request.Span, appID string) []attribute.KeyValue {
	if span == nil || (len(span.SoftprobeRequestPayload) == 0 && len(span.SoftprobeResponsePayload) == 0) {
		return nil
	}

	attrs := []attribute.KeyValue{
		attribute.String(AttributeRawRequestPayload, base64.StdEncoding.EncodeToString(span.SoftprobeRequestPayload)),
		attribute.String(AttributeRawResponsePayload, base64.StdEncoding.EncodeToString(span.SoftprobeResponsePayload)),
	}

	var mocker Mocker
	switch span.Type {
	case request.EventTypeHTTPClient:
		var err error
		mocker, err = HTTPClientRecording(*span, appID, span.SoftprobeRequestPayload, span.SoftprobeResponsePayload)
		if err != nil {
			return attrs
		}
	case request.EventTypeSQLClient:
		var err error
		mocker, err = DatabaseRecording(*span, appID)
		if err != nil {
			return attrs
		}
	default:
		return attrs
	}

	requestJSON, err := json.Marshal(mocker.TargetRequest)
	if err != nil {
		return attrs
	}
	responseJSON, err := json.Marshal(mocker.TargetResponse)
	if err != nil {
		return attrs
	}

	attrs = append(attrs,
		attribute.String(AttributeCategoryType, mocker.CategoryType.Name),
		attribute.String(AttributeTraceID, mocker.TraceID),
		attribute.String(AttributeSpanID, mocker.SpanID),
		attribute.String(AttributeParentSpanID, mocker.ParentSpanID),
		attribute.String(AttributeSegmentID, mocker.SegmentID),
		attribute.String(AttributeSpanKind, mocker.SpanKind),
		attribute.String(AttributeAppID, mocker.AppID),
		attribute.String(AttributeOperationName, mocker.OperationName),
		attribute.Int64(AttributeCreationTime, mocker.CreationTime),
		attribute.String(AttributeTargetRequest, string(requestJSON)),
		attribute.String(AttributeTargetResponse, string(responseJSON)),
	)
	return attrs
}
