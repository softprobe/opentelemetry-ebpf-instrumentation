// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestAttributesForHTTPClientUseSoftprobeOTLPContract(t *testing.T) {
	span := request.Span{
		Type:                     request.EventTypeHTTPClient,
		TraceID:                  trace.TraceID{1},
		SpanID:                   trace.SpanID{2},
		ParentSpanID:             trace.SpanID{3},
		Path:                     "/inventory/items",
		Method:                   "GET",
		FullPath:                 "https://inventory.example/inventory/items?sku=42",
		SoftprobeRequestPayload:  []byte("GET /inventory/items?sku=42 HTTP/1.1\r\nHost: inventory.example\r\n\r\n"),
		SoftprobeResponsePayload: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
	}

	attrs := AttributesForSpan(&span, "travel-ota")
	values := attributeValues(attrs)
	require.Equal(t, "HttpClient", values[AttributeCategoryType])
	require.Equal(t, span.TraceID.String(), values[AttributeTraceID])
	require.Equal(t, span.SpanID.String(), values[AttributeSpanID])
	require.Equal(t, span.ParentSpanID.String(), values[AttributeParentSpanID])
	require.Equal(t, "travel-ota", values[AttributeAppID])
	require.Equal(t, "/inventory/items", values[AttributeOperationName])

	var target Target
	require.NoError(t, json.Unmarshal([]byte(values[AttributeTargetRequest]), &target))
	require.Equal(t, "sku=42", target.Attributes["QueryString"])
	require.Equal(t, "GET", target.Attributes["HttpMethod"])
	require.Equal(t, "sku=42", target.Body)

	var response Target
	require.NoError(t, json.Unmarshal([]byte(values[AttributeTargetResponse]), &response))
	require.Equal(t, HTTPResponseWrapperType, response.Type)
}

func TestAttributesForDatabaseKeepRawPayloadWithoutInventingLegacyResponseType(t *testing.T) {
	span := request.Span{
		Type:                     request.EventTypeSQLClient,
		SoftprobeRequestPayload:  []byte("postgres request"),
		SoftprobeResponsePayload: []byte("postgres response"),
	}

	values := attributeValues(AttributesForSpan(&span, "travel-ota"))
	require.Equal(t, "cG9zdGdyZXMgcmVxdWVzdA==", values[AttributeRawRequestPayload])
	require.Equal(t, "cG9zdGdyZXMgcmVzcG9uc2U=", values[AttributeRawResponsePayload])
	_, hasLegacyCategory := values[AttributeCategoryType]
	require.False(t, hasLegacyCategory)
}

func TestAttributesForPostgresUseExistingDatabaseMockerContract(t *testing.T) {
	traceID, err := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	require.NoError(t, err)
	spanID, err := trace.SpanIDFromHex("1112131415161718")
	require.NoError(t, err)
	parentSpanID, err := trace.SpanIDFromHex("2122232425262728")
	require.NoError(t, err)
	span := request.Span{
		Type:                     request.EventTypeSQLClient,
		SubType:                  int(request.DBPostgres),
		Method:                   "INSERT",
		Path:                     "orders",
		DBNamespace:              "travel_orders",
		Statement:                "INSERT INTO orders (id) VALUES ('o-1')",
		TraceID:                  traceID,
		SpanID:                   spanID,
		ParentSpanID:             parentSpanID,
		SoftprobeRequestPayload:  []byte("postgres request frames"),
		SoftprobeResponsePayload: []byte("postgres response frames"),
	}

	values := attributeValues(AttributesForSpan(&span, "travel-ota"))
	require.Equal(t, "Database", values[AttributeCategoryType])
	require.Equal(t, "travel_orders@orders@INSERT@OBI.query", values[AttributeOperationName])
	require.Equal(t, span.TraceID.String(), values[AttributeTraceID])
	require.Equal(t, base64.StdEncoding.EncodeToString(span.SoftprobeRequestPayload), values[AttributeRawRequestPayload])
	require.Equal(t, base64.StdEncoding.EncodeToString(span.SoftprobeResponsePayload), values[AttributeRawResponsePayload])

	var requestTarget, responseTarget Target
	require.NoError(t, json.Unmarshal([]byte(values[AttributeTargetRequest]), &requestTarget))
	require.NoError(t, json.Unmarshal([]byte(values[AttributeTargetResponse]), &responseTarget))
	require.Equal(t, span.Statement, requestTarget.Body)
	require.Equal(t, "postgresql", requestTarget.Attributes["protocol"])
	require.Equal(t, base64.StdEncoding.EncodeToString(span.SoftprobeResponsePayload), responseTarget.Body)
	require.Equal(t, RawDatabaseResponseType("postgresql"), responseTarget.Type)
}

func TestDatabaseClientQueryUsesResolvedOBIContext(t *testing.T) {
	traceID := "0102030405060708090a0b0c0d0e0f10"
	replayID := "ffeeddccbbaa99887766554433221100"
	dbName := "travel_payments"
	sql := "INSERT INTO payments (id, amount) VALUES ('p-1', 22.5)"
	ctx := RequestTraceContext{TraceID: traceID, ReplayID: replayID}

	query, err := DatabaseClientQuery(ctx, "travel-ota", dbName, "mysql", sql)
	require.NoError(t, err)
	require.Equal(t, "Database", query.CategoryType.Name)
	require.Equal(t, traceID, query.TraceID)
	require.Equal(t, replayID, query.ReplayID)
	require.Equal(t, dbName+"@payments@INSERT@OBI.query", query.OperationName)
}

func attributeValues(attrs []attribute.KeyValue) map[string]string {
	values := make(map[string]string, len(attrs))
	for _, attr := range attrs {
		values[string(attr.Key)] = attr.Value.AsString()
	}
	return values
}
