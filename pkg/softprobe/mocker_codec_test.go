// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleSpanMeta() SpanMetadata {
	return SpanMetadata{
		AppID:             "travel-ota",
		TraceID:           "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:            "00f067aa0ba902b7",
		ParentSpanID:      "1111222233334444",
		SegmentID:         "seg-root-01",
		CreationTimeMs:    1730000000123,
		StartTimeNanos:    1730000000123000000,
		EndTimeNanos:      1730000000145000000,
		RecordEnvironment: 1,
		RecordVersion:     "obi-v1",
		SessionID:         "sess-01",
		Tags: map[string]string{
			"env": "staging",
		},
	}
}

func TestBuildServletAndHTTPClientMockers(t *testing.T) {
	meta := sampleSpanMeta()

	servlet := BuildServletMocker(meta, ServletExchange{
		Method:          http.MethodPost,
		RequestPath:     "/api/v1/orders",
		QueryString:     "currency=USD",
		RemoteAddr:      "10.0.0.5:51234",
		RequestHeaders:  map[string]string{"Content-Type": "application/json"},
		RequestBody:     []byte(`{"flightId":"SP101"}`),
		StatusCode:      http.StatusOK,
		ResponseHeaders: map[string]string{"Content-Type": "application/json"},
		ResponseBody:    `{"orderId":"ORD-1"}`,
	})
	assert.Equal(t, CategoryServlet, servlet.CategoryType)
	assert.True(t, servlet.CategoryType.EntryPoint)
	assert.Empty(t, servlet.ParentSpanID)
	assert.Equal(t, "/api/v1/orders", servlet.OperationName)
	assert.JSONEq(t, `{"orderId":"ORD-1"}`, servlet.TargetResponse.Body)

	httpMocker, err := BuildHTTPClientMocker(meta, HTTPClientExchange{
		Method:        http.MethodPost,
		OperationName: "/ndc/v2/airShopping",
		ContentType:   "application/json",
		RequestBody:   []byte(`{"origin":"SFO","dest":"JFK"}`),
		TargetAppID:   "sp-airline-ndc",
		Response: &HTTPResponseWrapper{
			Status:  http.StatusOK,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    `{"offers":[{"id":"OF-1"}]}`,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, CategoryHTTPClient, httpMocker.CategoryType)
	assert.False(t, httpMocker.CategoryType.EntryPoint)
	assert.Equal(t, "1111222233334444", httpMocker.ParentSpanID)
	assert.Equal(t, HTTPResponseWrapperType, httpMocker.TargetResponse.Type)
	assert.Equal(t, "sp-airline-ndc", httpMocker.TargetRequest.AttributeString(HeaderAppID))

	decodedResp, err := DecodeHTTPClientResponse(httpMocker)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, decodedResp.Status)
	assert.JSONEq(t, `{"offers":[{"id":"OF-1"}]}`, decodedResp.Body)
	assert.Equal(t, "application/json", decodedResp.Headers["Content-Type"])
}

func TestBuildDatabaseMockerAndDecodeResult(t *testing.T) {
	meta := sampleSpanMeta()
	rawSQL := "SELECT id, status\r\nFROM bookings\n\tWHERE user_id = $1 AND active = $2"

	mocker, err := BuildDatabaseMocker(meta, DatabaseExchange{
		DBName:     "ota_db",
		SQL:        rawSQL,
		Parameters: []any{42, true},
		Result: &DatabaseResult{
			Columns: []DatabaseColumn{
				{Name: "id", DataType: "int8", TypeOID: 20},
				{Name: "status", DataType: "varchar", TypeOID: 1043},
			},
			Rows:         [][]any{{float64(9001), "CONFIRMED"}},
			RowsAffected: 1,
			CommandTag:   "SELECT 1",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, CategoryDatabase, mocker.CategoryType)
	assert.Equal(t, DatabaseQueryOperationName, mocker.OperationName)
	assert.NotContains(t, mocker.OperationName, "@")
	assert.Equal(t, "SELECT id, status FROM bookings WHERE user_id = $1 AND active = $2", mocker.TargetRequest.Body)
	assert.Equal(t, "SELECT 'keep  two\nspaces' FROM dual", NormalizeSQL("  SELECT\n\t 'keep  two\nspaces'  FROM\r\ndual "))
	assert.Equal(t, "ota_db", mocker.TargetRequest.AttributeString(AttrDBName))
	assert.JSONEq(t, `[42,true]`, mocker.TargetRequest.AttributeString(AttrDBParameters))

	decoded, err := DecodeDatabaseResult(mocker)
	require.NoError(t, err)
	require.Len(t, decoded.Columns, 2)
	assert.Equal(t, "status", decoded.Columns[1].Name)
	require.Len(t, decoded.Rows, 1)
	assert.Equal(t, "CONFIRMED", decoded.Rows[0][1])
}

func TestRedisMultiKeyCanonicalizationAndNullReply(t *testing.T) {
	meta := sampleSpanMeta()

	t.Run("sorts order-free MGET keys when requested", func(t *testing.T) {
		mocker, err := BuildRedisMocker(meta, RedisExchange{
			Command:     "mget",
			ClusterName: "redis-cache:6379",
			Keys:        []string{"seat:3B", "seat:1A", "seat:2C"},
			OrderFree:   true,
			Reply: &RedisReply{
				Type: "*",
				Elements: []RedisReply{
					{Type: "$", Bulk: []byte("open")},
					{Type: "$", IsNil: true},
					{Type: "$", Bulk: []byte("held")},
				},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "MGET", mocker.OperationName)
		assert.Equal(t, OrderFreeSlotKey, mocker.TargetRequest.AttributeString(AttrOrderFreeSlot))
		assert.JSONEq(t, `{"key":"seat:1A;seat:2C;seat:3B"}`, mocker.TargetRequest.Body)

		reply, err := DecodeRedisReply(mocker)
		require.NoError(t, err)
		require.Len(t, reply.Elements, 3)
		assert.True(t, reply.Elements[1].IsNil)
	})

	t.Run("preserves order-sensitive LPUSH arguments and semicolon-containing keys", func(t *testing.T) {
		mkOrderSensitive, slot := CanonicalizeRedisMultiKey("LPUSH", []string{"queue:jobs"}, []string{"z", "a"}, true)
		assert.Empty(t, slot)
		assert.Equal(t, "queue:jobs", mkOrderSensitive.Key)
		assert.Equal(t, "z;a", mkOrderSensitive.Field)

		mkWithSemicolon, semiSlot := CanonicalizeRedisMultiKey("MGET", []string{"k;2", "k1"}, nil, true)
		assert.Empty(t, semiSlot)
		assert.Equal(t, "k;2;k1", mkWithSemicolon.Key)
	})

	t.Run("encodes nil bulk reply with sp.recordedNull", func(t *testing.T) {
		mocker, err := BuildRedisMocker(meta, RedisExchange{
			Command:     "GET",
			ClusterName: "redis-cache:6379",
			Keys:        []string{"session:missing"},
			Reply:       &RedisReply{Type: "$", IsNil: true},
		})
		require.NoError(t, err)
		assert.Empty(t, mocker.TargetResponse.Body)
		assert.True(t, mocker.TargetResponse.AttributeBool(AttrRecordedNull))

		decoded, err := DecodeRedisReply(mocker)
		require.NoError(t, err)
		assert.True(t, decoded.IsNil)
		assert.Equal(t, "$", decoded.Type)
	})
}

func TestBuildOTLPSpanAttributesRoundTrip(t *testing.T) {
	meta := sampleSpanMeta()
	seq := 3
	started := 5
	dropped := 0
	mocker, err := BuildDatabaseMocker(meta, DatabaseExchange{
		DBName:     "ota_db",
		SQL:        "SELECT 1",
		Parameters: nil,
		Result:     &DatabaseResult{Rows: [][]any{{float64(1)}}, RowsAffected: 1},
	})
	require.NoError(t, err)
	mocker.Seq = &seq
	mocker.SpanCountStarted = &started
	mocker.SpanCountDropped = &dropped

	attrs, err := BuildOTLPSpanAttributes(mocker)
	require.NoError(t, err)

	assert.Equal(t, "travel-ota", attrs[OTLPAttrAppID])
	assert.Equal(t, "Database", attrs[OTLPAttrCategoryType])
	assert.Equal(t, meta.TraceID, attrs[OTLPAttrTraceID])
	assert.Equal(t, meta.SpanID, attrs[OTLPAttrSpanID])
	assert.Equal(t, meta.ParentSpanID, attrs[OTLPAttrParentSpanID])
	assert.Equal(t, meta.SegmentID, attrs[OTLPAttrSegmentID])
	assert.Equal(t, SpanKindClient, attrs[OTLPAttrSpanKind])
	assert.Equal(t, DatabaseQueryOperationName, attrs[OTLPAttrOperationName])
	assert.Equal(t, DatabaseQueryOperationName, attrs[OTLPAttrOperation])
	assert.Equal(t, "obi-v1", attrs[OTLPAttrRecordVersion])
	assert.Equal(t, 3, attrs[OTLPAttrSeq])
	assert.Equal(t, 5, attrs[OTLPAttrSpanCountStarted])
	assert.Equal(t, 0, attrs[OTLPAttrSpanCountDropped])

	mockerJSON, ok := attrs[OTLPAttrMocker].(string)
	require.True(t, ok)
	var roundTrip SpMocker
	require.NoError(t, json.Unmarshal([]byte(mockerJSON), &roundTrip))
	assert.Equal(t, mocker.CategoryType, roundTrip.CategoryType)
	assert.Equal(t, "SELECT 1", roundTrip.TargetRequest.Body)
	require.NotNil(t, roundTrip.Seq)
	assert.Equal(t, 3, *roundTrip.Seq)
}
