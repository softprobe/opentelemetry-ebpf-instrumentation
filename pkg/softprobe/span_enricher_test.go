// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestSpanEnricherServletAndChildSegmentInvariant(t *testing.T) {
	reg := NewReplayRegistry(128, time.Minute)
	enricher := NewSpanEnricher(Config{
		Enabled:               true,
		AppID:                 "travel-ota",
		Env:                   "pro",
		ExcludeErrorResponses: true,
		RecordRate:            1.0,
	}, reg)

	traceID := [16]byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef, 0x01}
	servletSpanID := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	clientSpanID := [8]byte{0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}
	nowNano := time.Unix(1730000000, 0).UnixNano()

	clientSpan := &request.Span{
		Type:         request.EventTypeHTTPClient,
		Method:       "POST",
		Path:         "/ndc/v21.3/airshopping",
		Status:       200,
		TraceID:      trace.TraceID(traceID),
		SpanID:       trace.SpanID(clientSpanID),
		ParentSpanID: trace.SpanID(servletSpanID),
		Softprobe: &request.SoftprobeCapture{
			RawQuery: "cabin=ECONOMY",
			RequestHeaders: map[string][]string{
				"Content-Type": {"application/xml"},
			},
			ResponseHeaders: map[string][]string{
				"Content-Type": {"application/xml"},
			},
			RequestBody:  []byte("<IATA_AirShoppingRQ/>"),
			ResponseBody: []byte("<IATA_AirShoppingRS><OfferID>OF-1</OfferID></IATA_AirShoppingRS>"),
			StatusReason: "OK",
		},
	}

	childRes := enricher.EnrichSpan(clientSpan, traceID, clientSpanID, nowNano+1_000_000, nowNano+5_000_000)
	require.NotNil(t, childRes.Mocker)
	assert.False(t, childRes.IsEntryPoint)
	assert.Equal(t, "1122334455667788", childRes.Mocker.SegmentID)
	assert.Equal(t, "1122334455667788", childRes.Mocker.ParentSpanID)
	assert.Equal(t, "1122334455667788", childRes.Attributes[OTLPAttrSegmentID])
	assert.Equal(t, "/ndc/v21.3/airshopping", childRes.Mocker.OperationName)

	decodedWrapper, err := DecodeHTTPClientResponse(childRes.Mocker)
	require.NoError(t, err)
	assert.Equal(t, 200, decodedWrapper.StatusCode)
	assert.Contains(t, decodedWrapper.Body, "<OfferID>OF-1</OfferID>")

	servletSpan := &request.Span{
		Type:         request.EventTypeHTTP,
		Method:       "POST",
		Path:         "/api/flights/search",
		Peer:         "127.0.0.1",
		Status:       200,
		TraceID:      trace.TraceID(traceID),
		SpanID:       trace.SpanID(servletSpanID),
		ParentSpanID: trace.SpanID([8]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}),
		Softprobe: &request.SoftprobeCapture{
			RawQuery: "currency=USD",
			RequestHeaders: map[string][]string{
				"Content-Type": {"application/json"},
			},
			ResponseHeaders: map[string][]string{
				"Content-Type": {"application/json"},
			},
			RequestBody:  []byte(`{"origin":"DXB","destination":"LHR"}`),
			ResponseBody: []byte(`{"offers":[{"id":"OF-1"}]}`),
		},
	}

	servletRes := enricher.EnrichSpan(servletSpan, traceID, servletSpanID, nowNano, nowNano+10_000_000)
	require.NotNil(t, servletRes.Mocker)
	assert.True(t, servletRes.IsEntryPoint)
	assert.Equal(t, "1122334455667788", servletRes.Mocker.SpanID)
	assert.Equal(t, "1122334455667788", servletRes.Mocker.SegmentID)
	assert.Empty(t, servletRes.Mocker.ParentSpanID)
	assert.Empty(t, servletRes.Attributes[OTLPAttrParentSpanID])
	assert.Equal(t, "1122334455667788", servletRes.Attributes[OTLPAttrSegmentID])
	assert.Equal(t, "Servlet", servletRes.Attributes[OTLPAttrCategoryType])
}

func TestSpanEnricherDatabaseAndRedisWireMockers(t *testing.T) {
	enricher := NewSpanEnricher(Config{
		Enabled:    true,
		AppID:      "polyglot-app",
		Env:        "pro",
		RecordRate: 1.0,
	}, nil)

	traceID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	rootSpanID := [8]byte{1, 1, 1, 1, 1, 1, 1, 1}
	pgSpanID := [8]byte{2, 2, 2, 2, 2, 2, 2, 2}
	mysqlSpanID := [8]byte{3, 3, 3, 3, 3, 3, 3, 3}
	redisSpanID := [8]byte{4, 4, 4, 4, 4, 4, 4, 4}
	nowNano := time.Unix(1730000100, 0).UnixNano()

	pgBindReq := buildTestPgBindFrame([]string{"ORD-42"})
	pgDataResp := buildTestPgSelectFrame([]string{"id", "status"}, [][]string{{"ORD-42", "PAID"}}, "SELECT 1")

	pgSpan := &request.Span{
		Type:         request.EventTypeSQLClient,
		SubType:      int(request.DBPostgres),
		DBNamespace:  "orders_db",
		Statement:    "SELECT id, status FROM orders WHERE id = $1",
		TraceID:      trace.TraceID(traceID),
		SpanID:       trace.SpanID(pgSpanID),
		ParentSpanID: trace.SpanID(rootSpanID),
		Softprobe: &request.SoftprobeCapture{
			SQLWireRequest:  pgBindReq,
			SQLWireResponse: pgDataResp,
		},
	}
	pgRes := enricher.EnrichSpan(pgSpan, traceID, pgSpanID, nowNano, nowNano+1_000_000)
	require.NotNil(t, pgRes.Mocker)
	assert.Equal(t, CategoryDatabase.Name, pgRes.Mocker.CategoryType.Name)
	assert.Equal(t, "orders_db", pgRes.Mocker.TargetRequest.Attributes[AttrDBName])
	assert.Equal(t, "SELECT id, status FROM orders WHERE id = $1", pgRes.Mocker.TargetRequest.Body)
	assert.Contains(t, pgRes.Mocker.TargetRequest.Attributes[AttrDBParameters], "ORD-42")

	pgDecoded, err := DecodeDatabaseResult(pgRes.Mocker)
	require.NoError(t, err)
	require.Len(t, pgDecoded.Columns, 2)
	assert.Equal(t, "status", pgDecoded.Columns[1].Name)
	require.Len(t, pgDecoded.Rows, 1)
	assert.Equal(t, "PAID", pgDecoded.Rows[0][1])

	mysqlSpan := &request.Span{
		Type:         request.EventTypeSQLClient,
		SubType:      int(request.DBMySQL),
		DBNamespace:  "payments_db",
		Statement:    "UPDATE payments SET settled = 1 WHERE order_id = 'ORD-42'",
		TraceID:      trace.TraceID(traceID),
		SpanID:       trace.SpanID(mysqlSpanID),
		ParentSpanID: trace.SpanID(rootSpanID),
		Softprobe: &request.SoftprobeCapture{
			SQLWireResponse: buildTestMySQLOKPacket(1, 99),
		},
	}
	mysqlRes := enricher.EnrichSpan(mysqlSpan, traceID, mysqlSpanID, nowNano, nowNano+1_000_000)
	require.NotNil(t, mysqlRes.Mocker)
	mysqlDecoded, err := DecodeDatabaseResult(mysqlRes.Mocker)
	require.NoError(t, err)
	assert.Equal(t, int64(1), mysqlDecoded.RowsAffected)
	assert.Equal(t, int64(99), mysqlDecoded.LastInsertID)

	redisSpan := &request.Span{
		Type:         request.EventTypeRedisClient,
		Method:       "HSET",
		DBNamespace:  "0",
		TraceID:      trace.TraceID(traceID),
		SpanID:       trace.SpanID(redisSpanID),
		ParentSpanID: trace.SpanID(rootSpanID),
		Softprobe: &request.SoftprobeCapture{
			RedisWireReq:  []byte("*4\r\n$4\r\nHSET\r\n$9\r\nsession:1\r\n$4\r\nuser\r\n$5\r\nalice\r\n"),
			RedisWireResp: []byte(":1\r\n"),
		},
	}
	redisRes := enricher.EnrichSpan(redisSpan, traceID, redisSpanID, nowNano, nowNano+500_000)
	require.NotNil(t, redisRes.Mocker)
	assert.Equal(t, CategoryRedis.Name, redisRes.Mocker.CategoryType.Name)
	assert.Equal(t, "HSET", redisRes.Mocker.OperationName)
	assert.Contains(t, redisRes.Mocker.TargetRequest.Body, "session:1")
	redisReply, err := DecodeRedisReply(redisRes.Mocker)
	require.NoError(t, err)
	assert.Equal(t, ":", redisReply.Type)
	assert.Equal(t, int64(1), redisReply.Int)
}

func TestSpanEnricherErrorSuppressionReplayGuardAndSampling(t *testing.T) {
	reg := NewReplayRegistry(128, time.Minute)
	enricher := NewSpanEnricher(Config{
		Enabled:               true,
		AppID:                 "travel-ota",
		ExcludeErrorResponses: true,
		RecordRate:            1.0,
	}, reg)

	traceErr := [16]byte{0xaa, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	spanErr := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	errServlet := &request.Span{
		Type:   request.EventTypeHTTP,
		Method: "GET",
		Path:   "/missing",
		Status: 404,
	}
	res404 := enricher.EnrichSpan(errServlet, traceErr, spanErr, 1000, 2000)
	assert.Nil(t, res404.Mocker)
	assert.Empty(t, res404.Attributes)
	assert.True(t, res404.IsEntryPoint)

	traceReplay := [16]byte{0xbb, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	servletReplaySpan := &request.Span{
		Type:   request.EventTypeHTTP,
		Method: "POST",
		Path:   "/api/flights/search",
		Status: 200,
		Softprobe: &request.SoftprobeCapture{
			RequestHeaders: map[string][]string{
				"sp-record-id": {"rec-case-1"},
				"sp-replay-id": {"rep-run-9"},
			},
		},
	}
	enricher.ObserveServerSpan(servletReplaySpan, traceReplay, spanErr)
	sess, isReplay := reg.Lookup(traceReplay)
	require.True(t, isReplay)
	assert.Equal(t, "rec-case-1", sess.RecordedTraceID)
	assert.Equal(t, "rep-run-9", sess.ReplayID)

	childReplay := &request.Span{
		Type:   request.EventTypeHTTPClient,
		Method: "POST",
		Path:   "/ndc/v21.3/airshopping",
		Status: 200,
	}
	childRes := enricher.EnrichSpan(childReplay, traceReplay, [8]byte{9, 9, 9, 9, 9, 9, 9, 9}, 1000, 1500)
	assert.True(t, childRes.SuppressedReplay)
	assert.Nil(t, childRes.Mocker)
	assert.Empty(t, childRes.Attributes)

	servletRes := enricher.EnrichSpan(servletReplaySpan, traceReplay, spanErr, 1000, 2000)
	assert.True(t, servletRes.SuppressedReplay)
	assert.Nil(t, servletRes.Mocker)
	assert.Empty(t, servletRes.Attributes)

	zeroEnricher := NewSpanEnricher(Config{
		Enabled:    true,
		AppID:      "travel-ota",
		RecordRate: 0.0,
	}, nil)
	okServlet := &request.Span{
		Type:   request.EventTypeHTTP,
		Method: "POST",
		Path:   "/api/flights/search",
		Status: 200,
	}
	assert.Nil(t, zeroEnricher.EnrichSpan(okServlet, traceErr, spanErr, 1000, 2000).Mocker)
}

func buildTestPgBindFrame(params []string) []byte {
	var payload []byte
	payload = append(payload, 0)
	payload = append(payload, 0)
	payload = binary.BigEndian.AppendUint16(payload, 0)
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(params)))
	for _, p := range params {
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(p)))
		payload = append(payload, []byte(p)...)
	}
	payload = binary.BigEndian.AppendUint16(payload, 0)

	var frame []byte
	frame = append(frame, 'B')
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(payload)+4))
	frame = append(frame, payload...)
	return frame
}

func buildTestPgSelectFrame(cols []string, rows [][]string, tag string) []byte {
	var out []byte

	var rd []byte
	rd = binary.BigEndian.AppendUint16(rd, uint16(len(cols)))
	for _, c := range cols {
		rd = append(rd, []byte(c)...)
		rd = append(rd, 0)
		rd = append(rd, make([]byte, 18)...)
	}
	out = append(out, 'T')
	out = binary.BigEndian.AppendUint32(out, uint32(len(rd)+4))
	out = append(out, rd...)

	for _, row := range rows {
		var dr []byte
		dr = binary.BigEndian.AppendUint16(dr, uint16(len(row)))
		for _, val := range row {
			dr = binary.BigEndian.AppendUint32(dr, uint32(len(val)))
			dr = append(dr, []byte(val)...)
		}
		out = append(out, 'D')
		out = binary.BigEndian.AppendUint32(out, uint32(len(dr)+4))
		out = append(out, dr...)
	}

	cc := append([]byte(tag), 0)
	out = append(out, 'C')
	out = binary.BigEndian.AppendUint32(out, uint32(len(cc)+4))
	out = append(out, cc...)
	return out
}

func buildTestMySQLOKPacket(affected, insertID uint8) []byte {
	payload := []byte{0x00, affected, insertID, 0x02, 0x00, 0x00, 0x00}
	pkt := []byte{byte(len(payload)), 0x00, 0x00, 0x01}
	return append(pkt, payload...)
}
