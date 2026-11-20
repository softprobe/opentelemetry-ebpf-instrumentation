// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func TestCaptureSoftprobeHTTPDecompressesAndRestoresBodies(t *testing.T) {
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	_, err := gz.Write([]byte(`{"offers":[{"id":"OFF-1"}]}`))
	require.NoError(t, err)
	require.NoError(t, gz.Close())

	req := &http.Request{
		Method: http.MethodPost,
		Host:   "spair.softprobe.ai",
		URL:    &url.URL{Path: "/ndc/v21.3/airshopping", RawQuery: "adult=1&cabin=Y"},
		Header: http.Header{
			"Content-Type": []string{"application/json"},
			"X-Sp-Test":    []string{"abc"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"origin":"SFO","destination":"JFK"}`))),
	}
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":     []string{"application/json"},
			"Content-Encoding": []string{"gzip"},
		},
		Body: io.NopCloser(bytes.NewReader(gzBuf.Bytes())),
	}

	span := &request.Span{
		Type:     request.EventTypeHTTPClient,
		Method:   http.MethodPost,
		Path:     "/ndc/v21.3/airshopping",
		FullPath: "/ndc/v21.3/airshopping?adult=1&cabin=Y",
		Status:   200,
	}

	captureSoftprobeHTTP(4096, span, req, resp)
	require.NotNil(t, span.Softprobe)
	assert.Equal(t, "adult=1&cabin=Y", span.Softprobe.RawQuery)
	assert.Equal(t, "OK", span.Softprobe.StatusReason)
	assert.Equal(t, []string{"spair.softprobe.ai"}, span.Softprobe.RequestHeaders["Host"])
	assert.JSONEq(t, `{"origin":"SFO","destination":"JFK"}`, string(span.Softprobe.RequestBody))
	assert.JSONEq(t, `{"offers":[{"id":"OFF-1"}]}`, string(span.Softprobe.ResponseBody))
	assert.NotContains(t, span.Softprobe.ResponseHeaders, "Content-Encoding")

	restoredReq, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.JSONEq(t, `{"origin":"SFO","destination":"JFK"}`, string(restoredReq))

	restoredResp, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, gzBuf.Bytes(), restoredResp)
}

func TestDecodeHTTPBodyEncodingZstdAndBrotli(t *testing.T) {
	plain := []byte(`{"orderId":"ORD-999","status":"ISSUED"}`)

	enc, err := zstd.NewWriter(nil)
	require.NoError(t, err)
	zstdBytes := enc.EncodeAll(plain, nil)
	_ = enc.Close()

	decodedZstd, ok := decodeHTTPBodyEncoding(zstdBytes, "zstd", 4096)
	require.True(t, ok)
	assert.Equal(t, plain, decodedZstd)

	var brBuf bytes.Buffer
	bw := brotli.NewWriter(&brBuf)
	_, err = bw.Write(plain)
	require.NoError(t, err)
	require.NoError(t, bw.Close())

	decodedBr, ok := decodeHTTPBodyEncoding(brBuf.Bytes(), "br", 4096)
	require.True(t, ok)
	assert.Equal(t, plain, decodedBr)
}

func TestHTTPInfoEventToSpanCapturesSoftprobeWhenPayloadExtractionOff(t *testing.T) {
	parseCtx := NewEBPFParseContext(nil, nil, nil)
	parseCtx.softprobeMaxBodyBytes = 4096
	defer parseCtx.Close()

	rawReq := []byte("POST /api/flights/search?direct=true HTTP/1.1\r\nHost: 127.0.0.1:8081\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"origin\":\"LAX\"}")
	rawResp := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"flights\":[]}\n")

	var ev BPFHTTPInfo
	ev.Type = uint8(request.EventTypeHTTP)
	ev.Status = 200
	ev.HasLargeBuffers = 1
	ev.Tp.TraceId = [16]byte{1, 2, 3, 4}
	ev.Tp.SpanId = [8]byte{5, 6, 7, 8}
	copy(ev.Buf[:], rawReq[:min(len(rawReq), len(ev.Buf))])

	reqKey := largeBufferKey{
		traceID:    ev.Tp.TraceId,
		spanID:     ev.Tp.SpanId,
		packetType: packetTypeRequest,
		direction:  directionByPacketType(packetTypeRequest, false),
		connInfo:   ev.ConnInfo,
		kind:       protocolToLargeBufferKind(ProtocolTypeHTTP),
	}
	respKey := largeBufferKey{
		traceID:    ev.Tp.TraceId,
		spanID:     ev.Tp.SpanId,
		packetType: packetTypeResponse,
		direction:  directionByPacketType(packetTypeResponse, false),
		connInfo:   ev.ConnInfo,
		kind:       protocolToLargeBufferKind(ProtocolTypeHTTP),
	}
	parseCtx.largeBuffers.Add(reqKey, largebuf.NewLargeBufferFrom(rawReq))
	parseCtx.largeBuffers.Add(respKey, largebuf.NewLargeBufferFrom(rawResp))

	span, ignore, err := HTTPInfoEventToSpan(parseCtx, &ev)
	require.NoError(t, err)
	require.False(t, ignore)
	require.NotNil(t, span.Softprobe)
	assert.Equal(t, "direct=true", span.Softprobe.RawQuery)
	assert.JSONEq(t, `{"origin":"LAX"}`, string(span.Softprobe.RequestBody))
	assert.JSONEq(t, `{"flights":[]}`, string(span.Softprobe.ResponseBody))
}
