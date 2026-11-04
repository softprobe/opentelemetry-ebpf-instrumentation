// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestIngressGatewayRecordsServletAndPropagatesTraceparent(t *testing.T) {
	type tracePayload struct {
		body []byte
		err  error
	}
	tracePayloads := make(chan tracePayload, 1)
	traceReceiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		tracePayloads <- tracePayload{body: body, err: err}
		w.WriteHeader(http.StatusOK)
	}))
	defer traceReceiver.Close()

	type upstreamRequest struct {
		traceparent string
		method      string
		path        string
		body        string
	}
	upstreamRequests := make(chan upstreamRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		upstreamRequests <- upstreamRequest{
			traceparent: r.Header.Get("traceparent"),
			method:      r.Method,
			path:        r.URL.Path,
			body:        string(body),
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-OTA", "recorded")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	traceURL, err := url.Parse(traceReceiver.URL)
	require.NoError(t, err)
	ingress, err := NewIngressGateway(IngressGatewayConfig{
		AppID:    "travel-ota",
		Upstream: upstreamURL,
		TraceAPI: traceURL,
	})
	require.NoError(t, err)
	server := httptest.NewServer(ingress)
	defer server.Close()

	requestBody := `{"fromCity":"JFK","toCity":"LAX"}`
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/flights/search?locale=en", strings.NewReader(requestBody))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Referer", "https://example.test/ignored")
	request.Header.Set("traceparent", "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, response.StatusCode)
	require.Equal(t, `{"accepted":true}`, string(responseBody))
	require.Equal(t, "recorded", response.Header.Get("X-OTA"))

	forwarded := <-upstreamRequests
	require.Equal(t, http.MethodPost, forwarded.method)
	require.Equal(t, "/api/flights/search", forwarded.path)
	require.Equal(t, requestBody, forwarded.body)
	forwardedContext, err := parseTraceparent(forwarded.traceparent)
	require.NoError(t, err)
	require.Equal(t, "0102030405060708090a0b0c0d0e0f10", hexString(forwardedContext.traceID))
	require.NotEqual(t, "1112131415161718", hexString(forwardedContext.parentSpanID))

	encoded := <-tracePayloads
	require.NoError(t, encoded.err)
	traces, err := (&ptrace.ProtoUnmarshaler{}).UnmarshalTraces(encoded.body)
	require.NoError(t, err)
	span := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	require.Equal(t, "0102030405060708090a0b0c0d0e0f10", span.TraceID().String())
	require.Equal(t, "1112131415161718", span.ParentSpanID().String())
	require.Equal(t, ptrace.SpanKindServer, span.Kind())
	attrs := span.Attributes()
	_, hasSegmentID := attrs.Get("sp_segment_id")
	require.Equal(t, CategoryServlet, stringAttribute(t, attrs, "sp_category_type"))
	require.Equal(t, "travel-ota", stringAttribute(t, attrs, "sp_app_id"))
	require.Equal(t, "/api/flights/search", stringAttribute(t, attrs, "sp_operation_name"))
	require.False(t, hasSegmentID)

	var requestTarget Target
	require.NoError(t, json.Unmarshal([]byte(stringAttribute(t, attrs, "sp_target_request_json")), &requestTarget))
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte(requestBody)), requestTarget.Body)
	require.Equal(t, "POST", requestTarget.Attributes["HttpMethod"])
	require.Equal(t, "/api/flights/search", requestTarget.Attributes["RequestPath"])
	requestHeaders := requestTarget.Attributes["Headers"].(map[string]any)
	require.Equal(t, "application/json", requestHeaders["Content-Type"])
	require.NotContains(t, requestHeaders, "Referer")

	var responseTarget Target
	require.NoError(t, json.Unmarshal([]byte(stringAttribute(t, attrs, "sp_target_response_json")), &responseTarget))
	require.Equal(t, `{"accepted":true}`, responseTarget.Body)
	require.Equal(t, "java.lang.String", responseTarget.Type)
	require.Equal(t, "application/json", responseTarget.Attributes["Headers"].(map[string]any)["Content-Type"])
}

func TestIngressGatewayCreatesTraceContextWhenMissing(t *testing.T) {
	var traceparent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceparent = r.Header.Get("traceparent")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	traceReceiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer traceReceiver.Close()
	traceURL, err := url.Parse(traceReceiver.URL)
	require.NoError(t, err)
	ingress, err := NewIngressGateway(IngressGatewayConfig{
		AppID: "travel-ota", Upstream: upstreamURL, TraceAPI: traceURL,
	})
	require.NoError(t, err)
	server := httptest.NewServer(ingress)
	defer server.Close()

	response, err := http.Get(server.URL + "/api/flights/search")
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	generated, err := parseTraceparent(traceparent)
	require.NoError(t, err)
	require.Len(t, generated.traceID, 16)
	require.Len(t, generated.parentSpanID, 8)
	require.Equal(t, uint32(1), generated.flags)
}

func TestIngressGatewaySavesServletReplayResult(t *testing.T) {
	const recordedTraceID = "0102030405060708090a0b0c0d0e0f10"
	const replayID = "ffeeddccbbaa99887766554433221100"
	type replayResult struct {
		mocker Mocker
		body   map[string]any
		err    error
	}
	replayResults := make(chan replayResult, 1)
	recordReceiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		var mocker Mocker
		if err == nil {
			err = json.Unmarshal(body, &mocker)
		}
		var payload map[string]any
		if err == nil {
			err = json.Unmarshal(body, &payload)
		}
		replayResults <- replayResult{mocker: mocker, body: payload, err: err}
		w.WriteHeader(http.StatusOK)
	}))
	defer recordReceiver.Close()
	var forwardedTraceparent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedTraceparent = r.Header.Get("traceparent")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"replayed":true}`))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	recordURL, err := url.Parse(recordReceiver.URL)
	require.NoError(t, err)
	traceURL, err := url.Parse("http://127.0.0.1:1/v1/traces")
	require.NoError(t, err)
	ingress, err := NewIngressGateway(IngressGatewayConfig{
		AppID: "travel-ota", Upstream: upstreamURL, TraceAPI: traceURL, RecordAPI: recordURL,
	})
	require.NoError(t, err)
	server := httptest.NewServer(ingress)
	defer server.Close()

	requestBody := `{"fromCity":"JFK","toCity":"LAX"}`
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/flights/search", strings.NewReader(requestBody))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1112131415161718-01")
	request.Header.Set("tracestate", "sp=mode:replay;tid:"+recordedTraceID+";rid:"+replayID)
	request.Header.Set("sp-schedule-replay", "true")
	request.Header.Set("sp-segment-id", "1111111111111111")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	responseBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, `{"replayed":true}`, string(responseBody))

	forwardedContext, err := parseTraceparent(forwardedTraceparent)
	require.NoError(t, err)
	require.Equal(t, recordedTraceID, hexString(forwardedContext.traceID))

	result := <-replayResults
	require.NoError(t, result.err)
	require.Equal(t, CategoryServlet, result.mocker.CategoryType.Name)
	categoryType, ok := result.body["categoryType"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, true, categoryType["entryPoint"])
	require.Equal(t, recordedTraceID, result.mocker.TraceID)
	require.Equal(t, replayID, result.mocker.ReplayID)
	require.Equal(t, "1111111111111111", result.mocker.SegmentID)
	require.Equal(t, `{"replayed":true}`, result.mocker.TargetResponse.Body)
	replayResponseHeaders := result.mocker.TargetResponse.Attributes["Headers"].(map[string]any)
	require.Equal(t, "application/json", replayResponseHeaders["Content-Type"])
}

func TestIngressGatewayRestoresRecordedTraceIDFromReplayTracestate(t *testing.T) {
	const recordedTraceID = "0102030405060708090a0b0c0d0e0f10"
	const replayTraceID = "a1a2a3a4a5a6a7a8a9aaabacadaeaf00"
	var traceparent string
	traceReceived := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceparent = r.Header.Get("traceparent")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	traceReceiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		traceReceived <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer traceReceiver.Close()
	traceURL, err := url.Parse(traceReceiver.URL)
	require.NoError(t, err)
	ingress, err := NewIngressGateway(IngressGatewayConfig{
		AppID: "travel-ota", Upstream: upstreamURL, TraceAPI: traceURL,
	})
	require.NoError(t, err)
	server := httptest.NewServer(ingress)
	defer server.Close()

	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/flights/search", strings.NewReader(`{"fromCity":"JFK"}`))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("traceparent", "00-"+replayTraceID+"-1112131415161718-03")
	request.Header.Set("tracestate", "sp=mode:replay;tid:"+recordedTraceID+";rid:69a9ff11c88bcf6b")
	request.Header.Set("sp-schedule-replay", "NORMAL")
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)

	forwarded, err := parseTraceparent(traceparent)
	require.NoError(t, err)
	require.Equal(t, recordedTraceID, hexString(forwarded.traceID))
	require.NotEqual(t, "1112131415161718", hexString(forwarded.parentSpanID))

	select {
	case <-time.After(50 * time.Millisecond):
		// Replay requests should not be ingested again as fresh recordings.
	case <-traceReceived:
		t.Fatal("replay request was exported as a new Servlet recording")
	}
}

func TestNewIngressGatewayValidatesRequiredSettings(t *testing.T) {
	t.Run("app id", func(t *testing.T) {
		_, err := NewIngressGateway(IngressGatewayConfig{})
		require.ErrorContains(t, err, "application ID")
	})

	t.Run("upstream", func(t *testing.T) {
		traceURL, err := url.Parse("http://backend.test/v1/traces")
		require.NoError(t, err)
		_, err = NewIngressGateway(IngressGatewayConfig{AppID: "travel-ota", TraceAPI: traceURL})
		require.ErrorContains(t, err, "upstream URL")
	})
}

func stringAttribute(t *testing.T, attrs pcommon.Map, key string) string {
	t.Helper()
	value, ok := attrs.Get(key)
	require.True(t, ok, "missing attribute %q", key)
	return value.Str()
}

func hexString(value []byte) string {
	return hex.EncodeToString(value)
}
