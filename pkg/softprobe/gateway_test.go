// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestGatewayReplayQueriesByTraceIDAndReturnsLegacyHTTPResponse(t *testing.T) {
	type backendObservation struct {
		path  string
		query Mocker
		err   error
	}
	observations := make(chan backendObservation, 1)
	targetResponse := Target{
		Type: HTTPResponseWrapperType,
		Body: `{"statusLine":"HTTP/1.1 202 Accepted","content":"eyJvayI6dHJ1ZX0=","headers":[{"f":"Content-Type","s":"application/json"}],"reason":"Accepted","statusCode":202}`,
	}
	body, err := json.Marshal(Mocker{TargetResponse: targetResponse})
	require.NoError(t, err)
	compressed := compressZstd(t, body)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observation := backendObservation{path: r.URL.Path}
		observation.err = json.NewDecoder(r.Body).Decode(&observation.query)
		observations <- observation
		w.Header().Set("Content-Type", "application/octet-stream")
		if _, err := w.Write(compressed); err != nil {
			return
		}
	}))
	defer backend.Close()

	apiURL, err := url.Parse(backend.URL + "/api/storage/record/query")
	require.NoError(t, err)
	gateway, err := NewGateway(GatewayConfig{
		Mode:      ReplayMode,
		AppID:     "travel-ota",
		RecordAPI: apiURL,
	})
	require.NoError(t, err)
	server := httptest.NewServer(gateway)
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/ndc/v21.3/airshopping?locale=en", bytes.NewBufferString(`{"search":1}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("traceparent", "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01")
	response, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	observation := <-observations
	require.NoError(t, observation.err)
	query := observation.query
	require.Equal(t, http.StatusAccepted, response.StatusCode)
	require.Equal(t, "application/json", response.Header.Get("Content-Type"))
	require.JSONEq(t, `{"ok":true}`, string(responseBody))
	require.Equal(t, "/api/storage/record/query", observation.path)
	require.Equal(t, "0102030405060708090a0b0c0d0e0f10", query.TraceID)
	require.Equal(t, "travel-ota", query.AppID)
	require.Equal(t, "/ndc/v21.3/airshopping", query.OperationName)
	require.Equal(t, "POST", query.TargetRequest.Attributes["HttpMethod"])
	require.Equal(t, "locale=en", query.TargetRequest.Attributes["QueryString"])
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte(`{"search":1}`)), query.TargetRequest.Body)
}

func TestGatewayReplayRequiresValidTraceparent(t *testing.T) {
	backendCalls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { backendCalls++ }))
	defer backend.Close()
	apiURL, err := url.Parse(backend.URL)
	require.NoError(t, err)
	gateway, err := NewGateway(GatewayConfig{Mode: ReplayMode, AppID: "travel-ota", RecordAPI: apiURL})
	require.NoError(t, err)
	server := httptest.NewServer(gateway)
	defer server.Close()

	response, err := http.Get(server.URL + "/airshopping")
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, http.StatusBadRequest, response.StatusCode)
	require.Zero(t, backendCalls)
}

func TestGatewayReplayUsesOBIRequestContextWhenTraceparentIsMissing(t *testing.T) {
	const traceID = "0102030405060708090a0b0c0d0e0f10"
	var received Mocker
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&received))
		_, _ = w.Write(zstdJSON(t, Mocker{TargetResponse: Target{
			Type: HTTPResponseWrapperType,
			Body: `{"statusLine":"HTTP/1.1 200 OK","content":"","headers":[],"reason":"OK","statusCode":200}`,
		}}))
	}))
	defer backend.Close()
	apiURL, err := url.Parse(backend.URL + "/api/storage/record/query")
	require.NoError(t, err)
	contextReader := &fixedRequestContextReader{context: RequestTraceContext{TraceID: traceID}}
	gateway, err := NewGateway(GatewayConfig{
		Mode: ReplayMode, AppID: "travel-ota", RecordAPI: apiURL, RequestContextMap: contextReader,
	})
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, "http://gateway/ndc/v21.3/orderretrieve", bytes.NewBufferString(`{"order":1}`))
	request.RemoteAddr = "192.0.2.15:43127"
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, traceID, received.TraceID)
	require.Equal(t, "/ndc/v21.3/orderretrieve", received.OperationName)
	require.Equal(t, 1, contextReader.calls)
	require.Equal(t, "192.0.2.15:43127", contextReader.address.String())
}

func TestGatewayReplayPrefersTraceparentAndConsumesOBIContext(t *testing.T) {
	const headerTraceID = "0102030405060708090a0b0c0d0e0f10"
	var received Mocker
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&received))
		_, _ = w.Write(zstdJSON(t, Mocker{TargetResponse: Target{
			Type: HTTPResponseWrapperType,
			Body: `{"statusLine":"HTTP/1.1 200 OK","content":"","headers":[],"reason":"OK","statusCode":200}`,
		}}))
	}))
	defer backend.Close()
	apiURL, err := url.Parse(backend.URL)
	require.NoError(t, err)
	contextReader := &fixedRequestContextReader{context: RequestTraceContext{TraceID: "ffeeddccbbaa99887766554433221100"}}
	gateway, err := NewGateway(GatewayConfig{
		Mode: ReplayMode, AppID: "travel-ota", RecordAPI: apiURL, RequestContextMap: contextReader,
	})
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, "http://gateway/airshopping", nil)
	request.RemoteAddr = "192.0.2.15:43127"
	request.Header.Set("traceparent", "00-"+headerTraceID+"-1112131415161718-01")
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, headerTraceID, received.TraceID)
	require.Equal(t, 1, contextReader.calls)
}

func TestGatewayRecordForwardsToUpstream(t *testing.T) {
	type upstreamObservation struct {
		path string
		host string
	}
	observations := make(chan upstreamObservation, 1)
	upstreamHost := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observations <- upstreamObservation{path: r.URL.Path, host: r.Host}
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write([]byte("recording")); err != nil {
			return
		}
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	upstreamHost = upstreamURL.Host
	gateway, err := NewGateway(GatewayConfig{Mode: RecordMode, Upstream: upstreamURL})
	require.NoError(t, err)
	server := httptest.NewServer(gateway)
	defer server.Close()

	response, err := http.Post(server.URL+"/ndc/v21.3/airshopping", "application/json", bytes.NewBufferString("{}"))
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	observation := <-observations
	require.Equal(t, http.StatusCreated, response.StatusCode)
	require.Equal(t, "recording", string(body))
	require.Equal(t, "/ndc/v21.3/airshopping", observation.path)
	require.Equal(t, upstreamHost, observation.host)
}

func TestGatewayRecordExportsLegacyCompatibleOTLPSpan(t *testing.T) {
	type upstreamObservation struct {
		body []byte
		err  error
	}
	upstreamObservations := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		upstreamObservations <- upstreamObservation{body: body, err: err}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if _, err := w.Write([]byte(`{"offer":"saved"}`)); err != nil {
			return
		}
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	type traceObservation struct {
		contentType string
		payload     []byte
		err         error
	}
	traceObservations := make(chan traceObservation, 1)
	traceReceiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, err := io.ReadAll(r.Body)
		traceObservations <- traceObservation{contentType: r.Header.Get("Content-Type"), payload: payload, err: err}
		w.WriteHeader(http.StatusOK)
	}))
	defer traceReceiver.Close()
	traceURL, err := url.Parse(traceReceiver.URL)
	require.NoError(t, err)

	gateway, err := NewGateway(GatewayConfig{
		Mode:     RecordMode,
		AppID:    "travel-ota",
		Upstream: upstreamURL,
		TraceAPI: traceURL,
		RequestContextMap: &fixedRequestContextReader{context: RequestTraceContext{
			TraceID:      "0102030405060708090a0b0c0d0e0f10",
			ParentSpanID: "1112131415161718",
			Flags:        1,
		}},
	})
	require.NoError(t, err)
	server := httptest.NewServer(gateway)
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/ndc/v21.3/airshopping?locale=en", bytes.NewBufferString(`{"search":1}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	gotUpstream := <-upstreamObservations
	require.NoError(t, gotUpstream.err)
	require.Equal(t, `{"search":1}`, string(gotUpstream.body))
	gotTrace := <-traceObservations
	require.NoError(t, gotTrace.err)
	require.Equal(t, "application/x-protobuf", gotTrace.contentType)
	captured, err := (&ptrace.ProtoUnmarshaler{}).UnmarshalTraces(gotTrace.payload)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, response.StatusCode)
	require.JSONEq(t, `{"offer":"saved"}`, string(responseBody))

	require.Eventually(t, func() bool { return captured.ResourceSpans().Len() == 1 }, time.Second, 10*time.Millisecond)
	resourceSpans := captured.ResourceSpans().At(0)
	serviceName, ok := resourceSpans.Resource().Attributes().Get("service.name")
	require.True(t, ok)
	require.Equal(t, "travel-ota", serviceName.Str())
	span := resourceSpans.ScopeSpans().At(0).Spans().At(0)
	require.Equal(t, "0102030405060708090a0b0c0d0e0f10", span.TraceID().String())
	require.Equal(t, "1112131415161718", span.ParentSpanID().String())
	attrs := span.Attributes()
	category, ok := attrs.Get("sp_category_type")
	require.True(t, ok)
	require.Equal(t, CategoryHTTPClient, category.Str())
	appID, ok := attrs.Get("sp_app_id")
	require.True(t, ok)
	require.Equal(t, "travel-ota", appID.Str())
	requestTargetJSON, ok := attrs.Get("sp_target_request_json")
	require.True(t, ok)
	var target Target
	require.NoError(t, json.Unmarshal([]byte(requestTargetJSON.Str()), &target))
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte(`{"search":1}`)), target.Body)
	require.Equal(t, "POST", target.Attributes["HttpMethod"])
	require.Equal(t, "locale=en", target.Attributes["QueryString"])
	responseTargetJSON, ok := attrs.Get("sp_target_response_json")
	require.True(t, ok)
	require.NotEmpty(t, responseTargetJSON.Str())
}

func compressZstd(t *testing.T, value []byte) []byte {
	t.Helper()
	writer, err := zstd.NewWriter(nil)
	require.NoError(t, err)
	defer writer.Close()
	return writer.EncodeAll(value, nil)
}
