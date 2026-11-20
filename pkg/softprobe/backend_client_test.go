// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func zstdCompressForTest(t *testing.T, v any) []byte {
	t.Helper()
	rawJSON, err := json.Marshal(v)
	require.NoError(t, err)
	enc, err := zstd.NewWriter(nil)
	require.NoError(t, err)
	defer func() { _ = enc.Close() }()
	return enc.EncodeAll(rawJSON, nil)
}

func TestJavaSentinelZstdBytesMatchBackendPayloads(t *testing.T) {
	dec, err := zstd.NewReader(nil)
	require.NoError(t, err)
	defer dec.Close()

	emptyJSON, err := dec.DecodeAll(EmptyInstanceZstdBytes, nil)
	require.NoError(t, err)
	assert.JSONEq(t, "{}", string(emptyJSON))

	skipJSON, err := dec.DecodeAll(ReplaySkipMockZstdBytes, nil)
	require.NoError(t, err)
	var skipMocker SpMocker
	require.NoError(t, json.Unmarshal(skipJSON, &skipMocker))
	assert.True(t, skipMocker.TargetResponse.AttributeBool(AttrSkipMock))

	mustMockJSON, err := dec.DecodeAll(ReplayMustMockZstdBytes, nil)
	require.NoError(t, err)
	var mustMocker SpMocker
	require.NoError(t, json.Unmarshal(mustMockJSON, &mustMocker))
	require.NotNil(t, mustMocker.TargetResponse)
}

func TestBackendClientQueryRecordOutcomes(t *testing.T) {
	reqMocker, err := BuildHTTPClientMocker(sampleSpanMeta(), HTTPClientExchange{
		Method:        http.MethodPost,
		OperationName: "/ndc/v2/airShopping",
		RequestBody:   []byte(`{"origin":"LAX"}`),
	})
	require.NoError(t, err)
	reqMocker.ReplayID = "replay-run-77"

	t.Run("zstd hit returns decoded mocker and sends strategy code header", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, EndpointRecordQuery, r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "1", r.Header.Get(HeaderMockStrategyCode))

			body, readErr := io.ReadAll(r.Body)
			assert.NoError(t, readErr)
			var incoming SpMocker
			assert.NoError(t, json.Unmarshal(body, &incoming))
			assert.Equal(t, "HttpClient", incoming.CategoryType.Name)

			recorded, buildErr := BuildHTTPClientMocker(sampleSpanMeta(), HTTPClientExchange{
				Method:        http.MethodPost,
				OperationName: "/ndc/v2/airShopping",
				Response: &HTTPResponseWrapper{
					Status:  http.StatusOK,
					Headers: map[string]string{"Content-Type": "application/json"},
					Body:    `{"flight":"SP888"}`,
				},
			})
			assert.NoError(t, buildErr)
			recorded.ID = "mock-id-888"

			w.Header().Set("Content-Type", "application/zstd")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(zstdCompressForTest(t, recorded))
		}))
		defer srv.Close()

		client, err := NewBackendClient(srv.URL)
		require.NoError(t, err)
		defer client.Close()

		res, err := client.QueryRecord(t.Context(), reqMocker, MockStrategyHTTPClient)
		require.NoError(t, err)
		assert.True(t, res.IsHit())
		assert.Equal(t, "hit", res.Outcome.String())
		require.NotNil(t, res.Mocker)
		assert.Equal(t, "mock-id-888", res.Mocker.ID)

		wrapper, err := DecodeHTTPClientResponse(res.Mocker)
		require.NoError(t, err)
		assert.JSONEq(t, `{"flight":"SP888"}`, wrapper.Body)
	})

	t.Run("EMPTY_INSTANCE sentinel returns EmptyMiss", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "0", r.Header.Get(HeaderMockStrategyCode))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(EmptyInstanceZstdBytes)
		}))
		defer srv.Close()

		client, err := NewBackendClient(srv.URL)
		require.NoError(t, err)
		defer client.Close()

		res, err := client.QueryRecord(t.Context(), reqMocker, MockStrategyDatabase)
		require.NoError(t, err)
		assert.True(t, res.IsEmptyMiss())
		assert.Nil(t, res.Mocker)
	})

	t.Run("empty-valued mustMock header returns MustMock", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(HeaderMustMock, "")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(ReplayMustMockZstdBytes)
		}))
		defer srv.Close()

		client, err := NewBackendClient(srv.URL)
		require.NoError(t, err)
		defer client.Close()

		res, err := client.QueryRecord(t.Context(), reqMocker, MockStrategyRedis)
		require.NoError(t, err)
		assert.True(t, res.IsMustMock())
		assert.Equal(t, "must_mock", res.Outcome.String())
	})

	t.Run("REPLAY_SKIP_MOCK sentinel and dynamic realCallMarker return SkipMock", func(t *testing.T) {
		callCount := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			callCount++
			w.WriteHeader(http.StatusOK)
			if callCount == 1 {
				_, _ = w.Write(ReplaySkipMockZstdBytes)
				return
			}
			marker := map[string]any{
				"targetResponse": map[string]any{
					"attributes": map[string]any{
						AttrSkipMock:   true,
						AttrRealCallID: "real-call-uuid-42",
					},
				},
			}
			_, _ = w.Write(zstdCompressForTest(t, marker))
		}))
		defer srv.Close()

		client, err := NewBackendClient(srv.URL)
		require.NoError(t, err)
		defer client.Close()

		first, err := client.QueryRecord(t.Context(), reqMocker, MockStrategyHTTPClient)
		require.NoError(t, err)
		assert.True(t, first.IsSkipMock())
		assert.Empty(t, first.RealCallID)

		second, err := client.QueryRecord(t.Context(), reqMocker, MockStrategyHTTPClient)
		require.NoError(t, err)
		assert.True(t, second.IsSkipMock())
		assert.Equal(t, "real-call-uuid-42", second.RealCallID)
	})
}

func TestBackendClientServletSaveRealCallAndAgentStatus(t *testing.T) {
	var savedServlet SpMocker
	var reportedRealCall SpMocker
	statusCalls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case EndpointRecordQuery:
			assert.Equal(t, "0", r.Header.Get(HeaderMockStrategyCode))
			raw, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			assert.NoError(t, json.Unmarshal(raw, &savedServlet))
			savedServlet.ID = "servlet-replay-001"
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(zstdCompressForTest(t, savedServlet))
		case EndpointReplayRealCallResult:
			raw, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			assert.NoError(t, json.Unmarshal(raw, &reportedRealCall))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"body":true}`))
		case EndpointAgentStatus:
			statusCalls++
			if statusCalls == 1 {
				w.Header().Set("Last-Modified", "Wed, 13 Nov 2026 00:00:00 GMT")
				w.WriteHeader(http.StatusOK)
				return
			}
			assert.Equal(t, "Wed, 13 Nov 2026 00:00:00 GMT", r.Header.Get("If-Modified-Since"))
			w.WriteHeader(http.StatusNotModified)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := NewBackendClient(srv.URL + "/")
	require.NoError(t, err)
	defer client.Close()

	meta := sampleSpanMeta()
	meta.ReplayID = "replay-900"
	servlet := BuildServletMocker(meta, ServletExchange{
		Method:       http.MethodGet,
		RequestPath:  "/api/v1/flights",
		StatusCode:   http.StatusOK,
		ResponseBody: `{"flights":[]}`,
	})

	echoed, err := client.SaveReplayServletResult(t.Context(), servlet)
	require.NoError(t, err)
	assert.Equal(t, "servlet-replay-001", echoed.ID)
	assert.True(t, savedServlet.CategoryType.EntryPoint)
	assert.Equal(t, "Servlet", savedServlet.CategoryType.Name)

	realCallMocker, err := BuildHTTPClientMocker(meta, HTTPClientExchange{
		Method:        http.MethodGet,
		OperationName: "/live/pricing",
		Response:      &HTTPResponseWrapper{Status: http.StatusOK, Body: `{"price":199}`},
	})
	require.NoError(t, err)
	realCallMocker.ID = "real-call-uuid-42"
	require.NoError(t, client.ReportRealCallResult(t.Context(), realCallMocker))
	assert.Equal(t, "real-call-uuid-42", reportedRealCall.ID)
	assert.Equal(t, "replay-900", reportedRealCall.ReplayID)

	missingID := *realCallMocker
	missingID.ID = ""
	require.Error(t, client.ReportRealCallResult(t.Context(), &missingID))

	firstStatus, err := client.SendAgentStatus(t.Context(), AgentStatusPayload{
		AppID:       "travel-ota",
		Host:        "10.0.0.12",
		AgentStatus: "WORKING",
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, firstStatus.StatusCode)
	assert.False(t, firstStatus.NotModified)
	assert.Equal(t, "Wed, 13 Nov 2026 00:00:00 GMT", firstStatus.LastModified)

	secondStatus, err := client.SendAgentStatusConditional(t.Context(), AgentStatusPayload{
		AppID:       "travel-ota",
		Host:        "10.0.0.12",
		AgentStatus: "WORKING",
	}, firstStatus.LastModified)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotModified, secondStatus.StatusCode)
	assert.True(t, secondStatus.NotModified)
}
