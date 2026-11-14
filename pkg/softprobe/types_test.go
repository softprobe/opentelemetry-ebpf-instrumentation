// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockCategoryTypeWireContract(t *testing.T) {
	tests := []struct {
		name     string
		cat      MockCategoryType
		wantJSON string
	}{
		{
			name:     "servlet entry point",
			cat:      CategoryServlet,
			wantJSON: `{"name":"Servlet","entryPoint":true,"skipComparison":false}`,
		},
		{
			name:     "http client dependency",
			cat:      CategoryHTTPClient,
			wantJSON: `{"name":"HttpClient","entryPoint":false,"skipComparison":false}`,
		},
		{
			name:     "database dependency",
			cat:      CategoryDatabase,
			wantJSON: `{"name":"Database","entryPoint":false,"skipComparison":false}`,
		},
		{
			name:     "redis dependency",
			cat:      CategoryRedis,
			wantJSON: `{"name":"Redis","entryPoint":false,"skipComparison":false}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.cat)
			require.NoError(t, err)
			assert.JSONEq(t, tc.wantJSON, string(raw))

			resolved, ok := CategoryByName(tc.cat.Name)
			require.True(t, ok)
			assert.Equal(t, tc.cat, resolved)
		})
	}

	_, ok := CategoryByName("UnknownCategory")
	assert.False(t, ok)
}

func TestSpMockerOmitsNilSeqAndSerializesSetSeq(t *testing.T) {
	unnumbered := SpMocker{
		CategoryType: CategoryDatabase,
		TraceID:      "4bf92f3577b34da6a3ce929d0e0e4736",
	}
	rawUnnumbered, err := json.Marshal(unnumbered)
	require.NoError(t, err)
	assert.NotContains(t, string(rawUnnumbered), `"seq"`)

	seqZero := 0
	numbered := SpMocker{
		CategoryType: CategoryDatabase,
		TraceID:      "4bf92f3577b34da6a3ce929d0e0e4736",
		Seq:          &seqZero,
	}
	rawNumbered, err := json.Marshal(numbered)
	require.NoError(t, err)
	assert.Contains(t, string(rawNumbered), `"seq":0`)
}

func TestHTTPResponseWrapperJavaAndGoWireCompatibility(t *testing.T) {
	t.Run("decodes sp-agent-java tuple payload", func(t *testing.T) {
		payload := `{"offerId":"ndc-99"}`
		b64 := base64.StdEncoding.EncodeToString([]byte(payload))
		javaWire := `{"statusLine":"HTTP/1.1 201 Created","statusCode":201,"reason":"Created","headers":[{"f":"Content-Type","s":"application/json"},{"f":"X-Provider","s":"spair"}],"content":"` + b64 + `"}`

		var wrapper HTTPResponseWrapper
		require.NoError(t, json.Unmarshal([]byte(javaWire), &wrapper))
		assert.Equal(t, http.StatusCreated, wrapper.Status)
		assert.Equal(t, http.StatusCreated, wrapper.StatusCode)
		assert.Equal(t, "Created", wrapper.Reason)
		assert.Equal(t, "application/json", wrapper.Headers["Content-Type"])
		assert.Equal(t, "spair", wrapper.Headers["X-Provider"])
		assert.Equal(t, payload, wrapper.Body)
		assert.Equal(t, b64, wrapper.BodyBase64)

		decodedBytes, err := wrapper.PayloadBytes()
		require.NoError(t, err)
		assert.Equal(t, []byte(payload), decodedBytes)
	})

	t.Run("marshals both SpanDisplayAdapter and Go fields", func(t *testing.T) {
		wrapper := HTTPResponseWrapper{
			Status: http.StatusOK,
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Body: `{"ok":true}`,
		}
		raw, err := json.Marshal(wrapper)
		require.NoError(t, err)

		var inspect map[string]any
		require.NoError(t, json.Unmarshal(raw, &inspect))
		assert.InDelta(t, 200, inspect["status"], 0)
		assert.InDelta(t, 200, inspect["statusCode"], 0)
		assert.Equal(t, "HTTP/1.1 200 OK", inspect["statusLine"])
		bodyField, ok := inspect["body"].(string)
		require.True(t, ok)
		assert.JSONEq(t, `{"ok":true}`, bodyField)
		assert.NotEmpty(t, inspect["bodyBase64"])
		assert.Equal(t, inspect["bodyBase64"], inspect["content"])
	})

	t.Run("decodes map-shaped headers", func(t *testing.T) {
		mapWire := `{"status":202,"headers":{"X-Trace":["a","b"],"Content-Type":"text/plain"},"body":"accepted"}`
		var wrapper HTTPResponseWrapper
		require.NoError(t, json.Unmarshal([]byte(mapWire), &wrapper))
		assert.Equal(t, http.StatusAccepted, wrapper.Status)
		assert.Equal(t, "a, b", wrapper.Headers["X-Trace"])
		assert.Equal(t, "text/plain", wrapper.Headers["Content-Type"])
		assert.Equal(t, "accepted", wrapper.Body)
	})
}

func TestTraceparentParseAndFormat(t *testing.T) {
	valid := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tc, err := ParseTraceparent(valid)
	require.NoError(t, err)
	assert.Equal(t, byte(0x00), tc.Version)
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", tc.TraceIDHex())
	assert.Equal(t, "00f067aa0ba902b7", tc.SpanIDHex())
	assert.Equal(t, byte(0x01), tc.Flags)
	assert.Equal(t, valid, FormatTraceparent(tc))

	invalidInputs := []string{
		"",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
	}
	for _, bad := range invalidInputs {
		_, parseErr := ParseTraceparent(bad)
		require.Error(t, parseErr, "input %q should fail", bad)
	}
}

func TestTracestateParseAndFormatPreservesVendors(t *testing.T) {
	raw := "congo=t61rcWkgMzE, sp=mode:replay;tid:rec-trace-001;rid:rep-run-999, rojo=00f067aa0ba902b7"
	sp, ok := ParseTracestate(raw)
	require.True(t, ok)
	assert.Equal(t, ModeReplay, sp.Mode)
	assert.Equal(t, "rec-trace-001", sp.RecordedTraceID)
	assert.Equal(t, "rep-run-999", sp.ReplayID)

	updated := FormatTracestate(raw, SpTracestate{
		Mode:            ModeFullReplay,
		RecordedTraceID: "rec-trace-002",
		ReplayID:        "rep-run-1000",
	})
	assert.Equal(
		t,
		"sp=mode:full-replay;tid:rec-trace-002;rid:rep-run-1000,congo=t61rcWkgMzE,rojo=00f067aa0ba902b7",
		updated,
	)

	_, missing := ParseTracestate("congo=t61rcWkgMzE,rojo=00f067aa0ba902b7")
	assert.False(t, missing)
}

func TestExtractInboundReplayHeaders(t *testing.T) {
	h := make(http.Header)
	h.Set(HeaderTraceparent, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	h.Set(HeaderTracestate, "sp=mode:replay;tid:recorded-abc;rid:replay-xyz")
	h.Set(HeaderScheduleReplay, "true")
	h.Set(HeaderSegmentID, "seg-42")
	h.Set(HeaderIgnoreDependencies, "true")
	h.Set(HeaderExclusionOperations, `{"http":["POST /audit"],"redis":[]}`)
	h.Set(HeaderInclusionOperations, `["GET /offers","POST /book"]`)

	meta, ok := ExtractInboundReplay(h)
	require.True(t, ok)
	assert.True(t, meta.HasTraceContext)
	assert.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", meta.TraceContext.TraceIDHex())
	assert.Equal(t, ModeReplay, meta.Mode)
	assert.Equal(t, "true", meta.ScheduleReplay)
	assert.Equal(t, "recorded-abc", meta.RecordedTraceID)
	assert.Equal(t, "replay-xyz", meta.ReplayID)
	assert.Equal(t, "seg-42", meta.SegmentID)
	assert.True(t, meta.IgnoreDependencies)
	assert.Equal(t, []string{"POST /audit"}, meta.ExclusionOperations["http"])
	assert.Empty(t, meta.ExclusionOperations["redis"])
	assert.Equal(t, []string{"GET /offers", "POST /book"}, meta.InclusionOperations["*"])

	normalHeaders := make(http.Header)
	normalHeaders.Set(HeaderTraceparent, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	_, isReplay := ExtractInboundReplay(normalHeaders)
	assert.False(t, isReplay)
}

func TestConfigValidation(t *testing.T) {
	cfg := DefaultConfig()
	require.NoError(t, cfg.Validate())
	assert.True(t, cfg.IsDefault())

	cfg.Enabled = true
	cfg.AppID = "travel-ota"
	cfg.BackendURL = "http://sp-backend:8090"
	cfg.IngressProxyPort = 15006
	cfg.EgressProxyPort = 15001
	require.NoError(t, cfg.Validate())
	assert.False(t, cfg.IsDefault())

	samePorts := cfg
	samePorts.EgressProxyPort = 15006
	require.Error(t, samePorts.Validate())

	badScheme := cfg
	badScheme.BackendURL = "grpc://sp-backend:4317"
	require.Error(t, badScheme.Validate())
}
