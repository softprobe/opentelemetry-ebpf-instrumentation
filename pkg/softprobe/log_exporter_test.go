// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/plog"
)

func TestLogExporterForwardsCorrelatedOTLPLogsAndReplayID(t *testing.T) {
	var (
		mu       sync.Mutex
		received []plog.Logs
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/logs", r.URL.Path)
		assert.Equal(t, "application/x-protobuf", r.Header.Get("Content-Type"))
		body, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var unmarshaler plog.ProtoUnmarshaler
		ld, err := unmarshaler.UnmarshalLogs(body)
		if !assert.NoError(t, err) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = append(received, ld)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	reg := NewReplayRegistry(64, time.Minute)
	replayTraceID := [16]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	recordTraceID := [16]byte{0xca, 0xfe, 0xba, 0xbe, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	spanID := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	reg.RegisterInbound(InboundReplayMetadata{
		Mode:            ModeReplay,
		RecordedTraceID: "orig-trace-1",
		ReplayID:        "replay-42",
		HasTraceContext: true,
		TraceContext: TraceContext{
			Version: 0x00,
			TraceID: replayTraceID,
			SpanID:  spanID,
			Flags:   0x01,
		},
	})

	exp := NewLogExporter(Config{
		Enabled:       true,
		AppID:         "travel-ota",
		VectorLogsURL: srv.URL + "/v1/logs",
	}, reg, WithLogFlushInterval(20*time.Millisecond))
	require.NotNil(t, exp)

	assert.False(t, exp.Enqueue(LogRecordInput{
		TraceID: [16]byte{},
		SpanID:  spanID,
		Body:    "uncorrelated startup line\n",
	}))
	assert.True(t, exp.Enqueue(LogRecordInput{
		Timestamp: time.Unix(1730000500, 0),
		TraceID:   recordTraceID,
		SpanID:    spanID,
		Body:      "2026-11-13 INFO Searching NDC flights DXB->LHR\n",
	}))
	assert.True(t, exp.Enqueue(LogRecordInput{
		Timestamp: time.Unix(1730000501, 0),
		TraceID:   replayTraceID,
		SpanID:    spanID,
		Body:      "2026-11-13 WARN Replay fallback triggered\r\n",
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, exp.Close(ctx))

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, received)

	var records []plog.LogRecord
	for _, ld := range received {
		for i := 0; i < ld.ResourceLogs().Len(); i++ {
			rl := ld.ResourceLogs().At(i)
			svcName, ok := rl.Resource().Attributes().Get("service.name")
			require.True(t, ok)
			assert.Equal(t, "travel-ota", svcName.Str())
			for j := 0; j < rl.ScopeLogs().Len(); j++ {
				sl := rl.ScopeLogs().At(j)
				for k := 0; k < sl.LogRecords().Len(); k++ {
					records = append(records, sl.LogRecords().At(k))
				}
			}
		}
	}
	require.Len(t, records, 2)

	rec0 := records[0]
	assert.Equal(t, "2026-11-13 INFO Searching NDC flights DXB->LHR", rec0.Body().Str())
	assert.Equal(t, "INFO", rec0.SeverityText())
	assert.Equal(t, FormatTraceIDHex(recordTraceID), rec0.TraceID().String())
	assert.Equal(t, FormatSpanIDHex(spanID), rec0.SpanID().String())
	src0, ok := rec0.Attributes().Get("sp.source")
	require.True(t, ok)
	assert.Equal(t, "app", src0.Str())
	_, hasReplay0 := rec0.Attributes().Get("sp.replay_id")
	assert.False(t, hasReplay0)

	rec1 := records[1]
	assert.Equal(t, "2026-11-13 WARN Replay fallback triggered", rec1.Body().Str())
	assert.Equal(t, "WARN", rec1.SeverityText())
	rep1, ok := rec1.Attributes().Get("sp.replay_id")
	require.True(t, ok)
	assert.Equal(t, "replay-42", rep1.Str())
}

func TestNewLogExporterDisabledOrEmptyURLReturnsNil(t *testing.T) {
	assert.Nil(t, NewLogExporter(Config{Enabled: false, VectorLogsURL: "http://vector:4318/v1/logs"}, nil))
	assert.Nil(t, NewLogExporter(Config{Enabled: true, VectorLogsURL: ""}, nil))
}
