// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

const (
	defaultLogQueueSize     = 4096
	defaultLogMaxBatch      = 128
	defaultLogFlushInterval = 250 * time.Millisecond
	defaultLogHTTPTimeout   = 5 * time.Second
	logScopeName            = "softprobe.obi.logs"

	LogSourceApp   = "app"
	LogSourceAgent = "agent"
)

type LogRecordInput struct {
	Timestamp    time.Time
	TraceID      [16]byte
	SpanID       [8]byte
	Body         string
	SeverityText string
	Source       string
	ReplayID     string
	FD           int
}

type LogExporter struct {
	cfg            Config
	replayRegistry *ReplayRegistry
	client         *http.Client
	ch             chan LogRecordInput
	flushInterval  time.Duration
	maxBatch       int
	closeOnce      sync.Once
	done           chan struct{}
	log            *slog.Logger
}

type LogExporterOption func(*LogExporter)

func WithLogFlushInterval(d time.Duration) LogExporterOption {
	return func(l *LogExporter) {
		if d > 0 {
			l.flushInterval = d
		}
	}
}

func WithLogHTTPClient(c *http.Client) LogExporterOption {
	return func(l *LogExporter) {
		if c != nil {
			l.client = c
		}
	}
}

func NewLogExporter(cfg Config, replayRegistry *ReplayRegistry, opts ...LogExporterOption) *LogExporter {
	cfg = cfg.WithDefaults()
	if !cfg.Enabled || strings.TrimSpace(cfg.VectorLogsURL) == "" {
		return nil
	}
	exp := &LogExporter{
		cfg:            cfg,
		replayRegistry: replayRegistry,
		client:         &http.Client{Timeout: defaultLogHTTPTimeout},
		ch:             make(chan LogRecordInput, defaultLogQueueSize),
		flushInterval:  defaultLogFlushInterval,
		maxBatch:       defaultLogMaxBatch,
		done:           make(chan struct{}),
		log:            slog.With("component", "softprobe.LogExporter"),
	}
	for _, opt := range opts {
		opt(exp)
	}
	go exp.run()
	return exp
}

func (l *LogExporter) Enqueue(rec LogRecordInput) bool {
	if l == nil || rec.TraceID == ([16]byte{}) {
		return false
	}
	rec.Body = strings.TrimRight(rec.Body, "\r\n")
	if rec.Body == "" {
		return false
	}
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now()
	}
	select {
	case l.ch <- rec:
		return true
	default:
		return false
	}
}

func (l *LogExporter) Close(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		close(l.ch)
	})
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *LogExporter) run() {
	defer close(l.done)

	ticker := time.NewTicker(l.flushInterval)
	defer ticker.Stop()

	batch := make([]LogRecordInput, 0, l.maxBatch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), defaultLogHTTPTimeout)
		err := l.sendBatch(ctx, batch)
		cancel()
		if err != nil {
			l.log.Debug("failed to export correlated app logs to vector", "error", err, "count", len(batch))
		}
		batch = batch[:0]
	}

	for {
		select {
		case rec, ok := <-l.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, rec)
			if len(batch) >= l.maxBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (l *LogExporter) sendBatch(ctx context.Context, batch []LogRecordInput) error {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	if l.cfg.AppID != "" {
		rl.Resource().Attributes().PutStr("service.name", l.cfg.AppID)
	}
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName(logScopeName)

	for _, item := range batch {
		lr := sl.LogRecords().AppendEmpty()
		ts := pcommon.NewTimestampFromTime(item.Timestamp)
		lr.SetTimestamp(ts)
		lr.SetObservedTimestamp(ts)
		lr.SetTraceID(pcommon.TraceID(item.TraceID))
		if item.SpanID != ([8]byte{}) {
			lr.SetSpanID(pcommon.SpanID(item.SpanID))
		}
		sev := item.SeverityText
		if sev == "" {
			sev = InferLogSeverity(item.Body)
		}
		lr.SetSeverityText(sev)
		lr.SetSeverityNumber(severityTextToNumber(sev))
		lr.Body().SetStr(item.Body)

		attrs := lr.Attributes()
		source := strings.TrimSpace(item.Source)
		if source == "" {
			source = LogSourceApp
		}
		attrs.PutStr("sp.source", source)
		attrs.PutStr("trace_id", FormatTraceIDHex(item.TraceID))
		if item.SpanID != ([8]byte{}) {
			attrs.PutStr("span_id", FormatSpanIDHex(item.SpanID))
		}
		replayID := strings.TrimSpace(item.ReplayID)
		if replayID == "" && l.replayRegistry != nil {
			if sess, ok := l.replayRegistry.Lookup(item.TraceID); ok {
				replayID = sess.ReplayID
			}
		}
		if replayID != "" {
			attrs.PutStr("sp.replay_id", replayID)
		}
	}

	var marshaler plog.ProtoMarshaler
	payload, err := marshaler.MarshalLogs(ld)
	if err != nil {
		return fmt.Errorf("marshaling OTLP logs protobuf: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.cfg.VectorLogsURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating OTLP logs HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := l.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending OTLP logs HTTP request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected Vector OTLP logs status %d", resp.StatusCode)
	}
	return nil
}

func InferLogSeverity(line string) string {
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "ERROR") || strings.Contains(upper, "FATAL") || strings.Contains(upper, "SEVERE"):
		return "ERROR"
	case strings.Contains(upper, "WARN"):
		return "WARN"
	case strings.Contains(upper, "DEBUG"):
		return "DEBUG"
	case strings.Contains(upper, "TRACE"):
		return "TRACE"
	default:
		return "INFO"
	}
}

func severityTextToNumber(sev string) plog.SeverityNumber {
	switch strings.ToUpper(sev) {
	case "ERROR":
		return plog.SeverityNumberError
	case "WARN":
		return plog.SeverityNumberWarn
	case "DEBUG":
		return plog.SeverityNumberDebug
	case "TRACE":
		return plog.SeverityNumberTrace
	default:
		return plog.SeverityNumberInfo
	}
}
