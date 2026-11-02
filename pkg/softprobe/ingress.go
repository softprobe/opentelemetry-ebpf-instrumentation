// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/ptrace"
)

type IngressGatewayConfig struct {
	AppID     string
	Upstream  *url.URL
	TraceAPI  *url.URL
	RecordAPI *url.URL
	Client    *http.Client
}

type IngressGateway struct {
	appID     string
	upstream  *httputil.ReverseProxy
	traceAPI  *url.URL
	recordAPI *url.URL
	client    *http.Client
}

func NewIngressGateway(cfg IngressGatewayConfig) (*IngressGateway, error) {
	if cfg.AppID == "" {
		return nil, errors.New("ingress gateway requires a Softprobe application ID")
	}
	if cfg.Upstream == nil || cfg.Upstream.Host == "" {
		return nil, errors.New("ingress gateway requires an upstream URL")
	}
	if cfg.TraceAPI == nil || cfg.TraceAPI.Host == "" {
		return nil, errors.New("ingress gateway requires the OTLP trace ingest URL")
	}
	client := cfg.Client
	if client == nil {
		client = http.DefaultClient
	}
	proxy := httputil.NewSingleHostReverseProxy(cfg.Upstream)
	return &IngressGateway{
		appID:     cfg.AppID,
		upstream:  proxy,
		traceAPI:  cfg.TraceAPI,
		recordAPI: cfg.RecordAPI,
		client:    client,
	}, nil
}

func (g *IngressGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	trace, spanID, err := ingressTraceContext(r.Header.Get("traceparent"), r.Header.Get("tracestate"))
	if err != nil {
		http.Error(w, "could not create trace context", http.StatusInternalServerError)
		return
	}
	tracestate := r.Header.Get("tracestate")
	_, hasRecordedTraceID := recordedTraceIDFromTracestate(tracestate)
	replayRequest := hasRecordedTraceID || strings.TrimSpace(r.Header.Get("sp-schedule-replay")) != ""
	replayID := replayIDFromTracestate(tracestate)
	requestHeaders := r.Header.Clone()
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	r.Header.Set("traceparent", formatTraceparent(trace.traceID, spanID, trace.flags))
	requestBody, restoredBody, withinLimit := readAndRestore(r.Body, maxCapturePayloadBytes)
	r.Body = restoredBody
	startTime := time.Now()
	proxy := *g.upstream
	proxy.ModifyResponse = func(response *http.Response) error {
		responseBody, restoredBody, responseWithinLimit := readAndRestore(response.Body, maxCapturePayloadBytes)
		response.Body = restoredBody
		if !withinLimit || !responseWithinLimit {
			return nil
		}
		if replayRequest {
			if replayID == "" {
				slog.Warn("could not export Softprobe Servlet replay result: replay tracestate has no replay ID",
					"operation", r.URL.Path, "trace_id", hex.EncodeToString(trace.traceID),
					"tracestate", tracestate)
				return nil
			}
			if err := g.exportServletReplayResult(
				r.Context(), r.Method, r.URL, requestHeaders, requestBody, response.Header, responseBody,
				trace, spanID, replayID, startTime,
			); err != nil {
				slog.Warn("could not export Softprobe Servlet replay result", "error", err)
			}
			return nil
		}
		if err := g.exportServletRecording(
			r.Context(), r.Method, r.URL, requestHeaders, requestBody, response.Header, responseBody,
			trace, spanID, startTime,
		); err != nil {
			slog.Warn("could not export Softprobe Servlet recording", "error", err)
		}
		return nil
	}
	proxy.ServeHTTP(w, r)
}

func ingressTraceContext(traceparent, tracestate string) (traceContext, []byte, error) {
	parent, err := parseTraceparent(traceparent)
	if err != nil {
		parent = traceContext{traceID: make([]byte, traceIDLength), flags: 1}
		if _, err := rand.Read(parent.traceID); err != nil {
			return traceContext{}, nil, fmt.Errorf("generate trace ID: %w", err)
		}
	} else if recordedTraceID, ok := recordedTraceIDFromTracestate(tracestate); ok {
		// The backend's replay sender may replace traceparent while keeping the
		// recorded trace ID in its Softprobe tracestate member. Restore that ID
		// at ingress so OBI can propagate the replay context to dependencies.
		parent.traceID = recordedTraceID
	}
	spanID := make([]byte, spanIDLength)
	if _, err := rand.Read(spanID); err != nil {
		return traceContext{}, nil, fmt.Errorf("generate ingress span ID: %w", err)
	}
	return parent, spanID, nil
}

func recordedTraceIDFromTracestate(tracestate string) ([]byte, bool) {
	for _, member := range strings.Split(tracestate, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(member), "=")
		if !ok || key != "sp" {
			continue
		}
		for _, field := range strings.Split(value, ";") {
			name, rawID, ok := strings.Cut(strings.TrimSpace(field), ":")
			if !ok || name != "tid" || len(rawID) != traceIDLength*2 {
				continue
			}
			traceID, err := hex.DecodeString(rawID)
			if err == nil && len(traceID) == traceIDLength && !allZero(traceID) {
				return traceID, true
			}
		}
	}
	return nil, false
}

func replayIDFromTracestate(tracestate string) string {
	for _, member := range strings.Split(tracestate, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(member), "=")
		if !ok || key != "sp" {
			continue
		}
		for _, field := range strings.Split(value, ";") {
			name, replayID, ok := strings.Cut(strings.TrimSpace(field), ":")
			if ok && name == "rid" && replayID != "" {
				return replayID
			}
		}
	}
	return ""
}

func formatTraceparent(traceID, spanID []byte, flags uint32) string {
	return fmt.Sprintf("00-%s-%s-%02x", hex.EncodeToString(traceID), hex.EncodeToString(spanID), byte(flags))
}

func (g *IngressGateway) exportServletRecording(
	ctx context.Context,
	method string,
	requestURL *url.URL,
	requestHeaders http.Header,
	requestBody []byte,
	responseHeaders http.Header,
	responseBody []byte,
	trace traceContext,
	spanID []byte,
	startTime time.Time,
) error {
	spanIDHex := hex.EncodeToString(spanID)
	mocker := Mocker{
		CategoryType:  CategoryType{Name: CategoryServlet, EntryPoint: true},
		TraceID:       hex.EncodeToString(trace.traceID),
		AppID:         g.appID,
		SpanID:        spanIDHex,
		ParentSpanID:  hex.EncodeToString(trace.parentSpanID),
		SpanKind:      "SERVER",
		CreationTime:  startTime.UnixMilli(),
		OperationName: requestURL.Path,
		TargetRequest: ServletRequestTarget(method, requestURL, requestHeaders, requestBody),
		TargetResponse: ServletResponseTarget(
			responseHeaders,
			responseBody,
		),
	}
	return exportRecordingSpan(
		ctx,
		g.client,
		g.traceAPI,
		mocker,
		"softprobe.obi.ingress",
		method+" "+requestURL.Path,
		ptrace.SpanKindServer,
		trace.flags,
		startTime,
	)
}

func (g *IngressGateway) exportServletReplayResult(
	ctx context.Context,
	method string,
	requestURL *url.URL,
	requestHeaders http.Header,
	requestBody []byte,
	responseHeaders http.Header,
	responseBody []byte,
	trace traceContext,
	spanID []byte,
	replayID string,
	startTime time.Time,
) error {
	if g.recordAPI == nil || g.recordAPI.Host == "" {
		return errors.New("ingress gateway requires the Softprobe record query URL to save replay results")
	}
	mocker := Mocker{
		CategoryType:  CategoryType{Name: CategoryServlet, EntryPoint: true},
		TraceID:       hex.EncodeToString(trace.traceID),
		ReplayID:      replayID,
		AppID:         g.appID,
		SpanID:        hex.EncodeToString(spanID),
		ParentSpanID:  hex.EncodeToString(trace.parentSpanID),
		SegmentID:     requestHeaders.Get("sp-segment-id"),
		SpanKind:      "SERVER",
		CreationTime:  startTime.UnixMilli(),
		OperationName: requestURL.Path,
		TargetRequest: ServletRequestTarget(method, requestURL, requestHeaders, requestBody),
		TargetResponse: ServletResponseTarget(
			responseHeaders,
			responseBody,
		),
	}
	encoded, err := json.Marshal(mocker)
	if err != nil {
		return fmt.Errorf("encode Servlet replay result: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, g.recordAPI.String(), bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("create Servlet replay result request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := g.client.Do(request)
	if err != nil {
		return fmt.Errorf("send Servlet replay result: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Servlet replay result returned HTTP %d", response.StatusCode)
	}
	return nil
}
