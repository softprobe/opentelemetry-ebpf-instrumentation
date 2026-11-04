// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

const (
	RecordMode                = "record"
	ReplayMode                = "replay"
	maxReplayRequestBodyBytes = 4 << 20
	maxCapturePayloadBytes    = 4 << 20
)

type GatewayConfig struct {
	Mode              string
	AppID             string
	Upstream          *url.URL
	RecordAPI         *url.URL
	TraceAPI          *url.URL
	RequestContextMap RequestTraceContextReader
	Client            *http.Client
}

type Gateway struct {
	mode              string
	appID             string
	upstream          *httputil.ReverseProxy
	recordAPI         *url.URL
	traceAPI          *url.URL
	requestContextMap RequestTraceContextReader
	client            *http.Client
}

func NewGateway(cfg GatewayConfig) (*Gateway, error) {
	if cfg.Mode != RecordMode && cfg.Mode != ReplayMode {
		return nil, fmt.Errorf("unsupported gateway mode %q", cfg.Mode)
	}
	if cfg.Mode == RecordMode && (cfg.Upstream == nil || cfg.Upstream.Host == "") {
		return nil, errors.New("record mode requires an upstream URL")
	}
	if cfg.Mode == ReplayMode && (cfg.RecordAPI == nil || cfg.RecordAPI.Host == "") {
		return nil, errors.New("replay mode requires the Softprobe record query URL")
	}
	if cfg.Mode == ReplayMode && cfg.AppID == "" {
		return nil, errors.New("replay mode requires the Softprobe application ID")
	}
	client := cfg.Client
	if client == nil {
		client = http.DefaultClient
	}
	gateway := &Gateway{
		mode:              cfg.Mode,
		appID:             cfg.AppID,
		recordAPI:         cfg.RecordAPI,
		traceAPI:          cfg.TraceAPI,
		requestContextMap: cfg.RequestContextMap,
		client:            client,
	}
	if cfg.Mode == RecordMode {
		gateway.upstream = httputil.NewSingleHostReverseProxy(cfg.Upstream)
		director := gateway.upstream.Director
		gateway.upstream.Director = func(request *http.Request) {
			director(request)
			// NewSingleHostReverseProxy preserves the incoming Host header.
			// Use the configured origin host for virtual-hosted HTTPS services.
			request.Host = cfg.Upstream.Host
		}
	}
	return gateway, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if g.mode == RecordMode {
		g.serveRecord(w, r)
		return
	}
	g.serveReplay(w, r)
}

type traceContext struct {
	traceID      []byte
	parentSpanID []byte
	flags        uint32
}

type recordRequest struct {
	trace       traceContext
	request     *http.Request
	requestBody []byte
	startTime   time.Time
	canCapture  bool
}

func (g *Gateway) serveRecord(w http.ResponseWriter, r *http.Request) {
	trace, err := g.traceContextForRequest(r)
	if err != nil {
		// Recording is best effort; keep the outbound request working when OBI
		// has no trace context for this connection.
		g.upstream.ServeHTTP(w, r)
		return
	}
	if g.traceAPI == nil || g.appID == "" {
		g.upstream.ServeHTTP(w, r)
		return
	}

	body, restoredBody, withinLimit := readAndRestore(r.Body, maxCapturePayloadBytes)
	r.Body = restoredBody
	request := &recordRequest{
		trace:       trace,
		request:     r,
		requestBody: body,
		startTime:   time.Now(),
		canCapture:  withinLimit,
	}
	proxy := *g.upstream
	proxy.ModifyResponse = func(response *http.Response) error {
		responseBody, restoredBody, responseWithinLimit := readAndRestore(response.Body, maxCapturePayloadBytes)
		response.Body = restoredBody
		if !request.canCapture || !responseWithinLimit {
			return nil
		}
		if err := g.exportHTTPRecording(r.Context(), request, response, responseBody); err != nil {
			slog.Warn("could not export Softprobe HTTP recording", "error", err)
		}
		return nil
	}
	proxy.ServeHTTP(w, r)
}

// readAndRestore reads at most limit+1 bytes and returns a body that can still
// be consumed in full by the proxy, including when it exceeds the capture cap.
type restoredReadCloser struct {
	io.Reader
	io.Closer
}

func readAndRestore(body io.ReadCloser, limit int64) ([]byte, io.ReadCloser, bool) {
	if body == nil {
		return nil, io.NopCloser(bytes.NewReader(nil)), true
	}
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	restored := &restoredReadCloser{Reader: io.MultiReader(bytes.NewReader(data), body), Closer: body}
	return data, restored, err == nil && int64(len(data)) <= limit
}

func (g *Gateway) serveReplay(w http.ResponseWriter, r *http.Request) {
	trace, err := g.traceContextForRequest(r)
	if err != nil {
		http.Error(w, "replay requires a valid traceparent or OBI request context", http.StatusBadRequest)
		return
	}
	traceID := hex.EncodeToString(trace.traceID)
	if recordedTraceID, ok := recordedTraceIDFromTracestate(r.Header.Get("tracestate")); ok {
		traceID = hex.EncodeToString(recordedTraceID)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxReplayRequestBodyBytes+1))
	if err != nil {
		http.Error(w, "failed to read replay request", http.StatusBadRequest)
		return
	}
	if len(body) > maxReplayRequestBodyBytes {
		http.Error(w, "replay request body exceeds the prototype limit", http.StatusRequestEntityTooLarge)
		return
	}

	query := HTTPClientQuery(traceID, g.appID, r.URL.Path, r.Method, r.URL.RawQuery, r.Header.Get("Content-Type"), body)
	query.ReplayID = replayIDFromTracestate(r.Header.Get("tracestate"))
	queryJSON, err := json.Marshal(query)
	if err != nil {
		http.Error(w, "failed to encode replay query", http.StatusInternalServerError)
		return
	}
	recorded, err := g.queryRecord(r.Context(), queryJSON)
	if err != nil {
		http.Error(w, "Softprobe replay query failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if recorded == nil || recorded.TargetResponse.Body == "" {
		slog.Warn("no Softprobe response matched replay request",
			"trace_id", traceID,
			"operation", r.URL.Path,
			"traceparent", r.Header.Get("traceparent"),
			"tracestate", r.Header.Get("tracestate"),
		)
		http.Error(w, "no recorded response for trace and HTTP request", http.StatusFailedDependency)
		return
	}
	response, err := HTTPResponseFromTarget(recorded.TargetResponse)
	if err != nil {
		http.Error(w, "invalid recorded HTTP response: "+err.Error(), http.StatusBadGateway)
		return
	}

	copyHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	if response.Body != nil {
		_, _ = io.Copy(w, response.Body)
		_ = response.Body.Close()
	}
}

func (g *Gateway) traceContextForRequest(r *http.Request) (traceContext, error) {
	trace, headerErr := parseTraceparent(r.Header.Get("traceparent"))
	if g.requestContextMap == nil || r.RemoteAddr == "" {
		return trace, headerErr
	}

	requestContext, found, mapErr := g.requestContextMap.Consume(r.RemoteAddr)
	if headerErr == nil {
		if mapErr != nil {
			slog.Debug("could not consume OBI request context; using traceparent", "error", mapErr)
		}
		return trace, nil
	}
	if mapErr != nil {
		return traceContext{}, mapErr
	}
	if !found {
		return traceContext{}, headerErr
	}

	traceID, err := decodeID(requestContext.TraceID, traceIDLength, "OBI trace ID")
	if err != nil {
		return traceContext{}, err
	}
	var parentSpanID []byte
	if requestContext.ParentSpanID != "" && !allZeroHexID(requestContext.ParentSpanID) {
		parentSpanID, err = decodeID(requestContext.ParentSpanID, spanIDLength, "OBI parent span ID")
		if err != nil {
			return traceContext{}, err
		}
	}
	return traceContext{traceID: traceID, parentSpanID: parentSpanID, flags: requestContext.Flags}, nil
}

func allZeroHexID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && allZero(decoded)
}

func (g *Gateway) queryRecord(ctx context.Context, queryJSON []byte) (*Mocker, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.recordAPI.String(), bytes.NewReader(queryJSON))
	if err != nil {
		return nil, fmt.Errorf("create recording query: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send recording query: %w", err)
	}
	defer resp.Body.Close()
	compressed, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read recording query response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("recording query returned HTTP %d", resp.StatusCode)
	}
	decoder, err := zstd.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("decode recording response compression: %w", err)
	}
	defer decoder.Close()
	data, err := io.ReadAll(decoder)
	if err != nil {
		return nil, fmt.Errorf("read decompressed recording response: %w", err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("[]")) || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	var mocker Mocker
	if err := json.Unmarshal(data, &mocker); err != nil {
		return nil, fmt.Errorf("decode recorded mocker: %w", err)
	}
	if mocker.TargetResponse.Body == "" {
		return nil, nil
	}
	return &mocker, nil
}

func traceIDFromTraceparent(traceparent string) (string, error) {
	trace, err := parseTraceparent(traceparent)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(trace.traceID), nil
}

func parseTraceparent(traceparent string) (traceContext, error) {
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 || len(parts[0]) != 2 || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return traceContext{}, errors.New("invalid W3C traceparent")
	}
	if strings.EqualFold(parts[0], "ff") {
		return traceContext{}, errors.New("invalid W3C traceparent version")
	}
	traceBytes, err := hex.DecodeString(parts[1])
	if err != nil || allZero(traceBytes) {
		return traceContext{}, errors.New("invalid W3C trace ID")
	}
	spanBytes, err := hex.DecodeString(parts[2])
	if err != nil || allZero(spanBytes) {
		return traceContext{}, errors.New("invalid W3C span ID")
	}
	flags, err := hex.DecodeString(parts[3])
	if err != nil {
		return traceContext{}, errors.New("invalid W3C trace flags")
	}
	return traceContext{traceID: traceBytes, parentSpanID: spanBytes, flags: uint32(flags[0])}, nil
}

func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func copyHeaders(dst, src http.Header) {
	for name, values := range src {
		if isHopByHopHeader(name) || strings.EqualFold(name, "Content-Length") {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func isHopByHopHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}
