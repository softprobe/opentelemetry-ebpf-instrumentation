// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

const (
	EndpointRecordQuery          = "/api/storage/record/query"
	EndpointReplayRealCallResult = "/api/storage/replay/realCallResult"
	EndpointAgentStatus          = "/api/config/agent/agentStatus"

	DefaultBackendClientTimeout = 10 * time.Second
	maxBackendResponseBytes     = 64 << 20
)

var (
	// EmptyInstanceZstdBytes matches SerializationUtils.EMPTY_INSTANCE in sp-backend (Zstd-compressed "{}").
	EmptyInstanceZstdBytes = []byte{
		0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x50, 0x11, 0x00, 0x00, 0x7b, 0x7d,
	}

	// ReplaySkipMockZstdBytes matches SerializationUtils.REPLAY_SKIP_MOCK in sp-backend.
	ReplaySkipMockZstdBytes = []byte{
		0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x58, 0xdd, 0x02, 0x00, 0x02,
		0x86, 0x13, 0x17, 0x90, 0xa9, 0x39, 0xf3, 0x80, 0x28, 0x09,
		0xdc, 0x52, 0x6b, 0x02, 0x99, 0x2c, 0xe5, 0xfd, 0xb9, 0x35,
		0x3d, 0xeb, 0xe2, 0xf5, 0x1f, 0x4b, 0x6b, 0x2d, 0xa7, 0x3c,
		0xa9, 0x61, 0x70, 0x70, 0xcc, 0x40, 0x55, 0xa4, 0xc8, 0x4f,
		0x06, 0xcb, 0xbf, 0x54, 0x91, 0x1a, 0x1d, 0x1e, 0x64, 0xc2,
		0x7d, 0xc8, 0xf2, 0xb4, 0x93, 0xb0, 0x5f, 0x8a, 0x93, 0x7c,
		0x58, 0xe1, 0xd0, 0x5e, 0x9c, 0xa6, 0x80, 0x00, 0xe9, 0xcf,
		0xc7, 0x61, 0x1a, 0xe2, 0x04, 0x45, 0xa2, 0x71, 0x56, 0x05,
		0x03, 0x00, 0x45, 0x49, 0x2d, 0x53, 0x0b, 0xa9, 0x9d, 0x4f,
	}

	// ReplayMustMockZstdBytes matches SerializationUtils.REPLAY_MUST_MOCK in sp-backend.
	ReplayMustMockZstdBytes = []byte{
		0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x58, 0x8d, 0x02, 0x00, 0x12,
		0x05, 0x11, 0x16, 0x90, 0xa7, 0x6d, 0x0b, 0x01, 0x51, 0x0a,
		0xf4, 0xe2, 0xf5, 0x2d, 0x89, 0x34, 0x7d, 0xd6, 0xb6, 0xcc,
		0x8d, 0xd2, 0xba, 0x7b, 0xb1, 0x6b, 0x2d, 0x35, 0x0c, 0xf9,
		0x49, 0x80, 0xfb, 0x9f, 0xa9, 0x61, 0x46, 0xa9, 0x07, 0x19,
		0x70, 0x0f, 0xf6, 0xbe, 0x78, 0x0a, 0xf6, 0xaf, 0x9c, 0x64,
		0x83, 0x81, 0x54, 0xfc, 0x79, 0x89, 0x0d, 0xc4, 0xb0, 0xa7,
		0x4d, 0xea, 0x22, 0x21, 0x8b, 0xb2, 0x4a, 0xbc, 0xa6, 0x02,
		0x03, 0x00, 0x45, 0x49, 0x2d, 0x53, 0x0b, 0xa9, 0x9d, 0x4f,
	}
)

type ClientOption func(*BackendClient)

func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *BackendClient) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *BackendClient) {
		if timeout > 0 {
			c.httpClient = &http.Client{Timeout: timeout}
		}
	}
}

type BackendClient struct {
	baseURL    string
	httpClient *http.Client
	zstdDec    *zstd.Decoder
}

func NewBackendClient(baseURL string, opts ...ClientOption) (*BackendClient, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if err := validateHTTPURL("backend_url", trimmed); err != nil {
		return nil, err
	}
	if trimmed == "" {
		return nil, errors.New("softprobe backend_url must not be empty")
	}

	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, fmt.Errorf("initializing zstd decoder: %w", err)
	}

	c := &BackendClient{
		baseURL:    trimmed,
		httpClient: &http.Client{Timeout: DefaultBackendClientTimeout},
		zstdDec:    dec,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c, nil
}

func (c *BackendClient) Close() {
	if c != nil && c.zstdDec != nil {
		c.zstdDec.Close()
	}
}

func (c *BackendClient) QueryRecord(ctx context.Context, mocker *SpMocker, strategy MockStrategyCode) (QueryResult, error) {
	if mocker == nil {
		return QueryResult{}, errors.New("nil SpMocker")
	}
	if mocker.CategoryType.Name == "" {
		return QueryResult{}, errors.New("SpMocker categoryType.name is required")
	}

	headers := map[string]string{
		HeaderMockStrategyCode: strategy.HeaderValue(),
	}
	raw, respHeader, _, err := c.postJSON(ctx, EndpointRecordQuery, mocker, headers, http.StatusOK)
	if err != nil {
		return QueryResult{}, err
	}

	hasMustMockHeader := hasHeaderKey(respHeader, HeaderMustMock)

	if len(raw) == 0 || bytes.Equal(raw, EmptyInstanceZstdBytes) {
		if hasMustMockHeader {
			return QueryResult{Outcome: QueryOutcomeMustMock}, nil
		}
		return QueryResult{Outcome: QueryOutcomeEmptyMiss}, nil
	}

	decompressed, err := c.decompressZstd(raw)
	if err != nil {
		return QueryResult{}, err
	}

	var decoded SpMocker
	if err := json.Unmarshal(decompressed, &decoded); err != nil {
		return QueryResult{}, fmt.Errorf("decoding SpMocker from record/query: %w", err)
	}

	if bytes.Equal(raw, ReplaySkipMockZstdBytes) || decoded.TargetResponse.AttributeBool(AttrSkipMock) {
		return QueryResult{
			Outcome:    QueryOutcomeSkipMock,
			Mocker:     &decoded,
			RealCallID: decoded.TargetResponse.AttributeString(AttrRealCallID),
		}, nil
	}

	if hasMustMockHeader || bytes.Equal(raw, ReplayMustMockZstdBytes) || decoded.TargetResponse.AttributeBool(AttrMustMock) {
		return QueryResult{
			Outcome: QueryOutcomeMustMock,
			Mocker:  &decoded,
		}, nil
	}

	if isEmptyMockerJSON(decompressed, &decoded) {
		return QueryResult{Outcome: QueryOutcomeEmptyMiss}, nil
	}

	return QueryResult{
		Outcome: QueryOutcomeHit,
		Mocker:  &decoded,
	}, nil
}

func (c *BackendClient) SaveReplayServletResult(ctx context.Context, servletMocker *SpMocker) (*SpMocker, error) {
	if servletMocker == nil {
		return nil, errors.New("nil Servlet SpMocker")
	}

	payload := *servletMocker
	payload.CategoryType = CategoryServlet

	headers := map[string]string{
		HeaderMockStrategyCode: MockStrategyTryFindLastValue.HeaderValue(),
	}
	raw, _, _, err := c.postJSON(ctx, EndpointRecordQuery, &payload, headers, http.StatusOK)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || bytes.Equal(raw, EmptyInstanceZstdBytes) {
		return &payload, nil
	}

	decompressed, err := c.decompressZstd(raw)
	if err != nil {
		return nil, err
	}
	var echoed SpMocker
	if err := json.Unmarshal(decompressed, &echoed); err != nil {
		return nil, fmt.Errorf("decoding Servlet replay response: %w", err)
	}
	if isEmptyMockerJSON(decompressed, &echoed) {
		return &payload, nil
	}
	return &echoed, nil
}

func (c *BackendClient) ReportRealCallResult(ctx context.Context, mocker *SpMocker) error {
	if mocker == nil {
		return errors.New("nil SpMocker")
	}
	if mocker.CategoryType.Name == "" || mocker.TraceID == "" || mocker.ReplayID == "" || mocker.ID == "" {
		return errors.New("ReportRealCallResult requires categoryType, traceId, replayId, and id")
	}
	_, _, _, err := c.postJSON(ctx, EndpointReplayRealCallResult, mocker, nil, http.StatusOK)
	return err
}

func (c *BackendClient) SendAgentStatus(ctx context.Context, status AgentStatusPayload) (AgentStatusResult, error) {
	return c.SendAgentStatusConditional(ctx, status, "")
}

func (c *BackendClient) SendAgentStatusConditional(ctx context.Context, status AgentStatusPayload, ifModifiedSince string) (AgentStatusResult, error) {
	if strings.TrimSpace(status.AppID) == "" {
		return AgentStatusResult{}, errors.New("AgentStatusPayload appId is required")
	}
	var headers map[string]string
	if ifModifiedSince != "" {
		headers = map[string]string{"If-Modified-Since": ifModifiedSince}
	}
	_, respHeader, statusCode, err := c.postJSON(ctx, EndpointAgentStatus, status, headers, http.StatusOK, http.StatusNotModified)
	if err != nil {
		return AgentStatusResult{}, err
	}
	return AgentStatusResult{
		StatusCode:   statusCode,
		LastModified: respHeader.Get("Last-Modified"),
		NotModified:  statusCode == http.StatusNotModified,
		RecordedAt:   time.Now(),
	}, nil
}

func (c *BackendClient) postJSON(
	ctx context.Context,
	endpoint string,
	payload any,
	extraHeaders map[string]string,
	allowedStatuses ...int,
) ([]byte, http.Header, int, error) {
	reqBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("marshaling request for %s: %w", endpoint, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+endpoint, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("building request for %s: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("POST %s failed: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBackendResponseBytes))
	if err != nil {
		return nil, nil, resp.StatusCode, fmt.Errorf("reading response from %s: %w", endpoint, err)
	}

	if !statusAllowed(resp.StatusCode, allowedStatuses) {
		return nil, resp.Header, resp.StatusCode, fmt.Errorf("POST %s returned HTTP %d", endpoint, resp.StatusCode)
	}
	return body, resp.Header, resp.StatusCode, nil
}

func (c *BackendClient) decompressZstd(raw []byte) ([]byte, error) {
	out, err := c.zstdDec.DecodeAll(raw, nil)
	if err != nil {
		return nil, fmt.Errorf("zstd decompress failed: %w", err)
	}
	return out, nil
}

func statusAllowed(code int, allowed []int) bool {
	if slices.Contains(allowed, code) {
		return true
	}
	if len(allowed) == 0 {
		return code >= http.StatusOK && code < http.StatusMultipleChoices
	}
	return false
}

// hasHeaderKey checks case-insensitive key presence because AgentRecordingController
// emits .header("mustMock", "") with an empty value.
func hasHeaderKey(h http.Header, target string) bool {
	for k := range h {
		if strings.EqualFold(k, target) {
			return true
		}
	}
	return false
}

func isEmptyMockerJSON(decompressed []byte, m *SpMocker) bool {
	if bytes.Equal(bytes.TrimSpace(decompressed), []byte("{}")) {
		return true
	}
	return m.ID == "" &&
		m.CategoryType.Name == "" &&
		m.TraceID == "" &&
		m.ReplayID == "" &&
		m.TargetRequest == nil &&
		m.TargetResponse == nil
}
