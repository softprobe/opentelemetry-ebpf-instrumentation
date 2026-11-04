// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package softprobe translates OBI observations to the existing Softprobe
// recording and replay contract.
package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	CategoryHTTPClient      = "HttpClient"
	CategoryServlet         = "Servlet"
	HTTPResponseWrapperType = "io.softprobe.inst.httpclient.common.HttpResponseWrapper"
	javaStringType          = "java.lang.String"
	traceIDLength           = 16
	spanIDLength            = 8
)

// Target has the same JSON shape as ai.softprobe.model.mock.Mocker.Target.
type Target struct {
	Body       string         `json:"body"`
	Attributes map[string]any `json:"attributes"`
	Type       string         `json:"type"`
}

// CategoryType is serialized as the existing Softprobe category object.
type CategoryType struct {
	Name           string `json:"name"`
	EntryPoint     bool   `json:"entryPoint"`
	SkipComparison bool   `json:"skipComparison"`
}

// Mocker is the subset of the existing SpMocker contract used by HTTP capture
// and the /api/storage/record/query endpoint.
type Mocker struct {
	CategoryType   CategoryType `json:"categoryType"`
	TraceID        string       `json:"traceId"`
	ReplayID       string       `json:"replayId,omitempty"`
	AppID          string       `json:"appId"`
	SpanID         string       `json:"spanId,omitempty"`
	ParentSpanID   string       `json:"parentSpanId,omitempty"`
	SegmentID      string       `json:"segmentId,omitempty"`
	SpanKind       string       `json:"spanKind,omitempty"`
	CreationTime   int64        `json:"creationTime,omitempty"`
	OperationName  string       `json:"operationName"`
	TargetRequest  Target       `json:"targetRequest"`
	TargetResponse Target       `json:"targetResponse,omitzero"`
}

type httpResponseWrapper struct {
	StatusLine string                   `json:"statusLine"`
	Content    []byte                   `json:"content"`
	Locale     *httpResponseStringPair  `json:"locale"`
	Headers    []httpResponseStringPair `json:"headers"`
	Reason     string                   `json:"reason"`
	StatusCode int                      `json:"statusCode"`
	TypeName   *string                  `json:"typeName"`
}

type httpResponseStringPair struct {
	First  string `json:"f"`
	Second string `json:"s"`
}

func (w httpResponseWrapper) HeaderValue(name string) string {
	for _, header := range w.Headers {
		if strings.EqualFold(header.First, name) {
			return header.Second
		}
	}
	return ""
}

// HTTPClientRecording creates a Softprobe-compatible HTTP dependency recording
// from OBI's captured request and response wire buffers.
func HTTPClientRecording(span request.Span, appID string, requestPayload, responsePayload []byte) (Mocker, error) {
	requestMessage, requestBody, err := parseRequest(requestPayload)
	if err != nil {
		return Mocker{}, fmt.Errorf("parse captured HTTP request: %w", err)
	}
	responseMessage, responseBody, err := parseResponse(responsePayload, requestMessage)
	if err != nil {
		return Mocker{}, fmt.Errorf("parse captured HTTP response: %w", err)
	}

	query := HTTPClientQuery(
		span.TraceID.String(),
		appID,
		span.Path,
		requestMessage.Method,
		requestMessage.URL.RawQuery,
		requestMessage.Header.Get("Content-Type"),
		requestBody,
	)
	query.SpanID = span.SpanID.String()
	query.ParentSpanID = span.ParentSpanID.String()
	query.SegmentID = span.ParentSpanID.String()
	query.SpanKind = "CLIENT"
	query.CreationTime = time.Now().UnixMilli()
	query.TargetResponse = httpResponseTarget(responseMessage, responseBody)
	return query, nil
}

// HTTPClientQuery builds the request fields expected by the legacy Softprobe
// HttpClient match key and /api/storage/record/query API.
func HTTPClientQuery(traceID, appID, operationName, method, queryString, contentType string, body []byte) Mocker {
	requestURL := &url.URL{Path: operationName, RawQuery: queryString}
	requestHeaders := make(http.Header)
	requestHeaders.Set("Content-Type", contentType)
	return Mocker{
		CategoryType:  CategoryType{Name: CategoryHTTPClient},
		TraceID:       traceID,
		AppID:         appID,
		OperationName: operationName,
		TargetRequest: targetRequestForHTTP(&http.Request{Method: method, URL: requestURL, Header: requestHeaders}, body),
	}
}

func httpResponseTarget(response *http.Response, body []byte) Target {
	reason := response.Status
	if _, after, ok := strings.Cut(reason, " "); ok {
		reason = after
	}
	wrapped := httpResponseWrapper{
		StatusLine: response.Proto + " " + response.Status,
		Content:    body,
		Reason:     reason,
		StatusCode: response.StatusCode,
		Headers:    make([]httpResponseStringPair, 0, len(response.Header)),
	}
	for name, values := range response.Header {
		for _, value := range values {
			wrapped.Headers = append(wrapped.Headers, httpResponseStringPair{First: name, Second: value})
		}
	}
	serialized, _ := json.Marshal(wrapped)
	return Target{Body: string(serialized), Type: HTTPResponseWrapperType}
}

func parseRequest(payload []byte) (*http.Request, []byte, error) {
	if len(payload) == 0 {
		return nil, nil, errors.New("empty request payload")
	}
	message, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(message.Body)
	if err != nil {
		return nil, nil, err
	}
	return message, body, nil
}

func parseResponse(payload []byte, request *http.Request) (*http.Response, []byte, error) {
	if len(payload) == 0 {
		return nil, nil, errors.New("empty response payload")
	}
	message, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), request)
	if err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(message.Body)
	if err != nil {
		return nil, nil, err
	}
	return message, body, nil
}

func targetRequestForHTTP(req *http.Request, body []byte) Target {
	requestBody := req.URL.RawQuery
	if len(body) > 0 || (body != nil && req.Method != http.MethodGet) {
		requestBody = base64.StdEncoding.EncodeToString(body)
	}
	return Target{
		Body: requestBody,
		Type: javaStringType,
		Attributes: map[string]any{
			"Operation":   req.URL.Path,
			"HttpMethod":  req.Method,
			"QueryString": req.URL.RawQuery,
			"ContentType": req.Header.Get("Content-Type"),
		},
	}
}

// HTTPRequestTarget constructs the legacy targetRequest for an HTTP request
// received by the replay gateway. It preserves the raw query used by Softprobe's
// existing HttpClient match key.
func HTTPRequestTarget(method string, requestURL *url.URL, headers http.Header, body []byte) Target {
	return targetRequestForHTTP(&http.Request{
		Method: method,
		URL:    requestURL,
		Header: headers,
	}, body)
}

// ServletRequestTarget follows the Java agent's existing entrypoint shape:
// request bodies are base64 encoded and method/path/headers live in attributes.
func ServletRequestTarget(method string, requestURL *url.URL, headers http.Header, body []byte) Target {
	requestHeaders := firstHeaderValues(headers)
	deleteHeaderFold(requestHeaders, "Referer")
	return Target{
		Body: base64.StdEncoding.EncodeToString(body),
		Type: javaStringType,
		Attributes: map[string]any{
			"HttpMethod":  method,
			"RequestPath": requestURL.Path,
			"Headers":     requestHeaders,
		},
	}
}

// ServletResponseTarget follows the Java agent's body and response-header shape.
func ServletResponseTarget(headers http.Header, body []byte) Target {
	return Target{
		Body: string(body),
		Type: javaStringType,
		Attributes: map[string]any{
			"Headers": firstHeaderValues(headers),
		},
	}
}

func firstHeaderValues(headers http.Header) map[string]string {
	result := make(map[string]string, len(headers))
	for name, values := range headers {
		if len(values) > 0 {
			result[name] = values[0]
		}
	}
	return result
}

func deleteHeaderFold(headers map[string]string, name string) {
	for key := range headers {
		if strings.EqualFold(key, name) {
			delete(headers, key)
		}
	}
}

// HTTPResponseFromTarget decodes the existing Java HttpResponseWrapper stored
// in targetResponse and returns the original status, headers, and bytes.
func HTTPResponseFromTarget(target Target) (*http.Response, error) {
	if target.Type != HTTPResponseWrapperType {
		return nil, fmt.Errorf("unsupported recorded HTTP response type %q", target.Type)
	}
	var wrapped httpResponseWrapper
	if err := json.Unmarshal([]byte(target.Body), &wrapped); err != nil {
		return nil, fmt.Errorf("decode recorded HttpResponseWrapper: %w", err)
	}
	if wrapped.StatusCode < 100 || wrapped.StatusCode > 599 {
		return nil, fmt.Errorf("invalid recorded HTTP status %d", wrapped.StatusCode)
	}
	response := &http.Response{
		Status:        statusCodeLine(wrapped.StatusCode, wrapped.Reason),
		StatusCode:    wrapped.StatusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(wrapped.Content)),
		ContentLength: int64(len(wrapped.Content)),
	}
	if wrapped.StatusLine != "" {
		if fields := strings.Fields(wrapped.StatusLine); len(fields) > 1 {
			response.Proto = fields[0]
			response.ProtoMajor, response.ProtoMinor = parseHTTPVersion(response.Proto)
		}
	}
	for _, header := range wrapped.Headers {
		response.Header.Add(header.First, header.Second)
	}
	return response, nil
}

func statusCodeLine(status int, reason string) string {
	if reason == "" {
		reason = http.StatusText(status)
	}
	return strconv.Itoa(status) + " " + reason
}

func parseHTTPVersion(version string) (int, int) {
	var major, minor int
	if _, err := fmt.Sscanf(version, "HTTP/%d.%d", &major, &minor); err != nil {
		return 1, 1
	}
	return major, minor
}
