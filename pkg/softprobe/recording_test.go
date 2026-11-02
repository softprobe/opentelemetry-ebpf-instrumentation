// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestHTTPClientRecordingUsesLegacySoftprobeShape(t *testing.T) {
	span := request.Span{
		TraceID:      trace.TraceID{1, 2, 3},
		SpanID:       trace.SpanID{4, 5, 6},
		ParentSpanID: trace.SpanID{7, 8, 9},
		Start:        1_000_000,
		End:          2_000_000,
		Path:         "/ndc/v21.3/airshopping",
		FullPath:     "https://airline.example/ndc/v21.3/airshopping?locale=en",
		Type:         request.EventTypeHTTPClient,
		Method:       "POST",
		Status:       201,
		RequestHeaders: map[string][]string{
			"Content-Type": {"application/json"},
		},
	}
	req := []byte("POST /ndc/v21.3/airshopping?locale=en HTTP/1.1\r\nHost: airline.example\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"x\":1}")
	resp := []byte("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nX-Record: yes\r\nContent-Length: 11\r\n\r\n{\"ok\":true}")

	mocker, err := HTTPClientRecording(span, "travel-ota", req, resp)
	require.NoError(t, err)
	require.Equal(t, "HttpClient", mocker.CategoryType.Name)
	require.Equal(t, "01020300000000000000000000000000", mocker.TraceID)
	require.Equal(t, "0405060000000000", mocker.SpanID)
	require.Equal(t, "0708090000000000", mocker.ParentSpanID)
	require.Equal(t, "travel-ota", mocker.AppID)
	require.Equal(t, "/ndc/v21.3/airshopping", mocker.OperationName)

	require.Equal(t, "/ndc/v21.3/airshopping", mocker.TargetRequest.Attributes["Operation"])
	require.Equal(t, "POST", mocker.TargetRequest.Attributes["HttpMethod"])
	require.Equal(t, "locale=en", mocker.TargetRequest.Attributes["QueryString"])
	require.Equal(t, "application/json", mocker.TargetRequest.Attributes["ContentType"])
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte(`{"x":1}`)), mocker.TargetRequest.Body)
	require.Equal(t, "java.lang.String", mocker.TargetRequest.Type)

	var wrapper httpResponseWrapper
	require.NoError(t, json.Unmarshal([]byte(mocker.TargetResponse.Body), &wrapper))
	require.Equal(t, 201, wrapper.StatusCode)
	require.Equal(t, "Created", wrapper.Reason)
	require.Equal(t, []byte(`{"ok":true}`), wrapper.Content)
	require.Equal(t, "yes", wrapper.HeaderValue("X-Record"))
	require.Equal(t, "io.softprobe.inst.httpclient.common.HttpResponseWrapper", mocker.TargetResponse.Type)
}

func TestHTTPClientRecordingRejectsIncompleteWirePayloads(t *testing.T) {
	span := request.Span{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}}
	_, err := HTTPClientRecording(span, "travel-ota", []byte("not-http"), []byte("HTTP/1.1 200 OK\r\n\r\n"))
	require.Error(t, err)
}
