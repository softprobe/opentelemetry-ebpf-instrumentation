// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"net/http"
)

func (g *Gateway) exportHTTPRecording(ctx context.Context, captured *recordRequest, response *http.Response, responseBody []byte) error {
	spanID := make([]byte, 8)
	if _, err := rand.Read(spanID); err != nil {
		return fmt.Errorf("generate Softprobe span ID: %w", err)
	}

	query := HTTPClientQuery(
		hex.EncodeToString(captured.trace.traceID),
		g.appID,
		captured.request.URL.Path,
		captured.request.Method,
		captured.request.URL.RawQuery,
		captured.request.Header.Get("Content-Type"),
		captured.requestBody,
	)
	query.SpanID = hex.EncodeToString(spanID)
	query.ParentSpanID = hex.EncodeToString(captured.trace.parentSpanID)
	query.SegmentID = query.ParentSpanID
	query.SpanKind = "CLIENT"
	query.CreationTime = captured.startTime.UnixMilli()
	query.TargetResponse = httpResponseTarget(response, responseBody)
	return exportRecordingSpan(
		ctx,
		g.client,
		g.traceAPI,
		query,
		"softprobe.obi.gateway",
		captured.request.Method+" "+captured.request.URL.Path,
		ptrace.SpanKindClient,
		captured.trace.flags,
		captured.startTime,
	)
}
