// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen // import "go.opentelemetry.io/obi/pkg/export/otel/tracesgen"

import (
	"encoding/hex"
	"testing"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/metadata"
	"go.opentelemetry.io/obi/pkg/softprobe"
)

func TestGenerateTracesWithSoftprobePreservesEntrySpanIDAndSegment(t *testing.T) {
	enricher := softprobe.NewSpanEnricher(softprobe.Config{
		Enabled:               true,
		AppID:                 "travel-ota",
		Env:                   "pro",
		ExcludeErrorResponses: true,
		RecordRate:            1.0,
	}, softprobe.NewReplayRegistry(64, time.Minute))

	var traceID trace.TraceID
	rawTrace, err := hex.DecodeString("a1b2c3d4e5f6789012345678abcdef01")
	require.NoError(t, err)
	copy(traceID[:], rawTrace)

	servletSpanID := trace.SpanID{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
	intermediateSpanID := trace.SpanID{0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc}
	upstreamProxySpanID := trace.SpanID{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	clientSpanID := trace.SpanID{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22}

	baseMono := 10 * time.Second
	clientSpan := request.Span{
		Type:         request.EventTypeHTTPClient,
		Method:       "POST",
		Path:         "/ndc/v21.3/servicelist",
		Status:       200,
		RequestStart: int64(baseMono + 2*time.Millisecond),
		Start:        int64(baseMono + 2*time.Millisecond),
		End:          int64(baseMono + 8*time.Millisecond),
		TraceID:      traceID,
		SpanID:       clientSpanID,
		ParentSpanID: intermediateSpanID,
		Softprobe: &request.SoftprobeCapture{
			RequestBody:  []byte("<IATA_ServiceListRQ/>"),
			ResponseBody: []byte("<IATA_ServiceListRS/>"),
		},
	}

	// Start > RequestStart triggers createSubSpans ("in queue" + "processing").
	servletSpan := request.Span{
		Type:         request.EventTypeHTTP,
		Method:       "POST",
		Path:         "/api/flights/baggage/purchase",
		Status:       200,
		RequestStart: int64(baseMono),
		Start:        int64(baseMono + time.Millisecond),
		End:          int64(baseMono + 12*time.Millisecond),
		TraceID:      traceID,
		SpanID:       servletSpanID,
		ParentSpanID: upstreamProxySpanID,
		Softprobe: &request.SoftprobeCapture{
			RequestBody:  []byte(`{"orderId":"ORD-1"}`),
			ResponseBody: []byte(`{"status":"SUCCESS"}`),
		},
	}

	cache := expirable2.NewLRU[svc.UID, []attribute.KeyValue](16, nil, time.Minute)
	service := &svc.Attrs{UID: svc.UID{Name: "java"}}
	nodeMeta := &metadata.NodeMeta{}

	// Place child before server span so only ObserveServerSpan pre-registration resolves the root segment.
	traces := GenerateTracesWithSoftprobe(
		cache,
		service,
		nil,
		nodeMeta,
		[]TraceSpanAndAttributes{
			{Span: &clientSpan},
			{Span: &servletSpan},
		},
		"go.opentelemetry.io/obi",
		nil,
		enricher,
	)

	require.Equal(t, 1, traces.ResourceSpans().Len())
	rs := traces.ResourceSpans().At(0)
	svcName, ok := rs.Resource().Attributes().Get("service.name")
	require.True(t, ok)
	assert.Equal(t, "travel-ota", svcName.Str())

	var (
		exportedServlet ptrace.Span
		foundServlet    bool
		exportedClient  ptrace.Span
		foundClient     bool
	)
	for i := 0; i < rs.ScopeSpans().Len(); i++ {
		ss := rs.ScopeSpans().At(i)
		for j := 0; j < ss.Spans().Len(); j++ {
			sp := ss.Spans().At(j)
			switch sp.Kind() {
			case ptrace.SpanKindServer:
				exportedServlet = sp
				foundServlet = true
			case ptrace.SpanKindClient:
				exportedClient = sp
				foundClient = true
			}
		}
	}
	require.True(t, foundServlet)
	require.True(t, foundClient)

	assert.Equal(t, "1020304050607080", exportedServlet.SpanID().String())
	assert.True(t, exportedServlet.ParentSpanID().IsEmpty(), "Servlet entry span must have empty ParentSpanID")

	servletSeg, ok := exportedServlet.Attributes().Get(softprobe.OTLPAttrSegmentID)
	require.True(t, ok)
	assert.Equal(t, "1020304050607080", servletSeg.Str())

	clientSeg, ok := exportedClient.Attributes().Get(softprobe.OTLPAttrSegmentID)
	require.True(t, ok)
	assert.Equal(t, "1020304050607080", clientSeg.Str())
	assert.Equal(t, "5566778899aabbcc", exportedClient.ParentSpanID().String())
}
