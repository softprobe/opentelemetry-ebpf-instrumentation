// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func decodePostedMockerForTest(t *testing.T, body []byte) SpMocker {
	t.Helper()
	var m SpMocker
	assert.NoError(t, json.Unmarshal(body, &m))
	return m
}

func TestDataplaneBridgeBidirectionalRegistrationOrder(t *testing.T) {
	ctx := context.Background()
	ln1, err := ListenNonMPTCP(ctx, "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln1.Close()

	ln2, err := ListenNonMPTCP(ctx, "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln2.Close()

	dpA := &fakeDataplane{}
	bridgeA := NewDataplaneBridge(nil)
	require.NoError(t, bridgeA.SetIngressListener(ln1))
	require.Nil(t, dpA.registered())
	require.NoError(t, bridgeA.AttachDataplane(dpA))
	assert.Same(t, ln1, dpA.registered())

	dpB := &fakeDataplane{}
	bridgeB := NewDataplaneBridge(nil)
	require.NoError(t, bridgeB.AttachDataplane(dpB))
	require.Nil(t, dpB.registered())
	require.NoError(t, bridgeB.SetIngressListener(ln2))
	assert.Same(t, ln2, dpB.registered())
}

type fakeDataplane struct {
	mu sync.Mutex
	ln net.Listener
}

func (f *fakeDataplane) LookupEgressTarget(_ net.Addr) (EgressTarget, bool) {
	return EgressTarget{}, false
}

func (f *fakeDataplane) RegisterIngressListener(ln net.Listener) error {
	f.mu.Lock()
	f.ln = ln
	f.mu.Unlock()
	return nil
}

func (f *fakeDataplane) registered() net.Listener {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ln
}

func TestIngressReplayT0RegistrationAndT3SynchronousCommit(t *testing.T) {
	const (
		recordedTraceHex = "f1e44c876f1790e664ca6709160c35cd"
		replayIDHex      = "9f3c756610c14aed"
		segmentIDHex     = "2f207b44041a0ee4"
	)

	reg := NewReplayRegistry(128, time.Minute)
	bridge := NewDataplaneBridge(NewWriteContextTracker(128, time.Minute))

	var t3SaveCompleted atomic.Bool
	var savedMockerMu sync.Mutex
	var savedMocker *SpMocker

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/storage/record/query":
			body, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			m := decodePostedMockerForTest(t, body)
			time.Sleep(15 * time.Millisecond)
			savedMockerMu.Lock()
			savedMocker = &m
			savedMockerMu.Unlock()
			t3SaveCompleted.Store(true)
			w.Header().Set("Content-Type", "application/zstd")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(EmptyInstanceZstdBytes)
		case "/api/config/agent/agentStatus":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer backendSrv.Close()

	var t0SessionFound atomic.Bool
	var observedTraceparent atomic.Value

	appSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tp := r.Header.Get(HeaderTraceparent)
		observedTraceparent.Store(tp)
		if tc, err := ParseTraceparent(tp); err == nil {
			if _, ok := reg.Lookup(tc.TraceID); ok {
				t0SessionFound.Store(true)
			}
		}

		if r.Header.Get("Accept-Encoding") == "gzip" {
			var gzBuf bytes.Buffer
			gw := gzip.NewWriter(&gzBuf)
			_, _ = gw.Write([]byte(`{"flights":[{"flightNo":"SP101"}]}`))
			_ = gw.Close()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(gzBuf.Bytes())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"live":true}`))
	}))
	defer appSrv.Close()
	appHostPort := appSrv.Listener.Addr().String()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AppID = "travel-ota"
	cfg.BackendURL = backendSrv.URL
	cfg.Env = "pro"

	bc, err := NewBackendClient(backendSrv.URL)
	require.NoError(t, err)

	ingress := NewIngressListener(
		cfg,
		reg,
		bc,
		bridge,
		WithIngressTargetResolver(func(_ net.Conn) (string, error) {
			return appHostPort, nil
		}),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, ingress.Start(ctx))
	defer func() { _ = ingress.Close() }()

	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression:  true,
			MaxIdleConnsPerHost: 2,
		},
	}
	baseURL := "http://" + ingress.Addr().String()

	liveReq, err := http.NewRequest(http.MethodGet, baseURL+"/api/health", nil)
	require.NoError(t, err)
	liveResp, err := client.Do(liveReq)
	require.NoError(t, err)
	liveBody, err := io.ReadAll(liveResp.Body)
	_ = liveResp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, liveResp.StatusCode)
	assert.JSONEq(t, `{"live":true}`, string(liveBody))
	assert.Empty(t, liveResp.Header.Get(HeaderReplayID))
	assert.False(t, t3SaveCompleted.Load())

	replayReq, err := http.NewRequest(http.MethodPost, baseURL+"/api/flights/search?cabin=Y", bytes.NewReader([]byte(`{"origin":"SFO"}`)))
	require.NoError(t, err)
	replayReq.Header.Set("Content-Type", "application/json")
	replayReq.Header.Set("Accept-Encoding", "gzip")
	replayReq.Header.Set(HeaderScheduleReplay, "true")
	replayReq.Header.Set(HeaderTracestate, "sp=mode:replay;tid:"+recordedTraceHex+";rid:"+replayIDHex)
	replayReq.Header.Set(HeaderSegmentID, segmentIDHex)

	replayResp, err := client.Do(replayReq)
	require.NoError(t, err)
	assert.True(t, t0SessionFound.Load(), "T0 registration must complete before request hits target app")
	assert.True(t, t3SaveCompleted.Load(), "T3 SaveReplayServletResult must complete before response reaches caller")
	assert.Equal(t, replayIDHex, replayResp.Header.Get(HeaderReplayID))

	gr, err := gzip.NewReader(replayResp.Body)
	require.NoError(t, err)
	unzippedWire, err := io.ReadAll(gr)
	_ = gr.Close()
	_ = replayResp.Body.Close()
	require.NoError(t, err)
	assert.JSONEq(t, `{"flights":[{"flightNo":"SP101"}]}`, string(unzippedWire))

	savedMockerMu.Lock()
	m := savedMocker
	savedMockerMu.Unlock()
	require.NotNil(t, m)
	assert.Equal(t, CategoryServlet, m.CategoryType)
	assert.Equal(t, recordedTraceHex, m.TraceID)
	assert.Equal(t, replayIDHex, m.ReplayID)
	assert.Equal(t, segmentIDHex, m.SegmentID)
	assert.Equal(t, "/api/flights/search", m.OperationName)
	require.NotNil(t, m.TargetResponse)
	assert.JSONEq(t, `{"flights":[{"flightNo":"SP101"}]}`, m.TargetResponse.Body)
}

func TestEgressTLSPooledKeepAliveMixedLiveAndReplayHit(t *testing.T) {
	const (
		sockCookie       uint64 = 9001
		recordedTraceHex        = "d19582aec8c44078acda9bcce638488b"
		replayIDHex             = "56f3c62235e4d490"
		segmentIDHex            = "8340d63db5d76e3d"
	)
	recordedTraceID, err := ParseTraceIDHex(recordedTraceHex)
	require.NoError(t, err)
	serverSpanID, err := ParseSpanIDHex(segmentIDHex)
	require.NoError(t, err)

	upstreamCA, err := NewEphemeralCA()
	require.NoError(t, err)
	upstreamLeaf, err := upstreamCA.LeafCertificateForHost("spair.softprobe.ai")
	require.NoError(t, err)

	var upstreamHits atomic.Int32
	upstreamTLS := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"source":"live","call":` + strconv.Itoa(int(n)) + `}`))
	}))
	upstreamTLS.TLS = &tls.Config{
		Certificates: []tls.Certificate{*upstreamLeaf},
	}
	upstreamTLS.EnableHTTP2 = true
	upstreamTLS.StartTLS()
	defer upstreamTLS.Close()

	upstreamAddrPort, err := netip.ParseAddrPort(upstreamTLS.Listener.Addr().String())
	require.NoError(t, err)
	upstreamRoots := upstreamCA.CertPool()

	mockBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/storage/record/query":
			body, readErr := io.ReadAll(r.Body)
			assert.NoError(t, readErr)
			qm := decodePostedMockerForTest(t, body)
			assert.Equal(t, CategoryHTTPClient, qm.CategoryType)
			assert.Equal(t, recordedTraceHex, qm.TraceID)
			assert.Equal(t, replayIDHex, qm.ReplayID)
			assert.Equal(t, "/ndc/v21.3/airshopping", qm.OperationName)

			mockRespPayload := []byte(`{"source":"mocked-ndc","offerId":"OFFER-1"}`)
			hitMocker, buildErr := BuildHTTPClientMocker(SpanMetadata{
				AppID:     "travel-ota",
				TraceID:   recordedTraceHex,
				ReplayID:  replayIDHex,
				SegmentID: segmentIDHex,
			}, HTTPClientExchange{
				Method:        http.MethodPost,
				OperationName: "/ndc/v21.3/airshopping",
				Response: &HTTPResponseWrapper{
					Status:     http.StatusOK,
					StatusCode: http.StatusOK,
					Reason:     "OK",
					Headers:    map[string]string{"Content-Type": "application/json", "X-NDC-Mock": "hit"},
					HeaderList: []HeaderTuple{
						{Name: "Content-Type", Value: "application/json"},
						{Name: "X-NDC-Mock", Value: "hit"},
					},
					BodyBase64: base64.StdEncoding.EncodeToString(mockRespPayload),
					Body:       string(mockRespPayload),
				},
			})
			assert.NoError(t, buildErr)
			hitMocker.ID = "mock-doc-1"
			w.Header().Set("Content-Type", "application/zstd")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(zstdCompressForTest(t, hitMocker))
		case "/api/config/agent/agentStatus":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockBackend.Close()

	reg := NewReplayRegistry(128, time.Minute)
	tracker := NewWriteContextTracker(256, time.Minute)
	bridge := NewDataplaneBridge(tracker)

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AppID = "travel-ota"
	cfg.BackendURL = mockBackend.URL
	cfg.EgressProxyPort = 0

	lnProbe, err := ListenNonMPTCP(context.Background(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	freeEgressPort := int(extractPortFromAddr(lnProbe.Addr()))
	_ = lnProbe.Close()
	cfg.EgressProxyPort = freeEgressPort

	rt, err := NewRuntime(
		cfg,
		WithRuntimeCACertPath(filepath.Join(t.TempDir(), "sp-obi-ca.pem")),
		WithRuntimeReplayRegistry(reg),
		WithRuntimeDataplaneBridge(bridge),
		WithRuntimeEgressTargetResolver(func(_ net.Addr) (EgressTarget, bool) {
			return EgressTarget{
				SockCookie: sockCookie,
				AddrPort:   upstreamAddrPort,
				PID:        4242,
			}, true
		}),
		WithRuntimeHTTPHandlerOptions(WithUpstreamTLSConfig(&tls.Config{
			RootCAs:    upstreamRoots,
			MinVersion: tls.VersionTLS12,
		})),
	)
	require.NoError(t, err)

	require.NoError(t, rt.Start(t.Context()))
	defer func() { _ = rt.Close() }()

	var rawWrittenOffset atomic.Uint64
	var activeWriteTrace atomic.Pointer[[16]byte]

	egressAddr := rt.EgressAddr().String()
	pooledTransport := &http.Transport{
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		ForceAttemptHTTP2:   false,
		TLSClientConfig: &tls.Config{
			RootCAs:    rt.CA().CertPool(),
			ServerName: "spair.softprobe.ai",
			NextProtos: []string{"http/1.1"},
		},
		DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			rawConn, dialErr := d.DialContext(dialCtx, "tcp4", egressAddr)
			if dialErr != nil {
				return nil, dialErr
			}
			return &simulatedBPFWriteConn{
				Conn:         rawConn,
				sockCookie:   sockCookie,
				tracker:      tracker,
				offset:       &rawWrittenOffset,
				currentTrace: &activeWriteTrace,
				serverSpanID: serverSpanID,
			}, nil
		},
	}
	defer pooledTransport.CloseIdleConnections()
	client := &http.Client{Transport: pooledTransport}

	resp1, err := client.Post("https://spair.softprobe.ai/ndc/v21.3/airshopping", "application/json", bytes.NewReader([]byte(`{"trip":1}`)))
	require.NoError(t, err)
	body1, err := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, "HTTP/1.1", resp1.Proto)
	assert.JSONEq(t, `{"source":"live","call":1}`, string(body1))
	assert.Equal(t, int32(1), upstreamHits.Load())

	reg.Register(recordedTraceID, ReplaySession{
		TraceID:         recordedTraceID,
		Mode:            ModeReplay,
		RecordedTraceID: recordedTraceHex,
		ReplayID:        replayIDHex,
		SegmentID:       segmentIDHex,
	})
	traceCopy := recordedTraceID
	activeWriteTrace.Store(&traceCopy)

	resp2, err := client.Post("https://spair.softprobe.ai/ndc/v21.3/airshopping", "application/json", bytes.NewReader([]byte(`{"trip":1}`)))
	require.NoError(t, err)
	body2, err := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	assert.Equal(t, "hit", resp2.Header.Get("X-NDC-Mock"))
	assert.JSONEq(t, `{"source":"mocked-ndc","offerId":"OFFER-1"}`, string(body2))
	assert.Equal(t, int32(1), upstreamHits.Load(), "replay hit on pooled TLS connection must not dial or call upstream")
	assert.Equal(t, uint64(1), rt.HTTPHandler().Stats().MockHits.Load())

	activeWriteTrace.Store(nil)
	resp3, err := client.Post("https://spair.softprobe.ai/ndc/v21.3/airshopping", "application/json", bytes.NewReader([]byte(`{"trip":2}`)))
	require.NoError(t, err)
	body3, err := io.ReadAll(resp3.Body)
	_ = resp3.Body.Close()
	require.NoError(t, err)
	assert.JSONEq(t, `{"source":"live","call":2}`, string(body3))
	assert.Equal(t, int32(2), upstreamHits.Load())
}

func TestMustMockAndEmptyMissNeverDialUpstream(t *testing.T) {
	const (
		recordedTraceHex = "cf4d44d8a1ffc077d5f50176732791c2"
		replayIDHex      = "3288bdd4e03846f2"
		segmentIDHex     = "7819a48c1628ab9e"
	)
	recordedTraceID, err := ParseTraceIDHex(recordedTraceHex)
	require.NoError(t, err)

	var upstreamConnections atomic.Int32
	deadEndLn, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer deadEndLn.Close()
	go func() {
		for {
			c, acceptErr := deadEndLn.Accept()
			if acceptErr != nil {
				return
			}
			upstreamConnections.Add(1)
			_ = c.Close()
		}
	}()
	origDst, err := netip.ParseAddrPort(deadEndLn.Addr().String())
	require.NoError(t, err)

	var returnMustMock atomic.Bool
	returnMustMock.Store(true)

	mockBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/storage/record/query":
			w.Header().Set("Content-Type", "application/zstd")
			if returnMustMock.Load() {
				w.Header().Set(HeaderMustMock, "")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(ReplayMustMockZstdBytes)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(EmptyInstanceZstdBytes)
		case "/api/config/agent/agentStatus":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockBackend.Close()

	reg := NewReplayRegistry(64, time.Minute)
	reg.Register(recordedTraceID, ReplaySession{
		TraceID:         recordedTraceID,
		Mode:            ModeReplay,
		RecordedTraceID: recordedTraceHex,
		ReplayID:        replayIDHex,
		SegmentID:       segmentIDHex,
	})

	lnProbe, err := ListenNonMPTCP(context.Background(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	egressPort := int(extractPortFromAddr(lnProbe.Addr()))
	_ = lnProbe.Close()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AppID = "travel-ota"
	cfg.BackendURL = mockBackend.URL
	cfg.EgressProxyPort = egressPort

	rt, err := NewRuntime(
		cfg,
		WithRuntimeCACertPath(filepath.Join(t.TempDir(), "sp-obi-ca.pem")),
		WithRuntimeReplayRegistry(reg),
		WithRuntimeDataplaneBridge(NewDataplaneBridge(NewWriteContextTracker(64, time.Minute))),
		WithRuntimeEgressTargetResolver(func(_ net.Addr) (EgressTarget, bool) {
			return EgressTarget{SockCookie: 77, AddrPort: origDst, PID: 100}, true
		}),
	)
	require.NoError(t, err)

	require.NoError(t, rt.Start(t.Context()))
	defer func() { _ = rt.Close() }()

	egressAddr := rt.EgressAddr().String()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rt.CA().CertPool(),
				ServerName: "spair.softprobe.ai",
			},
			DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(dialCtx, "tcp4", egressAddr)
			},
		},
	}

	req1, err := http.NewRequest(http.MethodPost, "https://spair.softprobe.ai/ndc/v21.3/ordercreate", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	req1.Header.Set(HeaderTraceparent, "00-"+recordedTraceHex+"-56f3c62235e4d490-01")

	resp1, err := client.Do(req1)
	require.NoError(t, err)
	_ = resp1.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp1.StatusCode)
	assert.Equal(t, ErrorCodeMustMock, resp1.Header.Get(HeaderSoftprobeError))
	assert.Equal(t, int32(0), upstreamConnections.Load(), "MUST_MOCK must never open an upstream socket")
	assert.Equal(t, uint64(0), rt.HTTPHandler().Stats().UpstreamDials.Load())
	assert.Equal(t, uint64(1), rt.HTTPHandler().Stats().MustMockBlocks.Load())

	returnMustMock.Store(false)
	req2, err := http.NewRequest(http.MethodPost, "https://spair.softprobe.ai/ndc/v21.3/ordercreate", bytes.NewReader([]byte(`{}`)))
	require.NoError(t, err)
	req2.Header.Set(HeaderTraceparent, "00-"+recordedTraceHex+"-56f3c62235e4d490-01")

	resp2, err := client.Do(req2)
	require.NoError(t, err)
	_ = resp2.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp2.StatusCode)
	assert.Equal(t, ErrorCodeMockMiss, resp2.Header.Get(HeaderSoftprobeError))
	assert.Equal(t, int32(0), upstreamConnections.Load(), "empty mock miss must never open an upstream socket")
	assert.Equal(t, uint64(0), rt.HTTPHandler().Stats().UpstreamDials.Load())
	assert.Equal(t, uint64(1), rt.HTTPHandler().Stats().EmptyMissBlocks.Load())
}

func TestEgressSkipMockReportsRealCallResultAndHTTP2Replay(t *testing.T) {
	const (
		recordedTraceHex = "c61dcbc451b8b23ff91450bd7ee1d81b"
		replayIDHex      = "2e272b7f40d22fd5"
		segmentIDHex     = "d8105f7d62411625"
	)
	recordedTraceID, err := ParseTraceIDHex(recordedTraceHex)
	require.NoError(t, err)

	upstreamCA, err := NewEphemeralCA()
	require.NoError(t, err)
	upstreamLeaf, err := upstreamCA.LeafCertificateForHost("spair.softprobe.ai")
	require.NoError(t, err)

	upstreamTLS := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"realUpstream":true,"path":"` + r.URL.Path + `"}`))
	}))
	upstreamTLS.TLS = &tls.Config{
		Certificates: []tls.Certificate{*upstreamLeaf},
	}
	upstreamTLS.EnableHTTP2 = true
	upstreamTLS.StartTLS()
	defer upstreamTLS.Close()

	origDst, err := netip.ParseAddrPort(upstreamTLS.Listener.Addr().String())
	require.NoError(t, err)
	upstreamRoots := upstreamCA.CertPool()

	reportedCh := make(chan SpMocker, 1)
	mockBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/storage/record/query":
			body, readErr := io.ReadAll(r.Body)
			assert.NoError(t, readErr)
			qm := decodePostedMockerForTest(t, body)
			w.Header().Set("Content-Type", "application/zstd")
			if qm.OperationName == "/ndc/v21.3/live-bypass" {
				sentinel := &SpMocker{
					CategoryType: CategoryHTTPClient,
					TargetResponse: &Target{
						Attributes: map[string]any{
							AttrSkipMock:   true,
							AttrRealCallID: "real-call-id-77",
						},
					},
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(zstdCompressForTest(t, sentinel))
				return
			}
			payload := []byte(`{"h2Mocked":true}`)
			reqMethod := http.MethodPost
			if qm.TargetRequest != nil && qm.TargetRequest.AttributeString(AttrHTTPMethod) != "" {
				reqMethod = qm.TargetRequest.AttributeString(AttrHTTPMethod)
			}
			hit, buildErr := BuildHTTPClientMocker(SpanMetadata{
				AppID:     "travel-ota",
				TraceID:   recordedTraceHex,
				ReplayID:  replayIDHex,
				SegmentID: segmentIDHex,
			}, HTTPClientExchange{
				Method:        reqMethod,
				OperationName: qm.OperationName,
				Response: &HTTPResponseWrapper{
					Status:     http.StatusOK,
					StatusCode: http.StatusOK,
					Reason:     "OK",
					Headers:    map[string]string{"Content-Type": "application/json"},
					BodyBase64: base64.StdEncoding.EncodeToString(payload),
					Body:       string(payload),
				},
			})
			assert.NoError(t, buildErr)
			hit.ID = "h2-doc-1"
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(zstdCompressForTest(t, hit))

		case "/api/storage/replay/realCallResult":
			body, readErr := io.ReadAll(r.Body)
			assert.NoError(t, readErr)
			reported := decodePostedMockerForTest(t, body)
			select {
			case reportedCh <- reported:
			default:
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`true`))

		case "/api/config/agent/agentStatus":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockBackend.Close()

	reg := NewReplayRegistry(64, time.Minute)
	reg.Register(recordedTraceID, ReplaySession{
		TraceID:         recordedTraceID,
		Mode:            ModeReplay,
		RecordedTraceID: recordedTraceHex,
		ReplayID:        replayIDHex,
		SegmentID:       segmentIDHex,
	})

	lnProbe, err := ListenNonMPTCP(context.Background(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	egressPort := int(extractPortFromAddr(lnProbe.Addr()))
	_ = lnProbe.Close()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AppID = "travel-ota"
	cfg.BackendURL = mockBackend.URL
	cfg.EgressProxyPort = egressPort

	rt, err := NewRuntime(
		cfg,
		WithRuntimeCACertPath(filepath.Join(t.TempDir(), "sp-obi-ca.pem")),
		WithRuntimeReplayRegistry(reg),
		WithRuntimeDataplaneBridge(NewDataplaneBridge(NewWriteContextTracker(64, time.Minute))),
		WithRuntimeEgressTargetResolver(func(_ net.Addr) (EgressTarget, bool) {
			return EgressTarget{SockCookie: 88, AddrPort: origDst, PID: 200}, true
		}),
		WithRuntimeHTTPHandlerOptions(WithUpstreamTLSConfig(&tls.Config{
			RootCAs:    upstreamRoots,
			MinVersion: tls.VersionTLS12,
		})),
	)
	require.NoError(t, err)

	require.NoError(t, rt.Start(t.Context()))
	defer func() { _ = rt.Close() }()

	egressAddr := rt.EgressAddr().String()
	h2Transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    rt.CA().CertPool(),
			ServerName: "spair.softprobe.ai",
			NextProtos: []string{"h2"},
		},
		DialTLSContext: func(dialCtx context.Context, _, _ string, tlsCfg *tls.Config) (net.Conn, error) {
			var d net.Dialer
			raw, dialErr := d.DialContext(dialCtx, "tcp4", egressAddr)
			if dialErr != nil {
				return nil, dialErr
			}
			c := tls.Client(raw, tlsCfg)
			if hsErr := c.HandshakeContext(dialCtx); hsErr != nil {
				_ = raw.Close()
				return nil, hsErr
			}
			return c, nil
		},
	}
	h2Client := &http.Client{Transport: h2Transport}

	h2Req, err := http.NewRequest(http.MethodPost, "https://spair.softprobe.ai/ndc/v21.3/servicelist", bytes.NewReader([]byte(`{"pax":1}`)))
	require.NoError(t, err)
	h2Req.Header.Set(HeaderTraceparent, "00-"+recordedTraceHex+"-2e272b7f40d22fd5-01")
	h2Resp, err := h2Client.Do(h2Req)
	require.NoError(t, err)
	h2Body, err := io.ReadAll(h2Resp.Body)
	_ = h2Resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, 2, h2Resp.ProtoMajor)
	assert.JSONEq(t, `{"h2Mocked":true}`, string(h2Body))

	skipReq, err := http.NewRequest(http.MethodPost, "https://spair.softprobe.ai/ndc/v21.3/live-bypass", bytes.NewReader([]byte(`{"bypass":true}`)))
	require.NoError(t, err)
	skipReq.Header.Set(HeaderTraceparent, "00-"+recordedTraceHex+"-2e272b7f40d22fd5-01")
	skipResp, err := h2Client.Do(skipReq)
	require.NoError(t, err)
	skipBody, err := io.ReadAll(skipResp.Body)
	_ = skipResp.Body.Close()
	require.NoError(t, err)
	assert.JSONEq(t, `{"realUpstream":true,"path":"/ndc/v21.3/live-bypass"}`, string(skipBody))

	select {
	case reported := <-reportedCh:
		assert.Equal(t, "real-call-id-77", reported.ID)
		assert.Equal(t, recordedTraceHex, reported.TraceID)
		assert.Equal(t, replayIDHex, reported.ReplayID)
		wrapper, decErr := DecodeHTTPClientResponse(&reported)
		require.NoError(t, decErr)
		reportedBytes, pbErr := wrapper.PayloadBytes()
		require.NoError(t, pbErr)
		assert.JSONEq(t, `{"realUpstream":true,"path":"/ndc/v21.3/live-bypass"}`, string(reportedBytes))
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ReportRealCallResult")
	}
}

type simulatedBPFWriteConn struct {
	net.Conn
	sockCookie   uint64
	tracker      *WriteContextTracker
	offset       *atomic.Uint64
	currentTrace *atomic.Pointer[[16]byte]
	serverSpanID [8]byte
}

func (s *simulatedBPFWriteConn) Write(p []byte) (int, error) {
	if len(p) > 0 {
		startOff := s.offset.Add(uint64(len(p))) - uint64(len(p))
		var tid [16]byte
		if ptr := s.currentTrace.Load(); ptr != nil {
			tid = *ptr
		}
		s.tracker.RecordWrite(SocketWriteContext{
			SockCookie:   s.sockCookie,
			ByteOffset:   startOff,
			PayloadLen:   uint32(len(p)),
			TraceID:      tid,
			ServerSpanID: s.serverSpanID,
		})
	}
	return s.Conn.Write(p)
}

func TestEgressLiveHTTPSGzipCaptureEnrichesTruncatedSpan(t *testing.T) {
	const liveTraceHex = "dda187cc2c4ec48ab176a13695841e59"
	liveTraceID, err := ParseTraceIDHex(liveTraceHex)
	require.NoError(t, err)
	servletSpanID := [8]byte{0x30, 0x6d, 0xbc, 0x7e, 0x65, 0x2c, 0xb7, 0x3e}
	clientSpanID := [8]byte{0xd8, 0xd2, 0xce, 0x6b, 0xe4, 0x9f, 0xdf, 0xa2}

	upstreamCA, err := NewEphemeralCA()
	require.NoError(t, err)
	upstreamLeaf, err := upstreamCA.LeafCertificateForHost("spair.softprobe.ai")
	require.NoError(t, err)

	fullUpstreamJSON := `{"IATA_OfferPriceRS":{"Response":{"PricedOffer":{"OfferID":"OF-900","TotalPrice":420.50}}}}`
	upstreamTLS := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var gzBuf bytes.Buffer
		gz := gzip.NewWriter(&gzBuf)
		_, _ = gz.Write([]byte(fullUpstreamJSON))
		_ = gz.Close()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzBuf.Bytes())
	}))
	upstreamTLS.TLS = &tls.Config{
		Certificates: []tls.Certificate{*upstreamLeaf},
	}
	upstreamTLS.EnableHTTP2 = true
	upstreamTLS.StartTLS()
	defer upstreamTLS.Close()

	origDst, err := netip.ParseAddrPort(upstreamTLS.Listener.Addr().String())
	require.NoError(t, err)

	reg := NewReplayRegistry(128, time.Minute)
	tracker := NewWriteContextTracker(128, time.Minute)
	bridge := NewDataplaneBridge(tracker)

	lnProbe, err := ListenNonMPTCP(context.Background(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	freeEgressPort := int(extractPortFromAddr(lnProbe.Addr()))
	_ = lnProbe.Close()

	const sockCookie = uint64(40594)
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AppID = "travel-ota"
	cfg.Env = "pro"
	cfg.RecordRate = 1.0
	cfg.IngressProxyPort = -1
	cfg.EgressProxyPort = freeEgressPort

	rt, err := NewRuntime(
		cfg,
		WithRuntimeCACertPath(filepath.Join(t.TempDir(), "sp-obi-ca.pem")),
		WithRuntimeReplayRegistry(reg),
		WithRuntimeDataplaneBridge(bridge),
		WithRuntimeEgressTargetResolver(func(net.Addr) (EgressTarget, bool) {
			return EgressTarget{SockCookie: sockCookie, AddrPort: origDst, PID: 1234}, true
		}),
		WithRuntimeHTTPHandlerOptions(WithUpstreamTLSConfig(&tls.Config{
			RootCAs:    upstreamCA.CertPool(),
			MinVersion: tls.VersionTLS12,
		})),
	)
	require.NoError(t, err)

	require.NoError(t, rt.Start(t.Context()))
	defer func() { _ = rt.Close() }()

	egressAddr := rt.EgressAddr().String()
	var writeOff atomic.Uint64
	var activeTrace atomic.Pointer[[16]byte]
	activeTrace.Store(&liveTraceID)

	h2Transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    rt.CA().CertPool(),
			ServerName: "spair.softprobe.ai",
			NextProtos: []string{"h2"},
		},
		DialTLSContext: func(dialCtx context.Context, _, _ string, tlsCfg *tls.Config) (net.Conn, error) {
			var d net.Dialer
			rawConn, dialErr := d.DialContext(dialCtx, "tcp4", egressAddr)
			if dialErr != nil {
				return nil, dialErr
			}
			wrapped := &simulatedBPFWriteConn{
				Conn:         rawConn,
				sockCookie:   sockCookie,
				tracker:      tracker,
				offset:       &writeOff,
				currentTrace: &activeTrace,
				serverSpanID: servletSpanID,
			}
			tlsClient := tls.Client(wrapped, tlsCfg)
			if hsErr := tlsClient.HandshakeContext(dialCtx); hsErr != nil {
				_ = rawConn.Close()
				return nil, hsErr
			}
			return tlsClient, nil
		},
	}
	client := &http.Client{Transport: h2Transport}

	fullReqJSON := `{"IATA_OfferPriceRQ":{"Request":{"PricedOffer":{"OfferRefID":"FL900","OfferItemRefID":"FARE900"}}}}`
	req, err := http.NewRequest(http.MethodPost, "https://spair.softprobe.ai/ndc/v21.3/offerprice", bytes.NewReader([]byte(fullReqJSON)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	require.NoError(t, err)
	wireBody, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
	decodedWire, wasDecoded := decodeHTTPBody(wireBody, "gzip", 0)
	assert.True(t, wasDecoded)
	assert.JSONEq(t, fullUpstreamJSON, string(decodedWire))

	enricher := NewSpanEnricher(cfg, reg)
	enricher.SetExchangeCache(bridge.ExchangeCache())

	truncatedSpan := &request.Span{
		Type:         request.EventTypeHTTPClient,
		Method:       "POST",
		Path:         "/ndc/v21.3/offerprice",
		Status:       200,
		TraceID:      trace.TraceID(liveTraceID),
		SpanID:       trace.SpanID(clientSpanID),
		ParentSpanID: trace.SpanID(servletSpanID),
		Softprobe: &request.SoftprobeCapture{
			RequestBody:  []byte(`{"IATA_OfferPri`),
			ResponseBody: nil,
		},
	}

	nowNano := time.Now().UnixNano()
	res := enricher.EnrichSpan(truncatedSpan, liveTraceID, clientSpanID, nowNano, nowNano+5_000_000)
	require.NotNil(t, res.Mocker)
	reqDecoded, err := base64.StdEncoding.DecodeString(res.Mocker.TargetRequest.Body)
	require.NoError(t, err)
	assert.JSONEq(t, fullReqJSON, string(reqDecoded))

	wrapper, err := DecodeHTTPClientResponse(res.Mocker)
	require.NoError(t, err)
	respPayload, err := wrapper.PayloadBytes()
	require.NoError(t, err)
	assert.JSONEq(t, fullUpstreamJSON, string(respPayload))
	assert.Empty(t, wrapper.Headers["Content-Encoding"])
}

func TestRuntimeReplayEmitsAgentCorrelatedOTLPLogs(t *testing.T) {
	const (
		recordedTraceHex = "ab12cd34ef567890ab12cd34ef567890"
		replayIDHex      = "445566778899aabb"
		segmentIDHex     = "1122334455667788"
	)

	var (
		logsMu   sync.Mutex
		received []plog.Logs
	)
	vectorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		logsMu.Lock()
		received = append(received, ld)
		logsMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer vectorSrv.Close()

	mockBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/storage/record/query":
			body, readErr := io.ReadAll(r.Body)
			assert.NoError(t, readErr)
			qm := decodePostedMockerForTest(t, body)
			w.Header().Set("Content-Type", "application/zstd")
			if qm.CategoryType == CategoryServlet {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(EmptyInstanceZstdBytes)
				return
			}
			mockPayload := []byte(`{"status":"CONFIRMED"}`)
			hit, buildErr := BuildHTTPClientMocker(SpanMetadata{
				AppID:     "travel-ota",
				TraceID:   recordedTraceHex,
				ReplayID:  replayIDHex,
				SegmentID: segmentIDHex,
			}, HTTPClientExchange{
				Method:        http.MethodPost,
				OperationName: qm.OperationName,
				Response: &HTTPResponseWrapper{
					Status:     http.StatusOK,
					StatusCode: http.StatusOK,
					Reason:     "OK",
					Headers:    map[string]string{"Content-Type": "application/json"},
					BodyBase64: base64.StdEncoding.EncodeToString(mockPayload),
					Body:       string(mockPayload),
				},
			})
			assert.NoError(t, buildErr)
			hit.ID = "mock-order-1"
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(zstdCompressForTest(t, hit))
		case "/api/config/agent/agentStatus":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockBackend.Close()

	deadEndLn, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer deadEndLn.Close()
	origDst, err := netip.ParseAddrPort(deadEndLn.Addr().String())
	require.NoError(t, err)

	lnIngressProbe, err := ListenNonMPTCP(context.Background(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	ingressPort := int(extractPortFromAddr(lnIngressProbe.Addr()))
	_ = lnIngressProbe.Close()

	lnEgressProbe, err := ListenNonMPTCP(context.Background(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	egressPort := int(extractPortFromAddr(lnEgressProbe.Addr()))
	_ = lnEgressProbe.Close()

	reg := NewReplayRegistry(64, time.Minute)
	bridge := NewDataplaneBridge(NewWriteContextTracker(64, time.Minute))

	var egressAddrAtomic atomic.Value
	var caPoolAtomic atomic.Value

	appSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		egressAddr, _ := egressAddrAtomic.Load().(string)
		rootPool, _ := caPoolAtomic.Load().(*tls.Config)
		outClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: rootPool,
				DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(dialCtx, "tcp4", egressAddr)
				},
			},
		}
		outReq, reqErr := http.NewRequestWithContext(r.Context(), http.MethodPost, "https://spair.softprobe.ai/ndc/v21.3/ordercreate", bytes.NewReader([]byte(`{"offer":"1"}`)))
		if !assert.NoError(t, reqErr) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		outReq.Header.Set(HeaderTraceparent, r.Header.Get(HeaderTraceparent))
		outResp, doErr := outClient.Do(outReq)
		if !assert.NoError(t, doErr) {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		outBody, _ := io.ReadAll(outResp.Body)
		_ = outResp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(outResp.StatusCode)
		_, _ = w.Write(outBody)
	}))
	defer appSrv.Close()
	appHostPort := appSrv.Listener.Addr().String()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AppID = "travel-ota"
	cfg.BackendURL = mockBackend.URL
	cfg.VectorLogsURL = vectorSrv.URL + "/v1/logs"
	cfg.IngressProxyPort = ingressPort
	cfg.EgressProxyPort = egressPort

	rt, err := NewRuntime(
		cfg,
		WithRuntimeCACertPath(filepath.Join(t.TempDir(), "sp-obi-ca.pem")),
		WithRuntimeReplayRegistry(reg),
		WithRuntimeDataplaneBridge(bridge),
		WithRuntimeIngressOptions(WithIngressTargetResolver(func(_ net.Conn) (string, error) {
			return appHostPort, nil
		})),
		WithRuntimeEgressTargetResolver(func(_ net.Addr) (EgressTarget, bool) {
			return EgressTarget{SockCookie: 501, AddrPort: origDst, PID: 777}, true
		}),
	)
	require.NoError(t, err)
	require.NotNil(t, rt.LogExporter())

	egressAddrAtomic.Store(fmt.Sprintf("127.0.0.1:%d", egressPort))
	caPoolAtomic.Store(&tls.Config{
		RootCAs:    rt.CA().CertPool(),
		ServerName: "spair.softprobe.ai",
	})

	require.NoError(t, rt.Start(t.Context()))

	replayReq, err := http.NewRequest(http.MethodPost, "http://"+rt.IngressAddr().String()+"/api/orders", bytes.NewReader([]byte(`{"pax":"A"}`)))
	require.NoError(t, err)
	replayReq.Header.Set("Content-Type", "application/json")
	replayReq.Header.Set(HeaderScheduleReplay, "true")
	replayReq.Header.Set(HeaderTracestate, "sp=mode:replay;tid:"+recordedTraceHex+";rid:"+replayIDHex)
	replayReq.Header.Set(HeaderSegmentID, segmentIDHex)

	replayResp, err := http.DefaultClient.Do(replayReq)
	require.NoError(t, err)
	respBody, err := io.ReadAll(replayResp.Body)
	_ = replayResp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, replayResp.StatusCode)
	assert.JSONEq(t, `{"status":"CONFIRMED"}`, string(respBody))
	assert.Equal(t, replayIDHex, replayResp.Header.Get(HeaderReplayID))

	require.NoError(t, rt.Close())

	logsMu.Lock()
	defer logsMu.Unlock()

	var agentRecords []plog.LogRecord
	for _, ld := range received {
		for i := 0; i < ld.ResourceLogs().Len(); i++ {
			rl := ld.ResourceLogs().At(i)
			for j := 0; j < rl.ScopeLogs().Len(); j++ {
				sl := rl.ScopeLogs().At(j)
				for k := 0; k < sl.LogRecords().Len(); k++ {
					lr := sl.LogRecords().At(k)
					if src, ok := lr.Attributes().Get("sp.source"); ok && src.Str() == LogSourceAgent {
						agentRecords = append(agentRecords, lr)
					}
				}
			}
		}
	}
	require.GreaterOrEqual(t, len(agentRecords), 2)

	var sawServletReplay, sawHTTPClientHit bool
	for _, lr := range agentRecords {
		assert.Equal(t, recordedTraceHex, lr.TraceID().String())
		repAttr, ok := lr.Attributes().Get("sp.replay_id")
		require.True(t, ok)
		assert.Equal(t, replayIDHex, repAttr.Str())
		body := lr.Body().Str()
		if strings.Contains(body, "softprobe replayed Servlet POST /api/orders") {
			sawServletReplay = true
		}
		if strings.Contains(body, "softprobe replay mock hit HttpClient POST /ndc/v21.3/ordercreate") {
			sawHTTPClientHit = true
		}
	}
	assert.True(t, sawServletReplay, "expected IngressListener replay agent log")
	assert.True(t, sawHTTPClientHit, "expected HTTPProtocolHandler replay hit agent log")
}

type fakeServerFirstHandler struct {
	port        uint16
	greeting    string
	serverFirst bool
	peekLenCh   chan int
}

func (f *fakeServerFirstHandler) Name() string {
	return "fake-server-first"
}

func (f *fakeServerFirstHandler) IsServerFirstPort(origPort uint16) bool {
	return f.serverFirst && origPort == f.port
}

func (f *fakeServerFirstHandler) CanHandle(preamble []byte, origPort uint16) bool {
	if origPort != f.port {
		return false
	}
	select {
	case f.peekLenCh <- len(preamble):
	default:
	}
	return true
}

func (f *fakeServerFirstHandler) HandleConnection(_ context.Context, conn OutgoingConnectionContext) error {
	if _, err := io.WriteString(conn.ClientConn, f.greeting); err != nil {
		return err
	}
	line, err := conn.BufReader.ReadString('\n')
	if err != nil {
		return err
	}
	_, err = io.WriteString(conn.ClientConn, "ack:"+line)
	return err
}

type fakeEmptyPreamblePortHandler struct {
	port      uint16
	greeting  string
	peekLenCh chan int
}

func (f *fakeEmptyPreamblePortHandler) Name() string {
	return "fake-empty-preamble"
}

func (f *fakeEmptyPreamblePortHandler) CanHandle(preamble []byte, origPort uint16) bool {
	if origPort != f.port {
		return false
	}
	select {
	case f.peekLenCh <- len(preamble):
	default:
	}
	return true
}

func (f *fakeEmptyPreamblePortHandler) HandleConnection(_ context.Context, conn OutgoingConnectionContext) error {
	_, err := io.WriteString(conn.ClientConn, f.greeting)
	return err
}

func TestRuntimeEgressServerSpeaksFirstHandlerDispatch(t *testing.T) {
	lnEgressProbe, err := ListenNonMPTCP(context.Background(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	egressPort := int(extractPortFromAddr(lnEgressProbe.Addr()))
	_ = lnEgressProbe.Close()

	var targetPort atomic.Uint32
	targetPort.Store(3306)

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.AppID = "travel-ota"
	cfg.IngressProxyPort = -1
	cfg.EgressProxyPort = egressPort

	rt, err := NewRuntime(
		cfg,
		WithRuntimeCACertPath(filepath.Join(t.TempDir(), "sp-obi-ca.pem")),
		WithRuntimeReplayRegistry(NewReplayRegistry(32, time.Minute)),
		WithRuntimeDataplaneBridge(NewDataplaneBridge(NewWriteContextTracker(32, time.Minute))),
		WithRuntimeEgressTargetResolver(func(_ net.Addr) (EgressTarget, bool) {
			p := uint16(targetPort.Load())
			return EgressTarget{
				SockCookie: 901,
				AddrPort:   netip.AddrPortFrom(netip.MustParseAddr("10.0.0.12"), p),
				PID:        999,
			}, true
		}),
	)
	require.NoError(t, err)

	mysqlHandler := &fakeServerFirstHandler{
		port:        3306,
		greeting:    "mysql-server-greeting\n",
		serverFirst: true,
		peekLenCh:   make(chan int, 1),
	}
	emptyPreambleHandler := &fakeEmptyPreamblePortHandler{
		port:      6380,
		greeting:  "port-fallback-greeting\n",
		peekLenCh: make(chan int, 1),
	}
	rt.RegisterProtocolHandler(emptyPreambleHandler)
	rt.RegisterProtocolHandler(mysqlHandler)

	require.NoError(t, rt.Start(t.Context()))
	defer func() { _ = rt.Close() }()

	start := time.Now()
	conn1, err := net.DialTimeout("tcp4", rt.EgressAddr().String(), 2*time.Second)
	require.NoError(t, err)
	defer conn1.Close()
	_ = conn1.SetDeadline(time.Now().Add(2 * time.Second))

	r1 := bufio.NewReader(conn1)
	greeting, err := r1.ReadString('\n')
	elapsed := time.Since(start)
	require.NoError(t, err)
	assert.Equal(t, "mysql-server-greeting\n", greeting)
	assert.Less(t, elapsed, 100*time.Millisecond, "ServerFirstProtocolHandler must skip the 200ms client peek timeout")
	assert.Equal(t, 0, <-mysqlHandler.peekLenCh)

	_, err = io.WriteString(conn1, "SELECT 1\n")
	require.NoError(t, err)
	ack, err := r1.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "ack:SELECT 1\n", ack)

	targetPort.Store(6380)
	conn2, err := net.DialTimeout("tcp4", rt.EgressAddr().String(), 2*time.Second)
	require.NoError(t, err)
	defer conn2.Close()
	_ = conn2.SetDeadline(time.Now().Add(2 * time.Second))

	r2 := bufio.NewReader(conn2)
	fallbackGreeting, err := r2.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "port-fallback-greeting\n", fallbackGreeting)
	assert.Equal(t, 0, <-emptyPreambleHandler.peekLenCh)
}
