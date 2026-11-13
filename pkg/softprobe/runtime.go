// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultHeartbeatInterval = 30 * time.Second
	defaultHeartbeatTimeout  = 5 * time.Second
)

type RuntimeOption func(*Runtime)

func WithRuntimeCACertPath(path string) RuntimeOption {
	return func(r *Runtime) {
		r.caCertPath = path
	}
}

func WithRuntimeReplayRegistry(reg *ReplayRegistry) RuntimeOption {
	return func(r *Runtime) {
		if reg != nil {
			r.replayRegistry = reg
		}
	}
}

func WithRuntimeDataplaneBridge(bridge *DataplaneBridge) RuntimeOption {
	return func(r *Runtime) {
		if bridge != nil {
			r.bridge = bridge
		}
	}
}

func WithRuntimeBackendClient(client *BackendClient) RuntimeOption {
	return func(r *Runtime) {
		r.backendClient = client
	}
}

func WithRuntimeLogExporter(exp *LogExporter) RuntimeOption {
	return func(r *Runtime) {
		r.logExporter = exp
	}
}

func WithRuntimeIngressOptions(opts ...IngressOption) RuntimeOption {
	return func(r *Runtime) {
		r.ingressOpts = append(r.ingressOpts, opts...)
	}
}

func WithRuntimeHTTPHandlerOptions(opts ...HTTPHandlerOption) RuntimeOption {
	return func(r *Runtime) {
		r.httpOpts = append(r.httpOpts, opts...)
	}
}

func WithRuntimePostgresHandlerOptions(opts ...PostgresHandlerOption) RuntimeOption {
	return func(r *Runtime) {
		r.postgresOpts = append(r.postgresOpts, opts...)
	}
}

func WithRuntimeMySQLHandlerOptions(opts ...MySQLHandlerOption) RuntimeOption {
	return func(r *Runtime) {
		r.mysqlOpts = append(r.mysqlOpts, opts...)
	}
}

func WithRuntimeRedisHandlerOptions(opts ...RedisHandlerOption) RuntimeOption {
	return func(r *Runtime) {
		r.redisOpts = append(r.redisOpts, opts...)
	}
}

func WithRuntimeHeartbeatInterval(d time.Duration) RuntimeOption {
	return func(r *Runtime) {
		if d > 0 {
			r.heartbeatInterval = d
		}
	}
}

func WithRuntimeEgressTargetResolver(fn func(remoteAddr net.Addr) (EgressTarget, bool)) RuntimeOption {
	return func(r *Runtime) {
		r.resolveEgressTarget = fn
	}
}

type Runtime struct {
	cfg                 Config
	caCertPath          string
	ca                  *EphemeralCA
	replayRegistry      *ReplayRegistry
	bridge              *DataplaneBridge
	backendClient       *BackendClient
	logExporter         *LogExporter
	ingress             *IngressListener
	httpHandler         *HTTPProtocolHandler
	postgresHandler     *PostgresProtocolHandler
	mysqlHandler        *MySQLProtocolHandler
	redisHandler        *RedisProtocolHandler
	handlersMu          sync.RWMutex
	handlers            []OutgoingProtocolHandler
	ingressOpts         []IngressOption
	httpOpts            []HTTPHandlerOption
	postgresOpts        []PostgresHandlerOption
	mysqlOpts           []MySQLHandlerOption
	redisOpts           []RedisHandlerOption
	resolveEgressTarget func(remoteAddr net.Addr) (EgressTarget, bool)
	heartbeatInterval   time.Duration
	dialRaw             func(ctx context.Context, network, address string) (net.Conn, error)
	log                 *slog.Logger

	mu          sync.Mutex
	egressLns   []net.Listener
	activeConns map[net.Conn]struct{}
	closing     bool
	wg          sync.WaitGroup
	stopOnce    sync.Once
	stopped     chan struct{}
	wroteCAFile bool
}

func NewRuntime(cfg Config, opts ...RuntimeOption) (*Runtime, error) {
	cfg = cfg.WithDefaults()
	var dialer net.Dialer
	dialer.Timeout = defaultUpstreamDialTTL
	dialer.SetMultipathTCP(false)

	rt := &Runtime{
		cfg:               cfg,
		caCertPath:        DefaultCACertPath,
		replayRegistry:    SharedReplayRegistry(),
		bridge:            SharedDataplaneBridge(),
		heartbeatInterval: defaultHeartbeatInterval,
		dialRaw:           dialer.DialContext,
		log:               slog.With("component", "softprobe.Runtime"),
		activeConns:       make(map[net.Conn]struct{}),
		stopped:           make(chan struct{}),
	}
	for _, opt := range opts {
		opt(rt)
	}

	if rt.backendClient == nil && rt.cfg.BackendURL != "" {
		bc, err := NewBackendClient(rt.cfg.BackendURL)
		if err != nil {
			return nil, fmt.Errorf("initializing softprobe backend client: %w", err)
		}
		rt.backendClient = bc
	}
	if rt.logExporter == nil {
		rt.logExporter = NewLogExporter(rt.cfg, rt.replayRegistry)
	}

	ca, err := NewEphemeralCA()
	if err != nil {
		return nil, err
	}
	rt.ca = ca

	httpOpts := make([]HTTPHandlerOption, 0, len(rt.httpOpts)+2)
	httpOpts = append(httpOpts, WithHTTPExchangeCache(rt.bridge.ExchangeCache()))
	if rt.logExporter != nil {
		httpOpts = append(httpOpts, WithHTTPLogExporter(rt.logExporter))
	}
	httpOpts = append(httpOpts, rt.httpOpts...)

	rt.httpHandler = NewHTTPProtocolHandler(
		rt.cfg,
		rt.ca,
		rt.replayRegistry,
		rt.bridge.WriteTracker(),
		rt.backendClient,
		httpOpts...,
	)

	postgresOpts := make([]PostgresHandlerOption, 0, len(rt.postgresOpts)+2)
	postgresOpts = append(postgresOpts, WithPostgresExchangeCache(rt.bridge.ExchangeCache()))
	if rt.logExporter != nil {
		postgresOpts = append(postgresOpts, WithPostgresLogExporter(rt.logExporter))
	}
	postgresOpts = append(postgresOpts, rt.postgresOpts...)
	rt.postgresHandler = NewPostgresProtocolHandler(
		rt.cfg,
		rt.replayRegistry,
		rt.bridge.WriteTracker(),
		rt.backendClient,
		postgresOpts...,
	)

	mysqlOpts := make([]MySQLHandlerOption, 0, len(rt.mysqlOpts)+2)
	mysqlOpts = append(mysqlOpts, WithMySQLExchangeCache(rt.bridge.ExchangeCache()))
	if rt.logExporter != nil {
		mysqlOpts = append(mysqlOpts, WithMySQLLogExporter(rt.logExporter))
	}
	mysqlOpts = append(mysqlOpts, rt.mysqlOpts...)
	rt.mysqlHandler = NewMySQLProtocolHandler(
		rt.cfg,
		rt.replayRegistry,
		rt.bridge.WriteTracker(),
		rt.backendClient,
		mysqlOpts...,
	)

	redisOpts := make([]RedisHandlerOption, 0, len(rt.redisOpts)+2)
	redisOpts = append(redisOpts, WithRedisExchangeCache(rt.bridge.ExchangeCache()))
	if rt.logExporter != nil {
		redisOpts = append(redisOpts, WithRedisLogExporter(rt.logExporter))
	}
	redisOpts = append(redisOpts, rt.redisOpts...)
	rt.redisHandler = NewRedisProtocolHandler(
		rt.cfg,
		rt.replayRegistry,
		rt.bridge.WriteTracker(),
		rt.backendClient,
		redisOpts...,
	)

	rt.handlers = []OutgoingProtocolHandler{
		rt.mysqlHandler,
		rt.postgresHandler,
		rt.redisHandler,
		rt.httpHandler,
	}

	if rt.cfg.IngressProxyPort > 0 {
		ingressOpts := make([]IngressOption, 0, len(rt.ingressOpts)+1)
		if rt.logExporter != nil {
			ingressOpts = append(ingressOpts, WithIngressLogExporter(rt.logExporter))
		}
		ingressOpts = append(ingressOpts, rt.ingressOpts...)
		rt.ingress = NewIngressListener(
			rt.cfg,
			rt.replayRegistry,
			rt.backendClient,
			rt.bridge,
			ingressOpts...,
		)
	}

	return rt, nil
}

func (r *Runtime) RegisterProtocolHandler(handler OutgoingProtocolHandler) {
	if handler == nil {
		return
	}
	r.handlersMu.Lock()
	r.handlers = append([]OutgoingProtocolHandler{handler}, r.handlers...)
	r.handlersMu.Unlock()
}

func (r *Runtime) CA() *EphemeralCA {
	return r.ca
}

func (r *Runtime) HTTPHandler() *HTTPProtocolHandler {
	return r.httpHandler
}

func (r *Runtime) PostgresHandler() *PostgresProtocolHandler {
	return r.postgresHandler
}

func (r *Runtime) MySQLHandler() *MySQLProtocolHandler {
	return r.mysqlHandler
}

func (r *Runtime) RedisHandler() *RedisProtocolHandler {
	return r.redisHandler
}

func (r *Runtime) LogExporter() *LogExporter {
	return r.logExporter
}

func (r *Runtime) IngressAddr() net.Addr {
	if r.ingress == nil {
		return nil
	}
	return r.ingress.Addr()
}

func (r *Runtime) EgressAddr() net.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.egressLns) == 0 {
		return nil
	}
	return r.egressLns[0].Addr()
}

func (r *Runtime) Start(ctx context.Context) error {
	if !r.cfg.Enabled {
		return nil
	}

	SetActiveCAPEM(r.ca.CAPEM())
	if r.caCertPath != "" {
		if err := r.ca.WritePEMFile(r.caCertPath); err != nil {
			r.log.Warn("failed writing softprobe ephemeral CA file", "path", r.caCertPath, "error", err)
		} else {
			r.wroteCAFile = true
		}
	}

	if r.ingress != nil {
		if err := r.ingress.Start(ctx); err != nil {
			SetActiveCAPEM(nil)
			return err
		}
	}

	if r.cfg.EgressProxyPort > 0 {
		if err := r.startEgressListeners(ctx); err != nil {
			if r.ingress != nil {
				_ = r.ingress.Close()
			}
			SetActiveCAPEM(nil)
			return err
		}
	}

	if r.backendClient != nil && r.cfg.AppID != "" {
		r.wg.Go(func() {
			r.heartbeatLoop(ctx)
		})
	}

	return nil
}

func (r *Runtime) Run(ctx context.Context) error {
	if err := r.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	return r.Close()
}

func (r *Runtime) Close() error {
	var (
		errs         []error
		closeBackend bool
	)
	r.stopOnce.Do(func() {
		closeBackend = true
		close(r.stopped)
		SetActiveCAPEM(nil)
		if r.ingress != nil {
			if err := r.ingress.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		r.mu.Lock()
		r.closing = true
		lns := r.egressLns
		r.egressLns = nil
		conns := make([]net.Conn, 0, len(r.activeConns))
		for c := range r.activeConns {
			conns = append(conns, c)
		}
		r.activeConns = nil
		r.mu.Unlock()
		for _, ln := range lns {
			if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
		for _, c := range conns {
			_ = c.Close()
		}
		if r.httpHandler != nil {
			r.httpHandler.Close()
		}
		if r.wroteCAFile && r.caCertPath != "" {
			_ = os.Remove(r.caCertPath)
		}
	})
	r.wg.Wait()
	if closeBackend {
		if r.logExporter != nil {
			closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = r.logExporter.Close(closeCtx)
			cancel()
		}
		if r.backendClient != nil {
			r.backendClient.Close()
		}
	}
	return errors.Join(errs...)
}

func (r *Runtime) startEgressListeners(ctx context.Context) error {
	v4Addr := fmt.Sprintf("127.0.0.1:%d", r.cfg.EgressProxyPort)
	ln4, err := ListenNonMPTCP(ctx, "tcp4", v4Addr)
	if err != nil {
		return fmt.Errorf("listening on softprobe egress %s: %w", v4Addr, err)
	}
	boundPort := extractPortFromAddr(ln4.Addr())
	lns := []net.Listener{ln4}

	if boundPort > 0 {
		v6Addr := fmt.Sprintf("[::1]:%d", boundPort)
		if ln6, err6 := ListenNonMPTCP(ctx, "tcp6", v6Addr); err6 == nil {
			lns = append(lns, ln6)
		}
	}

	r.mu.Lock()
	r.egressLns = lns
	r.mu.Unlock()

	for _, ln := range lns {
		r.wg.Add(1)
		go func(listener net.Listener) {
			defer r.wg.Done()
			r.acceptEgressLoop(ctx, listener)
		}(ln)
	}
	return nil
}

func (r *Runtime) trackEgressConn(c net.Conn, add bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if add {
		if r.closing || r.activeConns == nil {
			return false
		}
		r.activeConns[c] = struct{}{}
		return true
	}
	if r.activeConns != nil {
		delete(r.activeConns, c)
	}
	return true
}

func (r *Runtime) acceptEgressLoop(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-r.stopped:
				return
			case <-ctx.Done():
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			r.log.Debug("softprobe egress accept error", "error", err)
			continue
		}

		if !r.trackEgressConn(conn, true) {
			_ = conn.Close()
			return
		}

		r.wg.Add(1)
		go func(c net.Conn) {
			defer r.wg.Done()
			defer r.trackEgressConn(c, false)
			r.handleEgressConn(ctx, c)
		}(conn)
	}
}

func (r *Runtime) lookupEgressTarget(remoteAddr net.Addr) (EgressTarget, bool) {
	if r.resolveEgressTarget != nil {
		return r.resolveEgressTarget(remoteAddr)
	}
	return r.bridge.LookupEgressTarget(remoteAddr)
}

func (r *Runtime) handleEgressConn(ctx context.Context, rawConn net.Conn) {
	defer func() { _ = rawConn.Close() }()

	target, ok := r.lookupEgressTarget(rawConn.RemoteAddr())
	if !ok || !target.AddrPort.IsValid() {
		r.log.Debug("dropping egress connection without original destination", "remote", rawConn.RemoteAddr())
		return
	}

	origPort := target.AddrPort.Port()
	r.handlersMu.RLock()
	handlers := slices.Clone(r.handlers)
	r.handlersMu.RUnlock()

	serverFirst := false
	for _, handler := range handlers {
		if sf, ok := handler.(ServerFirstProtocolHandler); ok && sf.IsServerFirstPort(origPort) {
			serverFirst = true
			break
		}
	}

	cc := NewCountingConn(rawConn)
	br := bufio.NewReaderSize(cc, defaultProxyBufSize)

	var peek []byte
	if !serverFirst {
		_ = rawConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		peek, _ = br.Peek(min(defaultProxyBufSize, 8))
		_ = rawConn.SetReadDeadline(time.Time{})
	}

	oc := OutgoingConnectionContext{
		ClientConn: cc,
		BufReader:  br,
		SockCookie: target.SockCookie,
		OrigDst:    target.AddrPort,
		CallerPID:  target.PID,
	}

	for _, handler := range handlers {
		if handler.CanHandle(peek, origPort) {
			if err := handler.HandleConnection(ctx, oc); err != nil {
				r.log.Debug("egress protocol handler finished with error", "handler", handler.Name(), "orig_dst", target.AddrPort, "error", err)
			}
			return
		}
	}

	upConn, err := r.dialRaw(ctx, "tcp", target.AddrPort.String())
	if err != nil {
		r.log.Debug("failed dialing original destination for TCP passthrough", "orig_dst", target.AddrPort, "error", err)
		return
	}
	defer func() { _ = upConn.Close() }()
	spliceConnections(cc, br, upConn)
}

func (r *Runtime) heartbeatLoop(ctx context.Context) {
	host, _ := os.Hostname()
	send := func(status string) {
		hbCtx, cancel := context.WithTimeout(context.Background(), defaultHeartbeatTimeout)
		defer cancel()
		_, err := r.backendClient.SendAgentStatus(hbCtx, AgentStatusPayload{
			AppID:       r.cfg.AppID,
			Host:        host,
			CurrentRate: strconv.FormatFloat(r.cfg.RecordRate, 'f', -1, 64),
			AgentStatus: status,
		})
		if err != nil {
			r.log.Debug("failed sending softprobe agent heartbeat", "status", status, "error", err)
		}
	}

	r.bootstrapAgentLoad(host)
	send("START")
	ticker := time.NewTicker(r.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			send("SHUTDOWN")
			return
		case <-r.stopped:
			send("SHUTDOWN")
			return
		case <-ticker.C:
			send("WORKING")
		}
	}
}

func (r *Runtime) bootstrapAgentLoad(host string) {
	baseURL := strings.TrimRight(strings.TrimSpace(r.cfg.BackendURL), "/")
	appID := strings.TrimSpace(r.cfg.AppID)
	if baseURL == "" || appID == "" {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"appId":         appID,
		"host":          host,
		"recordVersion": defaultRecordVersion,
		"agentStatus":   "WORKING",
		"status":        1,
	})
	if err != nil {
		return
	}
	loadCtx, cancel := context.WithTimeout(context.Background(), defaultHeartbeatTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(loadCtx, http.MethodPost, baseURL+"/api/config/agent/load", bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.log.Debug("failed bootstrapping softprobe agent config", "error", err)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
}
