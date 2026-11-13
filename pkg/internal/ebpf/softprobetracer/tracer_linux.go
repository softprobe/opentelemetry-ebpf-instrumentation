// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package softprobetracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/softprobetracer"

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	v2 "github.com/containers/common/pkg/cgroupv2"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/softprobe"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type sp_orig_dst_t -type sp_tuple_key_t -type sp_bypass_key_t -type sp_write_ctx_event_t -type trace_key_t -type tp_info_pid_t -target $BPF_TARGETS Bpf ../../../../bpf/softprobe/sp_redirect.c -- -I../../../../bpf

const (
	cgroupFSRoot   = "/sys/fs/cgroup"
	cgroupV2Hybrid = "/sys/fs/cgroup/unified"
	cgroup2Magic   = 0x63677270
)

type Tracer struct {
	cfg        *obi.Config
	metrics    imetrics.Reporter
	pidsFilter ebpfcommon.ServiceFilter
	log        *slog.Logger

	bpfObjects   BpfObjects
	eventContext *ebpfcommon.EBPFEventContext

	closerMu       sync.Mutex
	closers        []io.Closer
	closed         bool
	cgroupAttached bool
	netnsAttached  bool

	pidsMu   sync.Mutex
	pidKeys  map[app.PID][]uint64
	liveKeys map[uint64]int

	portsMu       sync.RWMutex
	appPorts      map[uint16]uint16
	excludedPorts map[uint16]struct{}

	trackerMu    sync.RWMutex
	writeTracker *softprobe.WriteContextTracker
}

func New(cfg *obi.Config, metrics imetrics.Reporter, pidsFilter ebpfcommon.ServiceFilter) *Tracer {
	if cfg == nil {
		return nil
	}

	tr := &Tracer{
		cfg:           cfg,
		metrics:       metrics,
		pidsFilter:    pidsFilter,
		log:           slog.With("component", "softprobetracer"),
		pidKeys:       make(map[app.PID][]uint64),
		liveKeys:      make(map[uint64]int),
		appPorts:      make(map[uint16]uint16),
		excludedPorts: make(map[uint16]struct{}),
		writeTracker:  softprobe.NewWriteContextTracker(0, 0),
	}

	for _, p := range loopbackExcludedPortsFromConfig(cfg.Softprobe) {
		tr.excludedPorts[p] = struct{}{}
	}

	activeTracer.Store(tr)
	return tr
}

func (p *Tracer) SetWriteTracker(tracker *softprobe.WriteContextTracker) {
	p.trackerMu.Lock()
	p.writeTracker = tracker
	p.trackerMu.Unlock()
}

func (p *Tracer) WriteTracker() *softprobe.WriteContextTracker {
	p.trackerMu.RLock()
	defer p.trackerMu.RUnlock()
	return p.writeTracker
}

func (p *Tracer) LookupOrigDst(remoteAddr net.Addr) (uint64, OrigDst, bool) {
	clientPort, ok := extractRemotePort(remoteAddr)
	if !ok {
		return 0, OrigDst{}, false
	}

	egressPort := p.cfg.Softprobe.EgressProxyPort
	if egressPort <= 0 || egressPort > 65535 {
		return 0, OrigDst{}, false
	}
	if p.bpfObjects.SpTupleToCookie == nil || p.bpfObjects.SpOrigDst == nil {
		return 0, OrigDst{}, false
	}

	tkey := BpfSpTupleKeyT{
		ClientPort: clientPort,
		ProxyPort:  uint16(egressPort),
	}
	var cookie uint64
	if err := p.bpfObjects.SpTupleToCookie.Lookup(&tkey, &cookie); err != nil || cookie == 0 {
		return 0, OrigDst{}, false
	}

	orig, ok := p.LookupOrigDstByCookie(cookie)
	if !ok {
		return 0, OrigDst{}, false
	}
	return cookie, orig, true
}

func (p *Tracer) LookupOrigDstByCookie(sockCookie uint64) (OrigDst, bool) {
	if sockCookie == 0 || p.bpfObjects.SpOrigDst == nil {
		return OrigDst{}, false
	}
	var raw BpfSpOrigDstT
	if err := p.bpfObjects.SpOrigDst.Lookup(&sockCookie, &raw); err != nil {
		return OrigDst{}, false
	}
	return decodeOrigDst(raw.Ip, raw.Port, raw.Family, raw.Pid)
}

func ListenIngress(ctx context.Context, network, address string) (net.Listener, error) {
	var lc net.ListenConfig
	lc.SetMultipathTCP(false)
	return lc.Listen(ctx, network, address)
}

func (p *Tracer) RegisterIngressListener(ln net.Listener) error {
	if ln == nil {
		return errors.New("softprobetracer: nil ingress listener")
	}
	if p.bpfObjects.SpIngressSockmap == nil {
		return errors.New("softprobetracer: sp_ingress_sockmap not loaded")
	}

	sc, ok := ln.(syscall.Conn)
	if !ok {
		return fmt.Errorf("softprobetracer: listener %T does not expose syscall.Conn", ln)
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return fmt.Errorf("softprobetracer: listener syscall conn: %w", err)
	}

	var updateErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		key := uint32(0)
		val := uint64(fd)
		updateErr = p.bpfObjects.SpIngressSockmap.Update(&key, &val, ebpf.UpdateAny)
	})
	if ctrlErr != nil {
		return fmt.Errorf("softprobetracer: listener control: %w", ctrlErr)
	}
	return updateErr
}

func (p *Tracer) RegisterAppPort(appPort uint16) error {
	if appPort == 0 {
		return nil
	}
	p.portsMu.Lock()
	p.appPorts[appPort] = appPort
	m := p.bpfObjects.SpAppPorts
	p.portsMu.Unlock()

	if m != nil {
		val := appPort
		return m.Update(&appPort, &val, ebpf.UpdateAny)
	}
	return nil
}

func (p *Tracer) UnregisterAppPort(appPort uint16) error {
	if appPort == 0 {
		return nil
	}
	p.portsMu.Lock()
	delete(p.appPorts, appPort)
	m := p.bpfObjects.SpAppPorts
	p.portsMu.Unlock()

	if m != nil {
		err := m.Delete(&appPort)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	}
	return nil
}

func (p *Tracer) LookupRelocatedPort(appPort uint16) (uint16, bool) {
	if appPort == 0 {
		return 0, false
	}
	if p.bpfObjects.SpAppPorts != nil {
		var val uint16
		if err := p.bpfObjects.SpAppPorts.Lookup(&appPort, &val); err == nil && val != 0 {
			return val, true
		}
	}
	p.portsMu.RLock()
	val, ok := p.appPorts[appPort]
	p.portsMu.RUnlock()
	return val, ok && val != 0
}

func (p *Tracer) RegisterExcludedPort(port uint16) error {
	if port == 0 {
		return nil
	}
	p.portsMu.Lock()
	p.excludedPorts[port] = struct{}{}
	m := p.bpfObjects.SpExcludedPorts
	p.portsMu.Unlock()

	if m != nil {
		one := uint8(1)
		return m.Update(&port, &one, ebpf.UpdateAny)
	}
	return nil
}

func (p *Tracer) AllowPID(pid app.PID, ns uint32, _ *exec.FileInfo) {
	if uint32(pid) == uint32(os.Getpid()) {
		return
	}

	keys := []uint64{
		uint64(uint32(pid)),
		pidKey(ns, uint32(pid)),
	}
	if nsPids, err := procs.FindNamespacedPids(pid); err == nil {
		for _, nsPid := range nsPids {
			keys = append(keys, pidKey(ns, uint32(nsPid)))
		}
	}

	p.pidsMu.Lock()
	for _, oldKey := range p.pidKeys[pid] {
		p.decrementKeyLocked(oldKey)
	}
	unique := make([]uint64, 0, len(keys))
	seen := make(map[uint64]struct{}, len(keys))
	for _, k := range keys {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		unique = append(unique, k)
		p.liveKeys[k]++
		if p.bpfObjects.SpTargetPids != nil {
			one := uint8(1)
			if err := p.bpfObjects.SpTargetPids.Update(&k, &one, ebpf.UpdateAny); err != nil {
				p.log.Debug("failed updating sp_target_pids", "key", k, "error", err)
			}
		}
	}
	p.pidKeys[pid] = unique
	p.pidsMu.Unlock()

	if p.cfg.Softprobe.IngressProxyPort > 0 {
		for _, port := range discoverListeningTCPPorts(uint32(pid)) {
			if !p.isExcludedPort(port) {
				_ = p.RegisterAppPort(port)
			}
		}
	}
}

func (p *Tracer) BlockPID(pid app.PID, ns uint32) {
	p.pidsMu.Lock()
	defer p.pidsMu.Unlock()

	keys, ok := p.pidKeys[pid]
	if !ok {
		keys = []uint64{uint64(uint32(pid)), pidKey(ns, uint32(pid))}
	}
	delete(p.pidKeys, pid)

	for _, k := range keys {
		p.decrementKeyLocked(k)
	}
}

func (p *Tracer) decrementKeyLocked(k uint64) {
	cnt := p.liveKeys[k]
	if cnt <= 1 {
		delete(p.liveKeys, k)
		if p.bpfObjects.SpTargetPids != nil {
			if err := p.bpfObjects.SpTargetPids.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				p.log.Debug("failed deleting sp_target_pids key", "key", k, "error", err)
			}
		}
		return
	}
	p.liveKeys[k] = cnt - 1
}

func (p *Tracer) isExcludedPort(port uint16) bool {
	if port == 0 ||
		int(port) == p.cfg.Softprobe.IngressProxyPort ||
		int(port) == p.cfg.Softprobe.EgressProxyPort {
		return true
	}
	p.portsMu.RLock()
	_, excluded := p.excludedPorts[port]
	p.portsMu.RUnlock()
	return excluded
}

func (p *Tracer) syncConfiguredState() error {
	p.portsMu.RLock()
	excluded := make([]uint16, 0, len(p.excludedPorts))
	for port := range p.excludedPorts {
		excluded = append(excluded, port)
	}
	appPorts := make(map[uint16]uint16, len(p.appPorts))
	maps.Copy(appPorts, p.appPorts)
	p.portsMu.RUnlock()

	if p.bpfObjects.SpExcludedPorts != nil {
		one := uint8(1)
		for _, port := range excluded {
			if err := p.bpfObjects.SpExcludedPorts.Update(&port, &one, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("syncing sp_excluded_ports %d: %w", port, err)
			}
		}
	}

	if p.bpfObjects.SpAppPorts != nil {
		for appPort, targetPort := range appPorts {
			ap := appPort
			tp := targetPort
			if err := p.bpfObjects.SpAppPorts.Update(&ap, &tp, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("syncing sp_app_ports %d: %w", appPort, err)
			}
		}
	}

	p.pidsMu.Lock()
	keys := make([]uint64, 0, len(p.liveKeys))
	for k := range p.liveKeys {
		keys = append(keys, k)
	}
	p.pidsMu.Unlock()

	if p.bpfObjects.SpTargetPids != nil {
		one := uint8(1)
		for _, k := range keys {
			key := k
			if err := p.bpfObjects.SpTargetPids.Update(&key, &one, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("syncing sp_target_pids %d: %w", key, err)
			}
		}
	}

	return nil
}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}

	return []*ebpfcommon.SpecBundle{{
		Spec:      spec,
		Objects:   &p.bpfObjects,
		Constants: p.constants(),
	}}, nil
}

func (p *Tracer) LoadStandalone(sharedMaps map[string]*ebpf.Map, mu *sync.Mutex) error {
	spec, err := LoadBpf()
	if err != nil {
		return err
	}
	for _, mSpec := range spec.Maps {
		if mSpec.Pinning == ebpf.PinByName {
			mSpec.Pinning = ebpfconvenience.PinInternal
		}
	}
	if sharedMaps == nil {
		sharedMaps = make(map[string]*ebpf.Map)
	}
	if mu == nil {
		mu = &sync.Mutex{}
	}
	if err := ebpfconvenience.LoadSpec(spec, &p.bpfObjects, p.constants(), sharedMaps, mu, "", nil); err != nil {
		return err
	}
	p.AddCloser(&p.bpfObjects)
	return p.syncConfiguredState()
}

func (p *Tracer) AttachKProbesStandalone() error {
	for sym, desc := range p.KProbes() {
		if desc.Start == nil {
			continue
		}
		kp, err := link.Kprobe(sym, desc.Start, nil)
		if err != nil {
			if desc.Required {
				return fmt.Errorf("attaching kprobe %s: %w", sym, err)
			}
			p.log.Warn("optional kprobe attach failed", "symbol", sym, "error", err)
			continue
		}
		p.AddCloser(kp)
	}
	return nil
}

func (p *Tracer) AttachCgroup(cgroupPath string) error {
	if err := p.syncConfiguredState(); err != nil {
		return err
	}

	p.closerMu.Lock()
	if p.cgroupAttached {
		p.closerMu.Unlock()
		return nil
	}
	p.closerMu.Unlock()

	type cgroupProg struct {
		name   string
		prog   *ebpf.Program
		attach ebpf.AttachType
	}
	progs := []cgroupProg{
		{name: "sp_connect4", prog: p.bpfObjects.SpConnect4, attach: ebpf.AttachCGroupInet4Connect},
		{name: "sp_connect6", prog: p.bpfObjects.SpConnect6, attach: ebpf.AttachCGroupInet6Connect},
		{name: "sp_getpeername4", prog: p.bpfObjects.SpGetpeername4, attach: ebpf.AttachCgroupInet4GetPeername},
		{name: "sp_getpeername6", prog: p.bpfObjects.SpGetpeername6, attach: ebpf.AttachCgroupInet6GetPeername},
		{name: "sp_post_bind4", prog: p.bpfObjects.SpPostBind4, attach: ebpf.AttachCGroupInet4PostBind},
		{name: "sp_post_bind6", prog: p.bpfObjects.SpPostBind6, attach: ebpf.AttachCGroupInet6PostBind},
		{name: "sp_sockops", prog: p.bpfObjects.SpSockops, attach: ebpf.AttachCGroupSockOps},
	}

	resolvedPath, mfd, err := resolveCgroupTarget(cgroupPath)
	if err != nil {
		return err
	}
	if mfd >= 0 {
		p.AddCloser(fdCloser(mfd))
	}

	for _, cp := range progs {
		if cp.prog == nil {
			return fmt.Errorf("softprobetracer: program %s not loaded", cp.name)
		}
		var l link.Link
		if resolvedPath != "" {
			l, err = link.AttachCgroup(link.CgroupOptions{
				Path:    resolvedPath,
				Program: cp.prog,
				Attach:  cp.attach,
			})
		} else {
			l, err = link.AttachRawLink(link.RawLinkOptions{
				Target:  mfd,
				Program: cp.prog,
				Attach:  cp.attach,
			})
		}
		if err != nil {
			return fmt.Errorf("attaching %s: %w", cp.name, err)
		}
		p.AddCloser(l)
	}

	p.closerMu.Lock()
	p.cgroupAttached = true
	p.closerMu.Unlock()
	return nil
}

func (p *Tracer) AttachNetNS(netnsPath string) error {
	if p.cfg.Softprobe.IngressProxyPort <= 0 {
		return nil
	}
	if p.bpfObjects.SpSkLookup == nil {
		return errors.New("softprobetracer: sp_sk_lookup program not loaded")
	}

	p.closerMu.Lock()
	if p.netnsAttached {
		p.closerMu.Unlock()
		return nil
	}
	p.closerMu.Unlock()

	if netnsPath == "" {
		netnsPath = "/proc/self/ns/net"
	}
	nsFile, err := os.Open(netnsPath)
	if err != nil {
		return fmt.Errorf("opening netns %s: %w", netnsPath, err)
	}
	defer nsFile.Close()

	l, err := link.AttachNetNs(int(nsFile.Fd()), p.bpfObjects.SpSkLookup)
	if err != nil {
		return fmt.Errorf("attaching sp_sk_lookup to %s: %w", netnsPath, err)
	}
	p.AddCloser(l)

	p.closerMu.Lock()
	p.netnsAttached = true
	p.closerMu.Unlock()
	return nil
}

func (p *Tracer) constants() map[string]any {
	filterPids := int32(1)
	if p.cfg.Discovery.BPFPidFilterOff {
		filterPids = 0
	}

	hostPID, nsPID, nsID := currentProcessIdentity()
	ingressPort := uint16(0)
	if p.cfg.Softprobe.IngressProxyPort > 0 && p.cfg.Softprobe.IngressProxyPort <= 65535 {
		ingressPort = uint16(p.cfg.Softprobe.IngressProxyPort)
	}
	egressPort := uint16(0)
	if p.cfg.Softprobe.EgressProxyPort > 0 && p.cfg.Softprobe.EgressProxyPort <= 65535 {
		egressPort = uint16(p.cfg.Softprobe.EgressProxyPort)
	}

	m := map[string]any{
		"filter_pids":           filterPids,
		"max_transaction_time":  uint64(p.cfg.EBPF.MaxTransactionTime.Nanoseconds()),
		"g_bpf_debug":           p.cfg.EBPF.BpfDebug,
		"sp_obi_host_pid":       hostPID,
		"sp_obi_ns_pid":         nsPID,
		"sp_obi_ns_id":          nsID,
		"sp_ingress_proxy_port": ingressPort,
		"sp_egress_proxy_port":  egressPort,
	}
	maps.Copy(m, ebpfcommon.PIDFilterConstants())
	return m
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closerMu.Lock()
	if p.closed {
		p.closerMu.Unlock()
		closeReverse(c)
		return
	}
	p.closers = append(p.closers, c...)
	p.closerMu.Unlock()
}

func (p *Tracer) Close() error {
	p.closerMu.Lock()
	if p.closed {
		p.closerMu.Unlock()
		return nil
	}
	p.closed = true
	closers := p.closers
	p.closers = nil
	p.closerMu.Unlock()

	activeTracer.CompareAndSwap(p, nil)
	closeReverse(closers)
	return nil
}

func closeReverse(closers []io.Closer) {
	for _, c := range slices.Backward(closers) {
		if c != nil {
			_ = c.Close()
		}
	}
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc { return nil }

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	return map[string]ebpfcommon.ProbeDesc{
		"tcp_connect": {
			Start:    p.bpfObjects.SpKprobeTcpConnect,
			Required: true,
		},
		"tcp_sendmsg": {
			Start:    p.bpfObjects.SpKprobeTcpSendmsg,
			Required: true,
		},
	}
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc           { return nil }
func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc { return nil }
func (p *Tracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc     { return nil }
func (p *Tracer) SocketFilters() []*ebpf.Program                         { return nil }
func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg                         { return nil }
func (p *Tracer) SockOps() []ebpfcommon.SockOps                          { return nil }
func (p *Tracer) Iters() []*ebpfcommon.Iter                              { return nil }
func (p *Tracer) Tracing() []*ebpfcommon.Tracing                         { return nil }
func (p *Tracer) RecordInstrumentedLib(_ uint64, _ []io.Closer)          {}
func (p *Tracer) AddInstrumentedLibRef(_ uint64)                         {}
func (p *Tracer) UnlinkInstrumentedLib(_ uint64)                         {}
func (p *Tracer) AlreadyInstrumentedLib(_ uint64) bool                   { return false }
func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets)    {}
func (p *Tracer) ProcessBinary(_ *exec.FileInfo)                         {}
func (p *Tracer) SetEventContext(ctx *ebpfcommon.EBPFEventContext)       { p.eventContext = ctx }
func (p *Tracer) Capabilities() ebpfcommon.TracerCapability              { return 0 }
func (p *Tracer) Required() bool                                         { return false }

func (p *Tracer) Run(ctx context.Context, _ *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
	p.AddCloser(&p.bpfObjects)
	defer func() { _ = p.Close() }()

	if err := p.syncConfiguredState(); err != nil {
		p.log.Error("failed syncing softprobe BPF maps", "error", err)
		return
	}

	if err := p.AttachCgroup(p.cfg.EBPF.CgroupFSPath); err != nil {
		p.log.Error("failed attaching softprobe cgroup programs", "error", err)
		return
	}

	if p.cfg.Softprobe.IngressProxyPort > 0 {
		if err := p.AttachNetNS("/proc/self/ns/net"); err != nil {
			p.log.Warn("failed attaching softprobe sk_lookup program", "error", err)
		}
	}

	if p.bpfObjects.SpWriteCtxEvents == nil {
		<-ctx.Done()
		return
	}

	reader, err := ringbuf.NewReader(p.bpfObjects.SpWriteCtxEvents)
	if err != nil {
		p.log.Error("failed creating sp_write_ctx_events ringbuf reader", "error", err)
		return
	}

	var stopWG sync.WaitGroup
	stopWG.Go(func() {
		<-ctx.Done()
		_ = reader.Close()
	})
	defer stopWG.Wait()

	var rec ringbuf.Record
	for {
		if err := reader.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return
			}
			p.log.Debug("error reading sp_write_ctx_events ringbuf", "error", err)
			continue
		}
		p.recordWriteEvent(rec.RawSample)
	}
}

func (p *Tracer) recordWriteEvent(raw []byte) {
	ev, err := ebpfcommon.ReinterpretCast[BpfSpWriteCtxEventT](raw)
	if err != nil {
		return
	}
	tracker := p.WriteTracker()
	if tracker == nil {
		return
	}

	tracker.RecordWrite(softprobe.SocketWriteContext{
		SockCookie:   ev.SockCookie,
		ByteOffset:   ev.ByteOffset,
		PayloadLen:   ev.PayloadLen,
		TraceID:      ev.TraceId,
		ServerSpanID: ev.SpanId,
		RecordedAt:   time.Now(),
	})
}

func pidKey(nsid, pid uint32) uint64 {
	return (uint64(nsid) << 32) | uint64(pid)
}

func currentProcessIdentity() (hostPID uint32, nsPID uint32, nsID uint32) {
	nsPID = uint32(os.Getpid())
	hostPID = nsPID

	if target, err := os.Readlink("/proc/self"); err == nil {
		if parsed, err := strconv.ParseUint(filepath.Base(target), 10, 32); err == nil && parsed > 0 {
			hostPID = uint32(parsed)
		}
	}
	if st, err := os.Stat("/proc/self/ns/pid"); err == nil {
		if sysSt, ok := st.Sys().(*syscall.Stat_t); ok {
			nsID = uint32(sysSt.Ino)
		}
	}
	return hostPID, nsPID, nsID
}

type fdCloser int

func (fd fdCloser) Close() error {
	if fd < 0 {
		return nil
	}
	return unix.Close(int(fd))
}

func resolveCgroupTarget(cgroupPath string) (string, int, error) {
	if cgroupPath != "" {
		if !isCgroup2Path(cgroupPath) {
			return "", -1, fmt.Errorf("%s is not a cgroupv2 directory", cgroupPath)
		}
		return cgroupPath, -1, nil
	}
	if enabled, err := v2.Enabled(); err == nil && enabled && isCgroup2Path(cgroupFSRoot) {
		return cgroupFSRoot, -1, nil
	}
	if isCgroup2Path(cgroupV2Hybrid) {
		return cgroupV2Hybrid, -1, nil
	}

	fsfd, err := unix.Fsopen("cgroup2", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return "", -1, fmt.Errorf("cgroupv2 fsopen: %w", err)
	}
	defer unix.Close(fsfd)
	if err := unix.FsconfigCreate(fsfd); err != nil {
		return "", -1, fmt.Errorf("cgroupv2 fsconfig: %w", err)
	}
	mfd, err := unix.Fsmount(fsfd, unix.FSMOUNT_CLOEXEC, 0)
	if err != nil {
		return "", -1, fmt.Errorf("cgroupv2 fsmount: %w", err)
	}
	return "", mfd, nil
}

func isCgroup2Path(path string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false
	}
	return st.Type == cgroup2Magic
}

func discoverListeningTCPPorts(pid uint32) []uint16 {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}

	inodes := make(map[string]struct{})
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		if inode, ok := strings.CutPrefix(target, "socket:["); ok {
			if inode, ok := strings.CutSuffix(inode, "]"); ok && inode != "" {
				inodes[inode] = struct{}{}
			}
		}
	}
	if len(inodes) == 0 {
		return nil
	}

	seenPorts := make(map[uint16]struct{})
	for _, table := range []string{"tcp", "tcp6"} {
		for _, port := range parseProcNetTCPListeners(fmt.Sprintf("/proc/%d/net/%s", pid, table), inodes) {
			seenPorts[port] = struct{}{}
		}
	}

	ports := make([]uint16, 0, len(seenPorts))
	for port := range seenPorts {
		ports = append(ports, port)
	}
	return ports
}

func parseProcNetTCPListeners(path string, socketInodes map[string]struct{}) []uint16 {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var ports []uint16
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		// st == 0A is TCP_LISTEN in /proc/net/tcp{,6}.
		if !strings.EqualFold(fields[3], "0A") {
			continue
		}
		if _, ok := socketInodes[fields[9]]; !ok {
			continue
		}
		_, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		portVal, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil || portVal == 0 {
			continue
		}
		ports = append(ports, uint16(portVal))
	}
	return ports
}
