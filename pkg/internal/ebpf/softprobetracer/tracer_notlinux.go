// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package softprobetracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/softprobetracer"

import (
	"context"
	"io"
	"net"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/softprobe"
)

type Tracer struct{}

func ListenIngress(ctx context.Context, network, address string) (net.Listener, error) {
	var lc net.ListenConfig
	lc.SetMultipathTCP(false)
	return lc.Listen(ctx, network, address)
}

func New(_ *obi.Config, _ imetrics.Reporter, _ ebpfcommon.ServiceFilter) *Tracer { return nil }
func (p *Tracer) SetWriteTracker(_ *softprobe.WriteContextTracker)               {}
func (p *Tracer) WriteTracker() *softprobe.WriteContextTracker                   { return nil }
func (p *Tracer) LookupOrigDst(_ net.Addr) (uint64, OrigDst, bool)               { return 0, OrigDst{}, false }
func (p *Tracer) LookupEgressTarget(_ net.Addr) (softprobe.EgressTarget, bool) {
	return softprobe.EgressTarget{}, false
}
func (p *Tracer) LookupOrigDstByCookie(_ uint64) (OrigDst, bool)                 { return OrigDst{}, false }
func (p *Tracer) RegisterIngressListener(_ net.Listener) error                   { return nil }
func (p *Tracer) RegisterAppPort(_ uint16) error                                 { return nil }
func (p *Tracer) UnregisterAppPort(_ uint16) error                               { return nil }
func (p *Tracer) LookupRelocatedPort(_ uint16) (uint16, bool)                    { return 0, false }
func (p *Tracer) RegisterExcludedPort(_ uint16) error                            { return nil }
func (p *Tracer) AllowPID(_ app.PID, _ uint32, _ *exec.FileInfo)                 {}
func (p *Tracer) BlockPID(_ app.PID, _ uint32)                                   {}
func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error)                   { return nil, nil }
func (p *Tracer) AddCloser(_ ...io.Closer)                                       {}
func (p *Tracer) Close() error                                                   { return nil }
func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc                   { return nil }
func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc                       { return nil }
func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc         { return nil }
func (p *Tracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc             { return nil }
func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc                   { return nil }
func (p *Tracer) SocketFilters() []*ebpf.Program                                 { return nil }
func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg                                 { return nil }
func (p *Tracer) SockOps() []ebpfcommon.SockOps                                  { return nil }
func (p *Tracer) Iters() []*ebpfcommon.Iter                                      { return nil }
func (p *Tracer) Tracing() []*ebpfcommon.Tracing                                 { return nil }
func (p *Tracer) RecordInstrumentedLib(_ uint64, _ []io.Closer)                  {}
func (p *Tracer) AddInstrumentedLibRef(_ uint64)                                 {}
func (p *Tracer) UnlinkInstrumentedLib(_ uint64)                                 {}
func (p *Tracer) AlreadyInstrumentedLib(_ uint64) bool                           { return false }
func (p *Tracer) Run(_ context.Context, _ *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
}
func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}
func (p *Tracer) ProcessBinary(_ *exec.FileInfo)                      {}
func (p *Tracer) SetEventContext(_ *ebpfcommon.EBPFEventContext)      {}
func (p *Tracer) Capabilities() ebpfcommon.TracerCapability           { return 0 }
func (p *Tracer) Required() bool                                      { return false }
