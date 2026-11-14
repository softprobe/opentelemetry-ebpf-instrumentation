// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi // import "go.opentelemetry.io/obi/pkg/obi"

import (
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/softprobe"
)

const (
	softprobeMaxHTTPBufferBytes uint32 = 262144
	softprobeDefaultDBBuffer    uint32 = 65536
	softprobeBatchTimeout              = 250 * time.Millisecond
)

func (c *Config) ApplySoftprobeRuntimeDefaults() {
	if c == nil || !c.Softprobe.Enabled {
		return
	}

	c.Softprobe = c.Softprobe.WithDefaults()
	if c.Softprobe.IngressProxyPort == 0 {
		if c.Softprobe.EgressProxyPort == softprobe.DefaultIngressProxyPort {
			c.Softprobe.IngressProxyPort = softprobe.DefaultEgressProxyPort
		} else {
			c.Softprobe.IngressProxyPort = softprobe.DefaultIngressProxyPort
		}
	}
	if c.Softprobe.EgressProxyPort == 0 {
		if c.Softprobe.IngressProxyPort == softprobe.DefaultEgressProxyPort {
			c.Softprobe.EgressProxyPort = softprobe.DefaultIngressProxyPort
		} else {
			c.Softprobe.EgressProxyPort = softprobe.DefaultEgressProxyPort
		}
	}

	if c.ServiceName == "" && c.Softprobe.AppID != "" {
		c.ServiceName = c.Softprobe.AppID
	}

	if !c.Traces.Enabled() && c.Softprobe.BackendURL != "" {
		c.Traces.TracesEndpoint = strings.TrimRight(c.Softprobe.BackendURL, "/") + "/v1/traces"
		c.Traces.TracesProtocol = otelcfg.ProtocolHTTPProtobuf
		c.Traces.BatchTimeout = softprobeBatchTimeout
	}

	if c.EBPF.BatchTimeout == DefaultConfig.EBPF.BatchTimeout {
		c.EBPF.BatchTimeout = softprobeBatchTimeout
	}

	if len(c.Discovery.DefaultExcludeInstrument) == 0 {
		c.Discovery.DefaultExcludeInstrument = slices.Clone(DefaultConfig.Discovery.DefaultExcludeInstrument)
	}
	// Upstream OBI stops tpinjector header propagation and span export when a target
	// process exports OTLP traces. Softprobe record and replay require both to stay active.
	c.Discovery.ExcludeOTelInstrumentedServices = false

	if c.EBPF.BufferSizes.HTTP == 0 {
		httpBytes := uint32(min(c.Softprobe.MaxBodyBytes, int(softprobeMaxHTTPBufferBytes)))
		c.EBPF.BufferSizes.HTTP = httpBytes
	}
	if c.EBPF.BufferSizes.Postgres == 0 {
		c.EBPF.BufferSizes.Postgres = softprobeDefaultDBBuffer
	}
	if c.EBPF.BufferSizes.MySQL == 0 {
		c.EBPF.BufferSizes.MySQL = softprobeDefaultDBBuffer
	}
	if c.EBPF.BufferSizes.MSSQL == 0 {
		c.EBPF.BufferSizes.MSSQL = softprobeDefaultDBBuffer
	}
	if c.EBPF.BufferSizes.TCP == 0 {
		c.EBPF.BufferSizes.TCP = softprobeDefaultDBBuffer
	}

	c.EBPF.SoftprobeCaptureMaxBytes = c.Softprobe.MaxBodyBytes
	c.EBPF.TrackRequestHeaders = true
	c.EBPF.PopulateTraceContext = true
	if c.EBPF.ContextPropagation == config.ContextPropagationDisabled {
		c.EBPF.ContextPropagation = config.ContextPropagationHeaders
	}

	if c.Softprobe.VectorLogsURL != "" && len(c.EBPF.LogEnricher.Services) == 0 {
		c.EBPF.LogEnricher.Services = []config.LogEnricherServiceConfig{{
			Service: services.GlobDefinitionCriteria{{
				Path: services.NewGlob("*"),
			}},
		}}
	}
}
