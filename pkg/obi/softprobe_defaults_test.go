// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi // import "go.opentelemetry.io/obi/pkg/obi"

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/softprobe"
)

func TestApplySoftprobeRuntimeDefaultsDisabledNoOp(t *testing.T) {
	cfg := DefaultConfig
	cfg.ApplySoftprobeRuntimeDefaults()

	assert.Equal(t, uint32(0), cfg.EBPF.BufferSizes.HTTP)
	assert.Equal(t, uint32(0), cfg.EBPF.BufferSizes.Postgres)
	assert.Equal(t, 0, cfg.EBPF.SoftprobeCaptureMaxBytes)
	assert.False(t, cfg.EBPF.TrackRequestHeaders)
	assert.False(t, cfg.EBPF.PopulateTraceContext)
	assert.Equal(t, config.ContextPropagationDisabled, cfg.EBPF.ContextPropagation)
}

func TestApplySoftprobeRuntimeDefaultsEnabled(t *testing.T) {
	cfg := DefaultConfig
	cfg.Softprobe = softprobe.Config{
		Enabled:               true,
		AppID:                 "travel-ota",
		BackendURL:            "http://sp-app:8090/",
		VectorLogsURL:         "http://vector:4318/v1/logs",
		RecordRate:            1.0,
		ExcludeErrorResponses: true,
		MaxBodyBytes:          524288,
	}

	cfg.Discovery.DefaultExcludeInstrument = nil

	cfg.ApplySoftprobeRuntimeDefaults()

	assert.Equal(t, "travel-ota", cfg.ServiceName)
	assert.Equal(t, "http://sp-app:8090/v1/traces", cfg.Traces.TracesEndpoint)
	assert.Equal(t, otelcfg.ProtocolHTTPProtobuf, cfg.Traces.TracesProtocol)
	assert.Equal(t, 250*time.Millisecond, cfg.Traces.BatchTimeout)
	assert.Equal(t, 250*time.Millisecond, cfg.EBPF.BatchTimeout)
	assert.NotEmpty(t, cfg.Discovery.DefaultExcludeInstrument)
	assert.False(t, cfg.Discovery.ExcludeOTelInstrumentedServices)
	assert.Equal(t, uint32(262144), cfg.EBPF.BufferSizes.HTTP)
	assert.Equal(t, uint32(65536), cfg.EBPF.BufferSizes.Postgres)
	assert.Equal(t, uint32(65536), cfg.EBPF.BufferSizes.MySQL)
	assert.Equal(t, uint32(65536), cfg.EBPF.BufferSizes.MSSQL)
	assert.Equal(t, uint32(65536), cfg.EBPF.BufferSizes.TCP)
	assert.Equal(t, 524288, cfg.EBPF.SoftprobeCaptureMaxBytes)
	assert.Equal(t, softprobe.DefaultIngressProxyPort, cfg.Softprobe.IngressProxyPort)
	assert.Equal(t, softprobe.DefaultEgressProxyPort, cfg.Softprobe.EgressProxyPort)
	assert.True(t, cfg.EBPF.TrackRequestHeaders)
	assert.True(t, cfg.EBPF.PopulateTraceContext)
	assert.Equal(t, config.ContextPropagationHeaders, cfg.EBPF.ContextPropagation)
	assert.True(t, cfg.EBPF.LogEnricher.Enabled())

	assert.Equal(t, uint32(0), DefaultConfig.EBPF.BufferSizes.HTTP)
	assert.False(t, DefaultConfig.EBPF.LogEnricher.Enabled())
}

func TestApplySoftprobeRuntimeDefaultsPreservesExplicitBufferSizes(t *testing.T) {
	cfg := DefaultConfig
	cfg.ServiceName = "explicit-service"
	cfg.Traces.TracesEndpoint = "http://custom-otel:4318/v1/traces"
	cfg.EBPF.BufferSizes.HTTP = 16384
	cfg.EBPF.BufferSizes.Postgres = 8192
	cfg.EBPF.ContextPropagation = config.ContextPropagationAll
	cfg.Softprobe = softprobe.Config{
		Enabled:          true,
		AppID:            "travel-ota",
		BackendURL:       "http://sp-app:8090",
		IngressProxyPort: 15006,
		EgressProxyPort:  15001,
		MaxBodyBytes:     131072,
	}

	cfg.ApplySoftprobeRuntimeDefaults()

	assert.Equal(t, "explicit-service", cfg.ServiceName)
	assert.Equal(t, "http://custom-otel:4318/v1/traces", cfg.Traces.TracesEndpoint)
	assert.Equal(t, uint32(16384), cfg.EBPF.BufferSizes.HTTP)
	assert.Equal(t, uint32(8192), cfg.EBPF.BufferSizes.Postgres)
	assert.Equal(t, 15006, cfg.Softprobe.IngressProxyPort)
	assert.Equal(t, 15001, cfg.Softprobe.EgressProxyPort)
	assert.Equal(t, config.ContextPropagationAll, cfg.EBPF.ContextPropagation)
	assert.False(t, cfg.EBPF.LogEnricher.Enabled())
}
