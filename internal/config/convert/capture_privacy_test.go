// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/internal/config/schema"
)

func TestDemoApplicationSessionCaptureDisablesPayloadBuffers(t *testing.T) {
	data, err := os.ReadFile("../../../demo/demo-ota/obi-session-capture.yaml")
	require.NoError(t, err)

	var file struct {
		Extensions schema.Extensions `yaml:"extensions"`
	}
	require.NoError(t, yaml.Unmarshal(data, &file))
	require.NotNil(t, file.Extensions.OBI)

	cfg, err := V2ToRuntime(file.Extensions.OBI)
	require.NoError(t, err)
	require.Len(t, file.Extensions.OBI.Capture.Rules, 1)
	require.Equal(t, []string{"java"}, file.Extensions.OBI.Capture.Rules[0].Match.Process.LanguageGlob)
	require.Equal(t, []string{"*travel-ota*"}, file.Extensions.OBI.Capture.Rules[0].Match.Process.CmdArgsGlob)
	require.False(t, cfg.EBPF.PayloadExtraction.RecordPayloads)
	require.Zero(t, cfg.EBPF.BufferSizes.HTTP)
	require.Zero(t, cfg.EBPF.BufferSizes.MySQL)
	require.Zero(t, cfg.EBPF.BufferSizes.Postgres)
	require.Zero(t, cfg.EBPF.BufferSizes.MSSQL)
	require.Zero(t, cfg.EBPF.BufferSizes.Kafka)
	require.Zero(t, cfg.EBPF.BufferSizes.TCP)
	require.Zero(t, cfg.EBPF.BufferSizes.Aerospike)
}
