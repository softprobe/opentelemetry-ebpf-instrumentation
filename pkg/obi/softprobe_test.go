// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi // import "go.opentelemetry.io/obi/pkg/obi"

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/softprobe"
)

func TestConfigV1SoftprobeYAMLIgnored(t *testing.T) {
	cfg, err := LoadConfig(strings.NewReader(`softprobe:
  enabled: true
  app_id: travel-ota
  backend_url: http://127.0.0.1:18090
  ingress_proxy_port: 99999
`))
	require.NoError(t, err)
	require.Equal(t, softprobe.DefaultConfig(), cfg.Softprobe)
}

func TestConfigV1SoftprobeEnvironmentIgnored(t *testing.T) {
	t.Setenv("OTEL_EBPF_SOFTPROBE_ENABLED", "true")
	t.Setenv("OTEL_EBPF_SOFTPROBE_APP_ID", "travel-ota")
	cfg, err := LoadConfig(nil)
	require.NoError(t, err)
	require.Equal(t, softprobe.DefaultConfig(), cfg.Softprobe)
}

func TestConfigV1SoftprobeMapIgnored(t *testing.T) {
	cfg := DefaultConfig
	err := cfg.UnmarshalMap(map[string]any{
		"softprobe": map[string]any{"enabled": true, "app_id": "travel-ota"},
	})
	require.NoError(t, err)
	require.Equal(t, softprobe.DefaultConfig(), cfg.Softprobe)
}

func TestConfigV1SoftprobeNotMarshaled(t *testing.T) {
	cfg := DefaultConfig
	cfg.Softprobe.Enabled = true
	cfg.Softprobe.AppID = "travel-ota"
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NotContains(t, string(data), "softprobe:")
	require.NotContains(t, string(data), "travel-ota")
}

func TestConfigSoftprobeRuntimeValidation(t *testing.T) {
	t.Setenv("OTEL_EBPF_EXECUTABLE_PATH", "java")
	cfg, err := LoadConfig(nil)
	require.NoError(t, err)
	cfg.Softprobe.Enabled = true
	cfg.Softprobe.AppID = "travel-ota"
	cfg.Softprobe.BackendURL = "http://127.0.0.1:18090"
	require.NoError(t, cfg.ValidateStatic())

	cfg.Softprobe.MaxBodyBytes = -1
	require.ErrorContains(t, cfg.ValidateStatic(), "softprobe max_body_bytes")
}
