// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/softprobe"
)

func softprobeYAML(body string) string {
	return "file_format: \"1.0\"\nextensions:\n  obi:\n    version: \"2.0\"\n    softprobe:\n" + body
}

func TestSoftprobeV2DefaultsAndRoundTrip(t *testing.T) {
	_, ext, err := schema.ParseStandaloneYAML([]byte(softprobeYAML("      enabled: true\n      app_id: travel-ota\n      backend_url: http://127.0.0.1:18090\n")))
	require.NoError(t, err)
	cfg, err := V2ToRuntime(ext)
	require.NoError(t, err)

	want := softprobe.DefaultConfig()
	want.Enabled = true
	want.AppID = "travel-ota"
	want.BackendURL = "http://127.0.0.1:18090"
	require.Equal(t, want, cfg.Softprobe)
	require.True(t, cfg.Softprobe.ExcludeErrorResponses)
	require.Equal(t, 262144, cfg.Softprobe.MaxBodyBytes)

	cfg.Softprobe.VectorLogsURL = "http://vector:8686/logs"
	cfg.Softprobe.Env = "staging"
	cfg.Softprobe.RecordRate = 0.5
	cfg.Softprobe.ExcludeErrorResponses = false
	cfg.Softprobe.IngressProxyPort = 18081
	cfg.Softprobe.EgressProxyPort = 18082
	cfg.Softprobe.MaxBodyBytes = 524288

	_, exported := RuntimeToV2(cfg)
	require.NotNil(t, exported.Softprobe)
	roundTrip, err := V2ToRuntime(exported)
	require.NoError(t, err)
	require.Equal(t, cfg.Softprobe, roundTrip.Softprobe)
}

func TestSoftprobeV2DefaultOmittedOnExport(t *testing.T) {
	cfg := obi.DefaultConfig
	_, exported := RuntimeToV2(&cfg)
	require.Nil(t, exported.Softprobe)

	restored, err := V2ToRuntime(exported)
	require.NoError(t, err)
	require.Equal(t, softprobe.DefaultConfig(), restored.Softprobe)
}

func TestSoftprobeV2Validation(t *testing.T) {
	for _, field := range []string{
		"record_rate: -1",
		"ingress_proxy_port: 65536",
		"ingress_proxy_port: -1",
		"egress_proxy_port: 65536",
		"max_body_bytes: -5",
		"backend_url: ftp://invalid.example.com",
		"vector_logs_url: ://bad-url",
		"exclude_error_responses: null",
	} {
		t.Run(field, func(t *testing.T) {
			body := "      enabled: true\n      " + field + "\n"
			_, ext, err := schema.ParseStandaloneYAML([]byte(softprobeYAML(body)))
			require.NoError(t, err)
			_, err = V2ToRuntime(ext)
			require.Error(t, err)
			require.Contains(t, err.Error(), "softprobe")
		})
	}
}

func TestDisabledSoftprobeV2SkipsRuntimeValidation(t *testing.T) {
	_, ext, err := schema.ParseStandaloneYAML([]byte(softprobeYAML("      enabled: false\n      max_body_bytes: 0\n")))
	require.NoError(t, err)
	cfg, err := V2ToRuntime(ext)
	require.NoError(t, err)
	require.False(t, cfg.Softprobe.Enabled)
}
