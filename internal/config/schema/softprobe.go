// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

type Softprobe struct {
	Enabled               bool    `yaml:"enabled"`
	AppID                 string  `yaml:"app_id"`
	BackendURL            string  `yaml:"backend_url"`
	VectorLogsURL         string  `yaml:"vector_logs_url"`
	Env                   string  `yaml:"env"`
	RecordRate            float64 `yaml:"record_rate"`
	ExcludeErrorResponses *bool   `yaml:"exclude_error_responses,omitempty"`
	IngressProxyPort      int     `yaml:"ingress_proxy_port"`
	EgressProxyPort       int     `yaml:"egress_proxy_port"`
	MaxBodyBytes          int     `yaml:"max_body_bytes"`
}
