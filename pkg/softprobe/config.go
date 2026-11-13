// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"errors"
	"fmt"
	"math"
	"net/url"
)

const (
	DefaultMaxBodyBytes          = 262144
	DefaultRecordRate            = 1.0
	DefaultExcludeErrorResponses = true
)

type Config struct {
	Enabled               bool
	AppID                 string
	BackendURL            string
	VectorLogsURL         string
	Env                   string
	RecordRate            float64
	ExcludeErrorResponses bool
	IngressProxyPort      int
	EgressProxyPort       int
	MaxBodyBytes          int
}

func DefaultConfig() Config {
	return Config{
		RecordRate:            DefaultRecordRate,
		ExcludeErrorResponses: DefaultExcludeErrorResponses,
		MaxBodyBytes:          DefaultMaxBodyBytes,
	}
}

func (c Config) WithDefaults() Config {
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = DefaultMaxBodyBytes
	}
	return c
}

func (c Config) IsDefault() bool {
	return c == DefaultConfig()
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if math.IsNaN(c.RecordRate) || math.IsInf(c.RecordRate, 0) || c.RecordRate < 0 {
		return fmt.Errorf("softprobe record_rate must be a non-negative finite number, got %v", c.RecordRate)
	}
	if c.MaxBodyBytes <= 0 {
		return fmt.Errorf("softprobe max_body_bytes must be positive, got %d", c.MaxBodyBytes)
	}
	if err := validateTCPPort("ingress_proxy_port", c.IngressProxyPort); err != nil {
		return err
	}
	if err := validateTCPPort("egress_proxy_port", c.EgressProxyPort); err != nil {
		return err
	}
	if c.IngressProxyPort > 0 && c.IngressProxyPort == c.EgressProxyPort {
		return fmt.Errorf("softprobe ingress_proxy_port and egress_proxy_port must differ when set, got %d", c.IngressProxyPort)
	}
	if err := validateHTTPURL("backend_url", c.BackendURL); err != nil {
		return err
	}
	if err := validateHTTPURL("vector_logs_url", c.VectorLogsURL); err != nil {
		return err
	}
	return nil
}

func validateTCPPort(field string, port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("softprobe %s must be between 0 and 65535, got %d", field, port)
	}
	return nil
}

func validateHTTPURL(field, raw string) error {
	if raw == "" {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("softprobe %s is invalid: %w", field, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("softprobe %s must use http or https scheme, got %q", field, parsed.Scheme)
	}
	if parsed.Host == "" {
		return errors.New("softprobe " + field + " must include a host")
	}
	return nil
}
