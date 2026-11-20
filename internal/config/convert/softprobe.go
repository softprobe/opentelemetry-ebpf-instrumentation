// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"errors"
	"fmt"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/softprobe"
)

func defaultSoftprobeExtension() *schema.Softprobe {
	excludeErrors := softprobe.DefaultExcludeErrorResponses
	return &schema.Softprobe{
		Enabled:               false,
		RecordRate:            softprobe.DefaultRecordRate,
		ExcludeErrorResponses: &excludeErrors,
		MaxBodyBytes:          softprobe.DefaultMaxBodyBytes,
	}
}

func softprobeExtension(cfg softprobe.Config) *schema.Softprobe {
	cfg = cfg.WithDefaults()
	if cfg.IsDefault() {
		return nil
	}
	excludeErrors := cfg.ExcludeErrorResponses
	return &schema.Softprobe{
		Enabled:               cfg.Enabled,
		AppID:                 cfg.AppID,
		BackendURL:            cfg.BackendURL,
		VectorLogsURL:         cfg.VectorLogsURL,
		Env:                   cfg.Env,
		RecordRate:            cfg.RecordRate,
		ExcludeErrorResponses: &excludeErrors,
		IngressProxyPort:      cfg.IngressProxyPort,
		EgressProxyPort:       cfg.EgressProxyPort,
		MaxBodyBytes:          cfg.MaxBodyBytes,
	}
}

func applyV2Softprobe(cfg *obi.Config, src *schema.Softprobe, complete bool) error {
	if src == nil {
		cfg.Softprobe = softprobe.DefaultConfig()
		return nil
	}
	if complete && src.ExcludeErrorResponses == nil {
		return errors.New("softprobe.exclude_error_responses must not be null")
	}

	excludeErrors := softprobe.DefaultExcludeErrorResponses
	if src.ExcludeErrorResponses != nil {
		excludeErrors = *src.ExcludeErrorResponses
	}

	resolved := softprobe.Config{
		Enabled:               src.Enabled,
		AppID:                 src.AppID,
		BackendURL:            src.BackendURL,
		VectorLogsURL:         src.VectorLogsURL,
		Env:                   src.Env,
		RecordRate:            src.RecordRate,
		ExcludeErrorResponses: excludeErrors,
		IngressProxyPort:      src.IngressProxyPort,
		EgressProxyPort:       src.EgressProxyPort,
		MaxBodyBytes:          src.MaxBodyBytes,
	}
	if !complete {
		resolved = resolved.WithDefaults()
		if resolved.RecordRate == 0 && !src.Enabled {
			resolved.RecordRate = softprobe.DefaultRecordRate
		}
	}

	if err := resolved.Validate(); err != nil {
		return fmt.Errorf("softprobe: %w", err)
	}
	cfg.Softprobe = resolved
	return nil
}
