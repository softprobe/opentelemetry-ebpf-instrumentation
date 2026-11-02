// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"errors"
)

const DefaultRequestContextMapPath = "/sys/fs/bpf/otel/sp_request_ctx_v1"

type PinnedRequestContextMap struct{}

func NewPinnedRequestContextMap(string) (*PinnedRequestContextMap, error) {
	return nil, errors.New("OBI request replay requires Linux eBPF")
}

func (*PinnedRequestContextMap) Consume(string) (RequestTraceContext, bool, error) {
	return RequestTraceContext{}, false, errors.New("OBI request replay requires Linux eBPF")
}
