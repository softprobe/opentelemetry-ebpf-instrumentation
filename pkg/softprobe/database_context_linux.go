// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	DefaultRequestContextMapPath = "/sys/fs/bpf/otel/sp_request_ctx_v1"
	requestContextMaxAge         = 5 * time.Second
)

type requestContextKey struct {
	ClientAddr [16]byte
	ClientPort uint16
	Padding    [2]byte
}

type requestContextValue struct {
	TraceID     [16]byte
	SpanID      [8]byte
	ParentID    [8]byte
	StartedAtNs uint64
	Flags       uint8
	Padding     [7]byte
	UpdatedAtNs uint64
}

var _ RequestTraceContextReader = (*PinnedRequestContextMap)(nil)

// PinnedRequestContextMap consumes the versioned OBI context map shared with
// local protocol gateways.
type PinnedRequestContextMap struct {
	path string
}

func NewPinnedRequestContextMap(path string) (*PinnedRequestContextMap, error) {
	if path == "" {
		return nil, errors.New("OBI request context map path is required")
	}
	return &PinnedRequestContextMap{path: path}, nil
}

func (m *PinnedRequestContextMap) Consume(clientAddress string) (RequestTraceContext, bool, error) {
	key, err := requestContextKeyForAddress(clientAddress)
	if err != nil {
		return RequestTraceContext{}, false, err
	}

	ctxMap, err := ebpf.LoadPinnedMap(m.path, nil)
	if err != nil {
		return RequestTraceContext{}, false, fmt.Errorf("open OBI request context map: %w", err)
	}
	defer ctxMap.Close()

	var value requestContextValue
	if err := ctxMap.LookupAndDelete(&key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return RequestTraceContext{}, false, nil
		}
		return RequestTraceContext{}, false, fmt.Errorf("consume OBI request context: %w", err)
	}

	if !requestContextIsFresh(value.UpdatedAtNs) || allZero(value.TraceID[:]) {
		return RequestTraceContext{}, false, nil
	}

	return RequestTraceContext{
		TraceID:      hex.EncodeToString(value.TraceID[:]),
		ParentSpanID: hex.EncodeToString(value.ParentID[:]),
		Flags:        uint32(value.Flags),
	}, true, nil
}

func requestContextKeyForAddress(address string) (requestContextKey, error) {
	if address == "" {
		return requestContextKey{}, errors.New("OBI client address is missing")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return requestContextKey{}, fmt.Errorf("parse OBI client address: %w", err)
	}
	ip := net.ParseIP(host).To16()
	if ip == nil {
		return requestContextKey{}, fmt.Errorf("invalid OBI client IP %q", host)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return requestContextKey{}, fmt.Errorf("parse OBI client port: %w", err)
	}
	key := requestContextKey{ClientPort: uint16(port)}
	copy(key.ClientAddr[:], ip)
	return key, nil
}

func requestContextIsFresh(updatedAtNs uint64) bool {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return false
	}
	nowNs := uint64(now.Sec)*uint64(time.Second) + uint64(now.Nsec)
	maxAgeNs := uint64(requestContextMaxAge)
	return updatedAtNs > 0 && nowNs >= updatedAtNs && nowNs-updatedAtNs <= maxAgeNs
}
