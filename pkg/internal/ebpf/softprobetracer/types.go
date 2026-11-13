// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobetracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/softprobetracer"

import (
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	"go.opentelemetry.io/obi/pkg/softprobe"
)

const (
	afInet  uint16 = 2
	afInet6 uint16 = 10
)

type OrigDst struct {
	AddrPort netip.AddrPort
	Family   uint16
	PID      uint32
}

var activeTracer atomic.Pointer[Tracer]

func ActiveTracer() *Tracer {
	return activeTracer.Load()
}

func decodeOrigDst(ip [16]uint8, port uint16, family uint16, pid uint32) (OrigDst, bool) {
	if port == 0 {
		return OrigDst{}, false
	}

	switch family {
	case afInet:
		var ip4 [4]byte
		copy(ip4[:], ip[:4])
		addr := netip.AddrFrom4(ip4)
		return OrigDst{
			AddrPort: netip.AddrPortFrom(addr, port),
			Family:   family,
			PID:      pid,
		}, true
	case afInet6:
		addr := netip.AddrFrom16(ip).Unmap()
		return OrigDst{
			AddrPort: netip.AddrPortFrom(addr, port),
			Family:   family,
			PID:      pid,
		}, true
	default:
		return OrigDst{}, false
	}
}

func extractRemotePort(remoteAddr net.Addr) (uint16, bool) {
	if remoteAddr == nil {
		return 0, false
	}
	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		if tcpAddr.Port <= 0 || tcpAddr.Port > 65535 {
			return 0, false
		}
		return uint16(tcpAddr.Port), true
	}
	ap, err := netip.ParseAddrPort(remoteAddr.String())
	if err != nil || ap.Port() == 0 {
		return 0, false
	}
	return ap.Port(), true
}

func loopbackExcludedPortsFromConfig(cfg softprobe.Config) []uint16 {
	seen := make(map[uint16]struct{}, 4)
	var ports []uint16
	add := func(port int) {
		if port <= 0 || port > 65535 {
			return
		}
		p := uint16(port)
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			ports = append(ports, p)
		}
	}

	add(cfg.IngressProxyPort)
	add(cfg.EgressProxyPort)
	if p, ok := loopbackEndpointPort(cfg.BackendURL); ok {
		add(int(p))
	}
	if p, ok := loopbackEndpointPort(cfg.VectorLogsURL); ok {
		add(int(p))
	}
	return ports
}

func loopbackEndpointPort(rawURL string) (uint16, bool) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return 0, false
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return 0, false
	}
	host := strings.ToLower(u.Hostname())
	isLoopback := host == "localhost"
	if !isLoopback {
		if addr, err := netip.ParseAddr(host); err == nil && addr.IsLoopback() {
			isLoopback = true
		}
	}
	if !isLoopback {
		return 0, false
	}

	if portStr := u.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return 0, false
		}
		return uint16(port), true
	}

	switch strings.ToLower(u.Scheme) {
	case "http":
		return 80, true
	case "https":
		return 443, true
	default:
		return 0, false
	}
}
