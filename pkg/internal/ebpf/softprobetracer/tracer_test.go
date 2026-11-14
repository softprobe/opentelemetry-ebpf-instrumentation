// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobetracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/softprobetracer"

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/softprobe"
)

func TestDecodeOrigDst(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) {
		var ip [16]uint8
		copy(ip[:4], []byte{198, 51, 100, 42})
		got, ok := decodeOrigDst(ip, 8443, afInet, 1234)
		require.True(t, ok)
		assert.Equal(t, netip.MustParseAddrPort("198.51.100.42:8443"), got.AddrPort)
		assert.Equal(t, afInet, got.Family)
		assert.Equal(t, uint32(1234), got.PID)
	})

	t.Run("ipv6_v4mapped_unmaps_cleanly", func(t *testing.T) {
		ip := netip.AddrFrom4([4]byte{203, 0, 113, 9})
		v6 := netip.AddrFrom16(ip.As16())
		raw := v6.As16()
		got, ok := decodeOrigDst(raw, 5432, afInet6, 4321)
		require.True(t, ok)
		assert.Equal(t, netip.MustParseAddrPort("203.0.113.9:5432"), got.AddrPort)
		assert.Equal(t, afInet6, got.Family)
		assert.Equal(t, uint32(4321), got.PID)
	})

	t.Run("pure_ipv6", func(t *testing.T) {
		addr := netip.MustParseAddr("2001:db8::abcd")
		got, ok := decodeOrigDst(addr.As16(), 443, afInet6, 99)
		require.True(t, ok)
		assert.Equal(t, netip.MustParseAddrPort("[2001:db8::abcd]:443"), got.AddrPort)
		assert.Equal(t, afInet6, got.Family)
	})

	t.Run("invalid_zero_port_or_family", func(t *testing.T) {
		var ip [16]uint8
		_, ok := decodeOrigDst(ip, 0, afInet, 1)
		assert.False(t, ok)
		_, ok = decodeOrigDst(ip, 80, 99, 1)
		assert.False(t, ok)
	})
}

func TestExtractRemotePort(t *testing.T) {
	p, ok := extractRemotePort(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 51234})
	require.True(t, ok)
	assert.Equal(t, uint16(51234), p)

	_, ok = extractRemotePort(nil)
	assert.False(t, ok)
}

func TestLoopbackExcludedPortsFromConfig(t *testing.T) {
	ports := loopbackExcludedPortsFromConfig(softprobe.Config{
		IngressProxyPort: 15080,
		EgressProxyPort:  15081,
		BackendURL:       "http://127.0.0.1:18090",
		VectorLogsURL:    "http://localhost:8686/v1/logs",
	})
	assert.ElementsMatch(t, []uint16{15080, 15081, 18090, 8686}, ports)

	externalOnly := loopbackExcludedPortsFromConfig(softprobe.Config{
		EgressProxyPort: 15081,
		BackendURL:      "https://api.softprobe.ai",
		VectorLogsURL:   "https://logs.softprobe.ai:8443",
	})
	assert.Equal(t, []uint16{15081}, externalOnly)
}

func TestTracerLifecycleAndPortRegistration(t *testing.T) {
	cfg := &obi.Config{}
	cfg.Softprobe = softprobe.Config{
		Enabled:          true,
		IngressProxyPort: 15080,
		EgressProxyPort:  15081,
		BackendURL:       "http://127.0.0.1:18090",
	}

	tr := New(cfg, nil, nil)
	if tr == nil {
		t.Skip("tracer stubbed on non-linux platform")
	}
	defer func() { _ = tr.Close() }()

	assert.Same(t, tr, ActiveTracer())
	require.NoError(t, tr.RegisterAppPort(8080))
	relocated, ok := tr.LookupRelocatedPort(8080)
	require.True(t, ok)
	assert.Equal(t, uint16(8080), relocated)

	require.NoError(t, tr.UnregisterAppPort(8080))
	_, ok = tr.LookupRelocatedPort(8080)
	assert.False(t, ok)
}
