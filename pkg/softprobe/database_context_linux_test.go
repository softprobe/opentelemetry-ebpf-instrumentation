// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package softprobe

import (
	"net"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestRequestContextMapLayoutMatchesBPFABI(t *testing.T) {
	require.Equal(t, uintptr(20), unsafe.Sizeof(requestContextKey{}))
	require.Equal(t, uintptr(56), unsafe.Sizeof(requestContextValue{}))
}

func TestRequestContextKeyUsesClientAddress(t *testing.T) {
	key, err := requestContextKeyForAddress("192.0.2.14:43127")
	require.NoError(t, err)
	require.Equal(t, []byte(net.ParseIP("192.0.2.14").To16()), key.ClientAddr[:])
	require.Equal(t, uint16(43127), key.ClientPort)
}

func TestRequestContextKeyRejectsInvalidClientAddress(t *testing.T) {
	for _, address := range []string{"", "192.0.2.14", "example.com:43127", "192.0.2.14:port"} {
		t.Run(address, func(t *testing.T) {
			_, err := requestContextKeyForAddress(address)
			require.Error(t, err)
		})
	}
}
