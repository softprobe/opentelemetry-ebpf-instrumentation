// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEphemeralCALeafVerificationAndCaching(t *testing.T) {
	ca, err := NewEphemeralCA()
	require.NoError(t, err)
	require.NotEmpty(t, ca.CAPEM())
	require.True(t, ca.CACert().IsCA)

	dnsCert1, err := ca.LeafCertificateForHost("spair.softprobe.ai:443")
	require.NoError(t, err)
	dnsCert2, err := ca.LeafCertificateForHost("SPAIR.SOFTPROBE.AI")
	require.NoError(t, err)
	assert.Same(t, dnsCert1, dnsCert2)

	chains, err := dnsCert1.Leaf.Verify(x509.VerifyOptions{
		DNSName:   "spair.softprobe.ai",
		Roots:     ca.CertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, chains)

	ipCert, err := ca.LeafCertificateForHost("127.0.0.1:8443")
	require.NoError(t, err)
	require.Len(t, ipCert.Leaf.IPAddresses, 1)
	require.True(t, ipCert.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")))
	_, err = ipCert.Leaf.Verify(x509.VerifyOptions{
		DNSName:   "127.0.0.1",
		Roots:     ca.CertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	require.NoError(t, err)

	pemPath := filepath.Join(t.TempDir(), "sp-obi-ca.pem")
	require.NoError(t, ca.WritePEMFile(pemPath))
	diskPEM, err := os.ReadFile(pemPath)
	require.NoError(t, err)
	assert.Equal(t, ca.CAPEM(), diskPEM)

	SetActiveCAPEM(ca.CAPEM())
	t.Cleanup(func() { SetActiveCAPEM(nil) })
	assert.Equal(t, ca.CAPEM(), ActiveCAPEM())
}

func TestEphemeralCATLSHandshakeSNIAndFallback(t *testing.T) {
	ca, err := NewEphemeralCA()
	require.NoError(t, err)

	var observedSNI string
	ln, err := tls.Listen("tcp", "127.0.0.1:0", ca.ServerTLSConfig("127.0.0.1", func(hello *tls.ClientHelloInfo) {
		observedSNI = hello.ServerName
	}))
	require.NoError(t, err)
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn := conn.(*tls.Conn)
		done <- tlsConn.Handshake()
	}()

	clientConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName: "spair.softprobe.ai",
		RootCAs:    ca.CertPool(),
		NextProtos: []string{"http/1.1"},
	})
	require.NoError(t, err)
	assert.Equal(t, "http/1.1", clientConn.ConnectionState().NegotiatedProtocol)
	_ = clientConn.Close()
	require.NoError(t, <-done)
	assert.Equal(t, "spair.softprobe.ai", observedSNI)
}
