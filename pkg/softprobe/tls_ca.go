// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	DefaultCACertPath    = "/tmp/sp-obi-ca.pem"
	defaultLeafCacheSize = 2048
	defaultLeafCacheTTL  = 24 * time.Hour
	leafCertLifetime     = 48 * time.Hour
	rootCALifetime       = 365 * 24 * time.Hour
)

var activeCAPEM atomic.Pointer[[]byte]

func SetActiveCAPEM(pemBytes []byte) {
	if len(pemBytes) == 0 {
		activeCAPEM.Store(nil)
		return
	}
	cp := slices.Clone(pemBytes)
	activeCAPEM.Store(&cp)
}

func ActiveCAPEM() []byte {
	ptr := activeCAPEM.Load()
	if ptr == nil {
		return nil
	}
	return slices.Clone(*ptr)
}

type EphemeralCA struct {
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	caDER  []byte
	caPEM  []byte

	signMu sync.Mutex
	leaves *expirable.LRU[string, *tls.Certificate]
}

func NewEphemeralCA() (*EphemeralCA, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral CA key: %w", err)
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&caKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling ephemeral CA public key: %w", err)
	}
	skiHash := sha256.Sum256(pubDER)

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Softprobe OBI Ephemeral Root CA",
			Organization: []string{"Softprobe"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(rootCALifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          skiHash[:20],
	}

	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating ephemeral CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("parsing ephemeral CA certificate: %w", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caDER,
	})

	return &EphemeralCA{
		caKey:  caKey,
		caCert: caCert,
		caDER:  caDER,
		caPEM:  caPEM,
		leaves: expirable.NewLRU[string, *tls.Certificate](defaultLeafCacheSize, nil, defaultLeafCacheTTL),
	}, nil
}

func (c *EphemeralCA) CAPEM() []byte {
	if c == nil {
		return nil
	}
	return slices.Clone(c.caPEM)
}

func (c *EphemeralCA) CACert() *x509.Certificate {
	if c == nil {
		return nil
	}
	return c.caCert
}

func (c *EphemeralCA) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	if c != nil && c.caCert != nil {
		pool.AddCert(c.caCert)
	}
	return pool
}

func (c *EphemeralCA) WritePEMFile(path string) error {
	if c == nil || len(c.caPEM) == 0 {
		return errors.New("ephemeral CA is not initialized")
	}
	if path == "" {
		path = DefaultCACertPath
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating CA directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".sp-obi-ca-*.pem")
	if err != nil {
		return fmt.Errorf("creating temporary CA file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(c.caPEM); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temporary CA file: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temporary CA file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temporary CA file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("renaming temporary CA file to %s: %w", path, err)
	}
	cleanup = false
	return nil
}

func (c *EphemeralCA) LeafCertificateForHost(host string) (*tls.Certificate, error) {
	if c == nil {
		return nil, errors.New("ephemeral CA is nil")
	}
	normalized := normalizeCertHost(host)
	now := time.Now()

	if cached, ok := c.leaves.Get(normalized); ok && cached != nil && cached.Leaf != nil {
		if cached.Leaf.NotAfter.After(now.Add(1 * time.Hour)) {
			return cached, nil
		}
	}

	c.signMu.Lock()
	defer c.signMu.Unlock()

	if cached, ok := c.leaves.Get(normalized); ok && cached != nil && cached.Leaf != nil {
		if cached.Leaf.NotAfter.After(now.Add(1 * time.Hour)) {
			return cached, nil
		}
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating leaf key for %s: %w", normalized, err)
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&leafKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling leaf public key: %w", err)
	}
	skiHash := sha256.Sum256(pubDER)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: normalized,
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(leafCertLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          skiHash[:20],
		AuthorityKeyId:        c.caCert.SubjectKeyId,
	}
	if ip := net.ParseIP(normalized); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{normalized}
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.caCert, &leafKey.PublicKey, c.caKey)
	if err != nil {
		return nil, fmt.Errorf("signing leaf certificate for %s: %w", normalized, err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("parsing leaf certificate for %s: %w", normalized, err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{leafDER, c.caDER},
		PrivateKey:  leafKey,
		Leaf:        leafCert,
	}
	c.leaves.Add(normalized, cert)
	return cert, nil
}

func (c *EphemeralCA) ServerTLSConfig(fallbackHost string, onClientHello func(*tls.ClientHelloInfo)) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1", "h2"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if onClientHello != nil && hello != nil {
				onClientHello(hello)
			}
			host := fallbackHost
			if hello != nil && strings.TrimSpace(hello.ServerName) != "" {
				host = hello.ServerName
			}
			return c.LeafCertificateForHost(host)
		},
	}
}

func normalizeCertHost(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return "localhost"
	}
	if splitHost, _, err := net.SplitHostPort(h); err == nil && splitHost != "" {
		h = splitHost
	}
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "localhost"
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	return strings.ToLower(h)
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generating certificate serial number: %w", err)
	}
	if serial.Sign() <= 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}
