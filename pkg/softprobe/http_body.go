// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package softprobe // import "go.opentelemetry.io/obi/pkg/softprobe"

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/rand"
	"io"
	"maps"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

var httpMethodPrefixes = []string{
	"GET ",
	"POST ",
	"PUT ",
	"DELETE ",
	"PATCH ",
	"HEAD ",
	"OPTIONS ",
	"CONNECT ",
	"TRACE ",
	"PRI ",
}

func looksLikeHTTPPreface(peek []byte) bool {
	if len(peek) == 0 {
		return false
	}
	s := string(peek)
	for _, prefix := range httpMethodPrefixes {
		if len(s) >= len(prefix) {
			if strings.HasPrefix(s, prefix) {
				return true
			}
		} else if strings.HasPrefix(prefix, s) {
			return true
		}
	}
	return false
}

func sniffPayloadEncoding(raw []byte) string {
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		return "gzip"
	}
	if len(raw) >= 4 && raw[0] == 0x28 && raw[1] == 0xb5 && raw[2] == 0x2f && raw[3] == 0xfd {
		return "zstd"
	}
	return ""
}

func decodeHTTPBody(raw []byte, contentEncoding string, maxBytes int) ([]byte, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBodyBytes
	}
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	if enc == "" {
		enc = sniffPayloadEncoding(raw)
	}
	if enc == "" || enc == "identity" {
		if len(raw) > maxBytes {
			return slices.Clone(raw[:maxBytes]), false
		}
		return slices.Clone(raw), false
	}
	if comma := strings.IndexByte(enc, ','); comma >= 0 {
		enc = strings.TrimSpace(enc[:comma])
	}

	var (
		reader io.Reader
		closer io.Closer
	)
	switch enc {
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return clampBytes(raw, maxBytes), false
		}
		reader = gr
		closer = gr
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(raw))
		if err != nil {
			return clampBytes(raw, maxBytes), false
		}
		defer zr.Close()
		reader = zr
	case "deflate":
		if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
			reader = zr
			closer = zr
		} else {
			fr := flate.NewReader(bytes.NewReader(raw))
			reader = fr
			closer = fr
		}
	case "br":
		reader = brotli.NewReader(bytes.NewReader(raw))
	default:
		return clampBytes(raw, maxBytes), false
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}

	decoded, err := io.ReadAll(io.LimitReader(reader, int64(maxBytes)))
	if err != nil && len(decoded) == 0 {
		return clampBytes(raw, maxBytes), false
	}
	return decoded, true
}

func clampBytes(raw []byte, maxBytes int) []byte {
	if maxBytes > 0 && len(raw) > maxBytes {
		return slices.Clone(raw[:maxBytes])
	}
	return slices.Clone(raw)
}

func flattenHTTPHeader(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, vals := range h {
		if len(vals) > 0 {
			out[k] = strings.Join(vals, ", ")
		}
	}
	return out
}

func flattenAndTupleHTTPHeader(h http.Header) (map[string]string, []HeaderTuple) {
	if len(h) == 0 {
		return nil, nil
	}
	flat := make(map[string]string, len(h))
	keys := slices.Sorted(maps.Keys(h))
	var tuples []HeaderTuple
	for _, k := range keys {
		vals := h[k]
		if len(vals) == 0 {
			continue
		}
		flat[k] = strings.Join(vals, ", ")
		for _, v := range vals {
			tuples = append(tuples, HeaderTuple{Name: k, Value: v})
		}
	}
	return flat, tuples
}

func normalizeDecodedHeaderMap(headers map[string]string, decodedLen int, wasDecoded bool) map[string]string {
	if !wasDecoded || len(headers) == 0 {
		return headers
	}
	out := maps.Clone(headers)
	for k := range out {
		if strings.EqualFold(k, "Content-Encoding") || strings.EqualFold(k, "Transfer-Encoding") || strings.EqualFold(k, "Content-Length") {
			delete(out, k)
		}
	}
	out["Content-Length"] = strconv.Itoa(decodedLen)
	return out
}

func extractPortFromAddr(addr net.Addr) uint16 {
	if addr == nil {
		return 0
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok && tcpAddr.Port > 0 && tcpAddr.Port <= 65535 {
		return uint16(tcpAddr.Port)
	}
	_, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0
	}
	parsed, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(parsed)
}

func randomNonZeroTraceID() [16]byte {
	var id [16]byte
	_, _ = rand.Read(id[:])
	if id == ([16]byte{}) {
		id[15] = 1
	}
	return id
}

func randomNonZeroSpanID() [8]byte {
	var id [8]byte
	_, _ = rand.Read(id[:])
	if id == ([8]byte{}) {
		id[7] = 1
	}
	return id
}

func closeWriteHalf(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func spliceConnections(clientConn net.Conn, clientReader io.Reader, upstreamConn net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstreamConn, clientReader)
		closeWriteHalf(upstreamConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, upstreamConn)
		closeWriteHalf(clientConn)
		done <- struct{}{}
	}()
	<-done
	<-done
}
