// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/http2"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/bhpack"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func ensureSoftprobeCapture(span *request.Span) *request.SoftprobeCapture {
	if span.Softprobe == nil {
		span.Softprobe = &request.SoftprobeCapture{}
	}
	return span.Softprobe
}

func cloneHTTPHeaders(h http.Header) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for k, vals := range h {
		copied := make([]string, len(vals))
		copy(copied, vals)
		out[k] = copied
	}
	return out
}

func extractQueryFromFullPath(fullPath string) string {
	if _, query, ok := strings.Cut(fullPath, "?"); ok {
		return query
	}
	return ""
}

func extractStatusReason(status string, statusCode int) string {
	if status != "" {
		codePrefix := strconv.Itoa(statusCode) + " "
		if after, ok := strings.CutPrefix(status, codePrefix); ok {
			return strings.TrimSpace(after)
		}
		if trimmed := strings.TrimSpace(status); trimmed != strconv.Itoa(statusCode) {
			return trimmed
		}
	}
	if statusCode > 0 {
		return http.StatusText(statusCode)
	}
	return ""
}

func readAndRestoreBody(rc io.ReadCloser, maxBytes int) ([]byte, io.ReadCloser) {
	if rc == nil || maxBytes <= 0 {
		return nil, rc
	}
	raw, _ := io.ReadAll(io.LimitReader(rc, int64(maxBytes)+1))
	_ = rc.Close()
	restored := io.NopCloser(bytes.NewReader(raw))
	if len(raw) > maxBytes {
		raw = raw[:maxBytes]
	}
	if len(raw) == 0 {
		return nil, restored
	}
	copied := make([]byte, len(raw))
	copy(copied, raw)
	return copied, restored
}

func decodeHTTPBodyEncoding(raw []byte, contentEncoding string, maxBytes int) ([]byte, bool) {
	if len(raw) == 0 || maxBytes <= 0 {
		return raw, false
	}
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	if enc == "" {
		enc = sniffContentEncoding(raw)
	}
	if enc == "" || enc == "identity" {
		return raw, false
	}
	if comma := strings.IndexByte(enc, ','); comma >= 0 {
		enc = strings.TrimSpace(enc[:comma])
	}

	var reader io.Reader
	var closer io.Closer
	switch enc {
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return raw, false
		}
		reader = gr
		closer = gr
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(raw))
		if err != nil {
			return raw, false
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
		return raw, false
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}

	decoded, err := io.ReadAll(io.LimitReader(reader, int64(maxBytes)))
	if err != nil && len(decoded) == 0 {
		return raw, false
	}
	return decoded, true
}

func captureSoftprobeHTTP(maxBytes int, span *request.Span, req *http.Request, resp *http.Response) {
	if span == nil || maxBytes <= 0 {
		return
	}
	sp := ensureSoftprobeCapture(span)
	if sp.RawQuery == "" {
		sp.RawQuery = extractQueryFromFullPath(span.FullPath)
	}

	if req != nil {
		reqHeaders := cloneHTTPHeaders(req.Header)
		if req.Host != "" {
			if reqHeaders == nil {
				reqHeaders = make(map[string][]string, 1)
			}
			if _, hasHost := reqHeaders["Host"]; !hasHost {
				reqHeaders["Host"] = []string{req.Host}
			}
		}
		sp.RequestHeaders = reqHeaders
		if req.URL != nil && req.URL.RawQuery != "" {
			sp.RawQuery = req.URL.RawQuery
		}

		rawReqBody, restoredReqBody := readAndRestoreBody(req.Body, maxBytes)
		req.Body = restoredReqBody
		if len(rawReqBody) > 0 {
			reqEncoding := ""
			if req.Header != nil {
				reqEncoding = req.Header.Get("Content-Encoding")
			}
			decodedReq, wasDecoded := decodeHTTPBodyEncoding(rawReqBody, reqEncoding, maxBytes)
			sp.RequestBody = decodedReq
			if wasDecoded && sp.RequestHeaders != nil {
				delete(sp.RequestHeaders, "Content-Encoding")
				delete(sp.RequestHeaders, "Transfer-Encoding")
				sp.RequestHeaders["Content-Length"] = []string{strconv.Itoa(len(decodedReq))}
			}
		}
	}

	if resp != nil {
		sp.ResponseHeaders = cloneHTTPHeaders(resp.Header)
		sp.StatusReason = extractStatusReason(resp.Status, resp.StatusCode)
		rawRespBody, restoredRespBody := readAndRestoreBody(resp.Body, maxBytes)
		resp.Body = restoredRespBody
		if len(rawRespBody) > 0 {
			respEncoding := ""
			if resp.Header != nil {
				respEncoding = resp.Header.Get("Content-Encoding")
			}
			decodedResp, wasDecoded := decodeHTTPBodyEncoding(rawRespBody, respEncoding, maxBytes)
			sp.ResponseBody = decodedResp
			if wasDecoded && sp.ResponseHeaders != nil {
				delete(sp.ResponseHeaders, "Content-Encoding")
				delete(sp.ResponseHeaders, "Transfer-Encoding")
				sp.ResponseHeaders["Content-Length"] = []string{strconv.Itoa(len(decodedResp))}
			}
		}
	}
}

func captureSoftprobeHTTPRequestBuffer(maxBytes int, span *request.Span, requestBuffer *largebuf.LargeBuffer) {
	if span == nil || maxBytes <= 0 {
		return
	}
	sp := ensureSoftprobeCapture(span)
	if sp.RawQuery == "" {
		sp.RawQuery = extractQueryFromFullPath(span.FullPath)
	}
	if requestBuffer == nil || requestBuffer.Len() == 0 {
		return
	}
	reqReader := requestBuffer.NewReader()
	req, err := http.ReadRequest(bufio.NewReader(&reqReader))
	if err != nil || req == nil {
		return
	}
	defer func() { _ = req.Body.Close() }()
	if req.ContentLength > 0 {
		recoverRequestBody(req, requestBuffer)
	}
	captureSoftprobeHTTP(maxBytes, span, req, nil)
}

func extractHTTP2HeadersAndBody(buffer *largebuf.LargeBuffer) ([]byte, http.Header, string, bool) {
	if buffer == nil || buffer.Len() == 0 {
		return nil, nil, "", false
	}
	reader := buffer.NewReader()
	if pre, err := reader.Peek(len(http2.ClientPreface)); err == nil && string(pre) == http2.ClientPreface {
		_ = reader.Skip(len(http2.ClientPreface))
	}

	framer := http2.NewFramer(io.Discard, &reader)
	framer.SetMaxReadFrameSize(maxHTTP2ReadFrameSize)

	header := http.Header{}
	var rawPath string
	seenFrame := false
	dec := bhpack.NewDecoder(initialHeaderTableSize, nil)
	dec.SetEmitFunc(func(hf bhpack.HeaderField) {
		if hf.Value == "" || hf.Name == "<BAD INDEX>" {
			return
		}
		if hf.Name == ":path" {
			rawPath = hf.Value
			return
		}
		if strings.HasPrefix(hf.Name, ":") {
			return
		}
		header.Add(hf.Name, hf.Value)
	})

	var body []byte
	for {
		f, err := framer.ReadFrame()
		if err != nil {
			break
		}
		switch ff := f.(type) {
		case *http2.HeadersFrame:
			seenFrame = true
			decodeHTTP2HeaderBlock(dec, framer, ff)
		case *http2.DataFrame:
			seenFrame = true
			body = append(body, ff.Data()...)
			if ff.StreamEnded() {
				return body, header, rawPath, true
			}
		}
	}

	return body, header, rawPath, seenFrame && (len(body) > 0 || len(header) > 0)
}

func parseHTTP2RequestForSoftprobe(buffer *largebuf.LargeBuffer, span *request.Span) (*http.Request, bool) {
	body, header, rawPath, ok := extractHTTP2HeadersAndBody(buffer)
	if !ok {
		return nil, false
	}
	rawQuery := extractQueryFromFullPath(span.FullPath)
	if rawQuery == "" {
		rawQuery = extractQueryFromFullPath(rawPath)
	}
	req := &http.Request{
		Method:        span.Method,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        header,
		Host:          span.Host,
		URL:           &url.URL{Path: span.Path, RawQuery: rawQuery, Host: span.Host},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	return req, true
}

func parseHTTP2ResponseForSoftprobe(buffer *largebuf.LargeBuffer, req *http.Request, span *request.Span) (*http.Response, bool) {
	body, header, _, ok := extractHTTP2HeadersAndBody(buffer)
	if !ok {
		return nil, false
	}
	if header.Get("Content-Encoding") == "" {
		if enc := sniffContentEncoding(body); enc != "" {
			header.Set("Content-Encoding", enc)
		}
	}
	resp := &http.Response{
		StatusCode:    span.Status,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
	return resp, true
}

func captureSoftprobeHTTP2KProbe(maxBytes int, span *request.Span, event *BPFHTTP2Info, reqHeaders, respHeaders map[string][]string) {
	if span == nil || maxBytes <= 0 || event == nil {
		return
	}
	sp := ensureSoftprobeCapture(span)
	if sp.RawQuery == "" {
		sp.RawQuery = extractQueryFromFullPath(span.FullPath)
	}
	if len(reqHeaders) > 0 {
		sp.RequestHeaders = cloneHTTPHeaders(reqHeaders)
	}
	if len(respHeaders) > 0 {
		sp.ResponseHeaders = cloneHTTPHeaders(respHeaders)
	}
	if sp.StatusReason == "" && span.Status > 0 {
		sp.StatusReason = http.StatusText(span.Status)
	}

	reqLen := min(max(int(event.Len), 0), len(event.Data))
	if reqLen > 0 {
		if body, hdrs, rawPath, ok := extractHTTP2HeadersAndBody(largebuf.NewLargeBufferFrom(event.Data[:reqLen])); ok {
			if len(sp.RequestHeaders) == 0 && len(hdrs) > 0 {
				sp.RequestHeaders = cloneHTTPHeaders(hdrs)
			}
			if sp.RawQuery == "" && rawPath != "" {
				sp.RawQuery = extractQueryFromFullPath(rawPath)
			}
			if len(body) > 0 {
				if len(body) > maxBytes {
					body = body[:maxBytes]
				}
				enc := ""
				if sp.RequestHeaders != nil {
					if vals := sp.RequestHeaders["Content-Encoding"]; len(vals) > 0 {
						enc = vals[0]
					}
				}
				decoded, _ := decodeHTTPBodyEncoding(body, enc, maxBytes)
				sp.RequestBody = decoded
			}
		}
	}

	if len(event.RetData) > 0 {
		if body, hdrs, _, ok := extractHTTP2HeadersAndBody(largebuf.NewLargeBufferFrom(event.RetData[:])); ok {
			if len(sp.ResponseHeaders) == 0 && len(hdrs) > 0 {
				sp.ResponseHeaders = cloneHTTPHeaders(hdrs)
			}
			if len(body) > 0 {
				if len(body) > maxBytes {
					body = body[:maxBytes]
				}
				enc := ""
				if sp.ResponseHeaders != nil {
					if vals := sp.ResponseHeaders["Content-Encoding"]; len(vals) > 0 {
						enc = vals[0]
					}
				}
				decoded, wasDecoded := decodeHTTPBodyEncoding(body, enc, maxBytes)
				sp.ResponseBody = decoded
				if wasDecoded && sp.ResponseHeaders != nil {
					delete(sp.ResponseHeaders, "Content-Encoding")
					sp.ResponseHeaders["Content-Length"] = []string{strconv.Itoa(len(decoded))}
				}
			}
		}
	}
}

func copyBoundedLargeBuffer(buf *largebuf.LargeBuffer, maxBytes int) []byte {
	if buf == nil || buf.Len() == 0 || maxBytes <= 0 {
		return nil
	}
	view := buf.UnsafeView()
	n := min(len(view), maxBytes)
	out := make([]byte, n)
	copy(out, view[:n])
	return out
}

func captureSoftprobeTCP(maxBytes int, span *request.Span, requestBuffer, responseBuffer *largebuf.LargeBuffer, reversed bool) {
	if span == nil || maxBytes <= 0 {
		return
	}
	reqBuf, respBuf := requestBuffer, responseBuffer
	if reversed {
		reqBuf, respBuf = responseBuffer, requestBuffer
	}

	switch span.Type {
	case request.EventTypeSQLClient:
		sp := ensureSoftprobeCapture(span)
		sp.SQLWireRequest = copyBoundedLargeBuffer(reqBuf, maxBytes)
		sp.SQLWireResponse = copyBoundedLargeBuffer(respBuf, maxBytes)
	case request.EventTypeRedisClient:
		sp := ensureSoftprobeCapture(span)
		sp.RedisWireReq = copyBoundedLargeBuffer(reqBuf, maxBytes)
		sp.RedisWireResp = copyBoundedLargeBuffer(respBuf, maxBytes)
	}
}

func captureSoftprobeGoRedis(maxBytes int, span *request.Span, rawReq []byte) {
	if span == nil || maxBytes <= 0 || len(rawReq) == 0 {
		return
	}
	sp := ensureSoftprobeCapture(span)
	n := min(len(rawReq), maxBytes)
	sp.RedisWireReq = make([]byte, n)
	copy(sp.RedisWireReq, rawReq[:n])
}
