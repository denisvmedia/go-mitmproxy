package proxy_test

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"testing"

	"github.com/andybalholm/brotli"
	qt "github.com/frankban/quicktest"
	"github.com/klauspost/compress/zstd"

	"github.com/denisvmedia/go-mitmproxy/proxy"
)

func TestResponseIsTextContentTypeForText(t *testing.T) {
	c := qt.New(t)

	resp := &proxy.Response{Header: make(map[string][]string)}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")

	c.Assert(resp.IsTextContentType(), qt.IsTrue)
}

func TestResponseIsTextContentTypeForJSON(t *testing.T) {
	c := qt.New(t)

	resp := &proxy.Response{Header: make(map[string][]string)}
	resp.Header.Set("Content-Type", "application/json")

	c.Assert(resp.IsTextContentType(), qt.IsTrue)
}

func TestResponseIsTextContentTypeForBinary(t *testing.T) {
	c := qt.New(t)

	resp := &proxy.Response{Header: make(map[string][]string)}
	resp.Header.Set("Content-Type", "application/octet-stream")

	c.Assert(resp.IsTextContentType(), qt.IsFalse)
}

func TestRequestDecodedBodyIdentity(t *testing.T) {
	c := qt.New(t)

	plain := []byte("hello world")
	req := &proxy.Request{Header: make(map[string][]string), Body: append([]byte(nil), plain...)}
	req.Header.Set("Content-Encoding", "identity")

	decoded, err := req.DecodedBody()

	c.Assert(err, qt.IsNil)
	c.Assert(decoded, qt.DeepEquals, plain)
}

func TestRequestDecodedBodyEmpty(t *testing.T) {
	c := qt.New(t)

	plain := []byte("hello world")
	req := &proxy.Request{Header: make(map[string][]string), Body: append([]byte(nil), plain...)}
	req.Header.Set("Content-Encoding", "")

	decoded, err := req.DecodedBody()

	c.Assert(err, qt.IsNil)
	c.Assert(decoded, qt.DeepEquals, plain)
}

func TestRequestDecodedBodyGzip(t *testing.T) {
	c := qt.New(t)

	plain := []byte("hello world")
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(plain)
	_ = w.Close()

	req := &proxy.Request{Header: make(map[string][]string), Body: append([]byte(nil), buf.Bytes()...)}
	req.Header.Set("Content-Encoding", "gzip")

	decoded, err := req.DecodedBody()

	c.Assert(err, qt.IsNil)
	c.Assert(decoded, qt.DeepEquals, plain)
}

func TestRequestDecodedBodyDeflate(t *testing.T) {
	c := qt.New(t)

	plain := []byte("hello world")
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = w.Write(plain)
	_ = w.Close()

	req := &proxy.Request{Header: make(map[string][]string), Body: append([]byte(nil), buf.Bytes()...)}
	req.Header.Set("Content-Encoding", "deflate")

	decoded, err := req.DecodedBody()

	c.Assert(err, qt.IsNil)
	c.Assert(decoded, qt.DeepEquals, plain)
}

func TestRequestDecodedBodyBrotli(t *testing.T) {
	c := qt.New(t)

	plain := []byte("hello world")
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	_, _ = w.Write(plain)
	_ = w.Close()

	req := &proxy.Request{Header: make(map[string][]string), Body: append([]byte(nil), buf.Bytes()...)}
	req.Header.Set("Content-Encoding", "br")

	decoded, err := req.DecodedBody()

	c.Assert(err, qt.IsNil)
	c.Assert(decoded, qt.DeepEquals, plain)
}

func TestRequestDecodedBodyZstd(t *testing.T) {
	c := qt.New(t)

	plain := []byte("hello world")
	var buf bytes.Buffer
	w, _ := zstd.NewWriter(&buf)
	_, _ = w.Write(plain)
	w.Close()

	req := &proxy.Request{Header: make(map[string][]string), Body: append([]byte(nil), buf.Bytes()...)}
	req.Header.Set("Content-Encoding", "zstd")

	decoded, err := req.DecodedBody()

	c.Assert(err, qt.IsNil)
	c.Assert(decoded, qt.DeepEquals, plain)
}

func TestRequestDecodedBodyUnsupportedEncoding(t *testing.T) {
	c := qt.New(t)

	plain := []byte("hello world")
	req := &proxy.Request{Header: make(map[string][]string), Body: append([]byte(nil), plain...)}
	req.Header.Set("Content-Encoding", "unknown")

	_, err := req.DecodedBody()

	c.Assert(err, qt.IsNotNil)
}

func TestResponseReplaceToDecodedBodySuccess(t *testing.T) {
	c := qt.New(t)

	plain := []byte("payload")
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(plain)
	_ = w.Close()

	resp := &proxy.Response{Header: make(map[string][]string)}
	resp.Body = append([]byte(nil), buf.Bytes()...)
	resp.Header.Set("Content-Encoding", "gzip")
	resp.Header.Set("Transfer-Encoding", "chunked")

	resp.ReplaceToDecodedBody()

	c.Assert(resp.Body, qt.DeepEquals, plain)
	c.Assert(resp.Header.Get("Content-Encoding"), qt.Equals, "")
	c.Assert(resp.Header.Get("Transfer-Encoding"), qt.Equals, "")
	c.Assert(resp.Header.Get("Content-Length"), qt.Equals, "7")
}

func TestResponseReplaceToDecodedBodyOnError(t *testing.T) {
	c := qt.New(t)

	broken := []byte("not gzip data")
	resp := &proxy.Response{Header: make(map[string][]string)}
	resp.Body = append([]byte(nil), broken...)
	resp.Header.Set("Content-Encoding", "gzip")

	resp.ReplaceToDecodedBody()

	c.Assert(resp.Body, qt.DeepEquals, broken)
	c.Assert(resp.Header.Get("Content-Encoding"), qt.Equals, "gzip")
}
