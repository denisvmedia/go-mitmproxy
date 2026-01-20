package addons_test

import (
	"bytes"
	"compress/gzip"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy"
	"github.com/denisvmedia/go-mitmproxy/proxy/addons"
)

func TestDecoderResponseWithoutEncoding(t *testing.T) {
	c := qt.New(t)

	body := []byte("hello world")
	resp := &proxy.Response{
		StatusCode: 200,
		Header:     make(map[string][]string),
		Body:       append([]byte(nil), body...),
	}
	resp.Header.Set("Content-Encoding", "identity")
	resp.Header.Set("Transfer-Encoding", "chunked")

	flow := &proxy.Flow{
		Request:  &proxy.Request{},
		Response: resp,
	}

	decoder := &addons.Decoder{}
	decoder.Response(flow)

	c.Assert(flow.Response.Body, qt.DeepEquals, body)
	c.Assert(flow.Response.Header.Get("Content-Encoding"), qt.Equals, "")
	c.Assert(flow.Response.Header.Get("Transfer-Encoding"), qt.Equals, "")
	c.Assert(flow.Response.Header.Get("Content-Length"), qt.Equals, "11")
}

func TestDecoderResponseWithGzipEncoding(t *testing.T) {
	c := qt.New(t)

	plainBody := []byte("compressed body")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write(plainBody)
	_ = gz.Close()

	resp := &proxy.Response{
		StatusCode: 200,
		Header:     make(map[string][]string),
		Body:       append([]byte(nil), buf.Bytes()...),
	}
	resp.Header.Set("Content-Encoding", "gzip")

	flow := &proxy.Flow{
		Request:  &proxy.Request{},
		Response: resp,
	}

	decoder := &addons.Decoder{}
	decoder.Response(flow)

	c.Assert(flow.Response.Body, qt.DeepEquals, plainBody)
	c.Assert(flow.Response.Header.Get("Content-Encoding"), qt.Equals, "")
	c.Assert(flow.Response.Header.Get("Content-Length"), qt.Equals, "15")
}
