package helper_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/internal/helper"
)

func TestReaderToBufferReturnsBufferWhenBelowLimit(t *testing.T) {
	c := qt.New(t)

	data := []byte("small payload")
	reader := bytes.NewReader(data)

	buf, nextReader, err := helper.ReaderToBuffer(reader, int64(len(data)+10))

	c.Assert(err, qt.IsNil)
	c.Assert(buf, qt.DeepEquals, data)
	c.Assert(nextReader, qt.IsNil)
}

func TestReaderToBufferReturnsStreamingReaderWhenAtLimit(t *testing.T) {
	c := qt.New(t)

	data := []byte("streaming payload")
	reader := bytes.NewReader(data)

	buf, nextReader, err := helper.ReaderToBuffer(reader, int64(len(data)))

	c.Assert(err, qt.IsNil)
	c.Assert(buf, qt.IsNil)

	all, readErr := io.ReadAll(nextReader)
	c.Assert(readErr, qt.IsNil)
	c.Assert(all, qt.DeepEquals, data)
}

func TestCanonicalAddrAddsDefaultHTTPPort(t *testing.T) {
	c := qt.New(t)

	u, _ := url.Parse("http://example.com/path")
	addr := helper.CanonicalAddr(u)

	c.Assert(addr, qt.Equals, "example.com:80")
}

func TestCanonicalAddrAddsDefaultHTTPSPort(t *testing.T) {
	c := qt.New(t)

	u, _ := url.Parse("https://example.com/path")
	addr := helper.CanonicalAddr(u)

	c.Assert(addr, qt.Equals, "example.com:443")
}

func TestCanonicalAddrPreservesExplicitPort(t *testing.T) {
	c := qt.New(t)

	u, _ := url.Parse("http://example.com:8080/path")
	addr := helper.CanonicalAddr(u)

	c.Assert(addr, qt.Equals, "example.com:8080")
}

func TestIsTLSDetectsTLSHandshake(t *testing.T) {
	c := qt.New(t)

	bufTLS := []byte{0x16, 0x03, 0x03, 0x00}
	c.Assert(helper.IsTLS(bufTLS), qt.IsTrue)
}

func TestIsTLSRejectsNonTLS(t *testing.T) {
	c := qt.New(t)

	bufNonTLS := []byte{0x15, 0x03, 0x04, 0x00}
	c.Assert(helper.IsTLS(bufNonTLS), qt.IsFalse)
}

func TestNewStructFromFileLoadsJSON(t *testing.T) {
	c := qt.New(t)

	type sample struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}

	content := []byte(`{"name":"alice","age":30}`)
	dir := t.TempDir()
	file := dir + "/sample.json"

	writeErr := os.WriteFile(file, content, 0o644)
	c.Assert(writeErr, qt.IsNil)

	var out sample
	loadErr := helper.NewStructFromFile(file, &out)

	c.Assert(loadErr, qt.IsNil)
	c.Assert(out.Name, qt.Equals, "alice")
	c.Assert(out.Age, qt.Equals, 30)
}

func TestResponseCheckMarksWrote(t *testing.T) {
	c := qt.New(t)

	recorder := httptest.NewRecorder()
	wrapped := helper.NewResponseCheck(recorder)

	wrapped.WriteHeader(http.StatusTeapot)
	_, writeErr := wrapped.Write([]byte("body"))

	c.Assert(writeErr, qt.IsNil)
	c.Assert(recorder.Code, qt.Equals, http.StatusTeapot)
	c.Assert(recorder.Body.String(), qt.Equals, "body")
}
