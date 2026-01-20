// Justification for whitebox testing:
// These tests need access to Attacker's internal fields (clientFactory, listener) and
// helper functions (logErr, httpError) to verify behavior that is not exposed via the
// public API. The functionality under test is internal to the attacker package.

package attacker

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/cert"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/addonregistry"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/types"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/upstream"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/websocket"
)

type stubClientFactory struct {
	mainCalled bool
}

func (f *stubClientFactory) CreateMainClient(types.UpstreamManager, bool) *http.Client {
	f.mainCalled = true
	return &http.Client{}
}

func (*stubClientFactory) CreateHTTP2Client(*tls.Conn) *http.Client {
	return &http.Client{}
}

func (*stubClientFactory) CreatePlainHTTPClient(net.Conn) *http.Client {
	return &http.Client{}
}

func (*stubClientFactory) CreateHTTPSClient(*tls.Conn) *http.Client {
	return &http.Client{}
}

func TestNewUsesCustomClientFactory(t *testing.T) {
	c := qt.New(t)

	ca, err := cert.NewSelfSignCAMemory()
	c.Assert(err, qt.IsNil)

	factory := &stubClientFactory{}
	atk, err := New(Args{
		CA:                ca,
		UpstreamManager:   upstream.NewManager("", false),
		AddonRegistry:     addonregistry.New(),
		StreamLargeBodies: 1024,
		WSHandler:         websocket.New(),
		ClientFactory:     factory,
	})

	c.Assert(err, qt.IsNil)
	c.Assert(atk.clientFactory, qt.Equals, factory)
	c.Assert(factory.mainCalled, qt.IsTrue)
}

func TestNewDefaultsToDefaultClientFactory(t *testing.T) {
	c := qt.New(t)

	ca, err := cert.NewSelfSignCAMemory()
	c.Assert(err, qt.IsNil)

	atk, err := New(Args{
		CA:                ca,
		UpstreamManager:   upstream.NewManager("", false),
		AddonRegistry:     addonregistry.New(),
		StreamLargeBodies: 1024,
		WSHandler:         websocket.New(),
	})

	c.Assert(err, qt.IsNil)
	_, ok := atk.clientFactory.(*types.DefaultClientFactory)
	c.Assert(ok, qt.IsTrue)
}

func TestListenerAcceptReturnsConnection(t *testing.T) {
	c := qt.New(t)

	l := &listener{connChan: make(chan net.Conn, 1)}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	l.accept(clientConn)

	conn, err := l.Accept()
	c.Assert(err, qt.IsNil)
	c.Assert(conn, qt.Equals, clientConn)
}

func TestLogErrFiltersNormalErrors(t *testing.T) {
	c := qt.New(t)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	logErr(logger, errors.New("read: connection reset by peer"))
	c.Assert(buf.String(), qt.Contains, "level=DEBUG")

	buf.Reset()
	logErr(logger, errors.New("unexpected failure"))
	c.Assert(buf.String(), qt.Contains, "level=ERROR")
}

func TestHTTPErrorWritesExpectedHeaders(t *testing.T) {
	c := qt.New(t)

	rec := httptest.NewRecorder()
	httpError(rec, "boom", http.StatusProxyAuthRequired)

	res := rec.Result()
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)

	c.Assert(err, qt.IsNil)
	c.Assert(res.StatusCode, qt.Equals, http.StatusProxyAuthRequired)
	c.Assert(res.Header.Get("Proxy-Authenticate"), qt.Equals, `Basic realm="proxy"`)
	c.Assert(string(body), qt.Contains, "boom")
}
