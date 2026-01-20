// Justification for whitebox testing:
// The entry type and its ServeHTTP method are internal to the proxy package.
// Testing the entry's request routing logic, addon event triggers, authentication,
// and lifecycle methods requires access to the unexported entry field of Proxy.
// These tests verify critical internal behavior that cannot be tested via the public API alone.

package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/cert"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/conn"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/proxycontext"
)

type testAddon struct {
	BaseAddon
	requestheadersCalled    bool
	responseheadersCalled   bool
	accessProxyServerCalled bool
}

func (a *testAddon) Requestheaders(f *Flow) {
	a.requestheadersCalled = true
}

func (a *testAddon) Responseheaders(f *Flow) {
	a.responseheadersCalled = true
}

func (a *testAddon) AccessProxyServer(req *http.Request, res http.ResponseWriter) {
	a.accessProxyServerCalled = true
	res.WriteHeader(200)
	_, _ = res.Write([]byte("addon handled"))
}

func TestEntryServeHTTPDirectRequestTriggersAccessProxyServer(t *testing.T) {
	c := qt.New(t)

	ca, err := cert.NewSelfSignCAMemory()
	c.Assert(err, qt.IsNil)

	config := Config{Addr: ":0"}
	p, err := NewProxy(config, ca)
	c.Assert(err, qt.IsNil)

	addon := &testAddon{}
	p.AddAddon(addon)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	clientConn := conn.NewClientConn(&mockConn{})
	connCtx := conn.NewContext(clientConn)
	ctx := proxycontext.WithConnContext(req.Context(), connCtx)
	req = req.WithContext(ctx)

	p.entry.ServeHTTP(rec, req)

	c.Assert(addon.accessProxyServerCalled, qt.IsTrue)
	c.Assert(rec.Code, qt.Equals, 200)
	c.Assert(rec.Body.String(), qt.Equals, "addon handled")
}

func TestEntryServeHTTPDirectRequestWithoutAddonReturns400(t *testing.T) {
	c := qt.New(t)

	ca, err := cert.NewSelfSignCAMemory()
	c.Assert(err, qt.IsNil)

	config := Config{Addr: ":0"}
	p, err := NewProxy(config, ca)
	c.Assert(err, qt.IsNil)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	clientConn := conn.NewClientConn(&mockConn{})
	connCtx := conn.NewContext(clientConn)
	ctx := proxycontext.WithConnContext(req.Context(), connCtx)
	req = req.WithContext(ctx)

	p.entry.ServeHTTP(rec, req)

	c.Assert(rec.Code, qt.Equals, 400)
	c.Assert(rec.Body.String(), qt.Contains, "This is a proxy server")
}

func TestEntryServeHTTPWithProxyAuthRequiresAuthentication(t *testing.T) {
	c := qt.New(t)

	ca, err := cert.NewSelfSignCAMemory()
	c.Assert(err, qt.IsNil)

	config := Config{Addr: ":0"}
	p, err := NewProxy(config, ca)
	c.Assert(err, qt.IsNil)

	p.SetAuthProxy(func(res http.ResponseWriter, req *http.Request) (bool, error) {
		auth := req.Header.Get("Proxy-Authorization")
		return auth == "valid-token", nil
	})

	req := httptest.NewRequest("GET", "http://example.com", nil)
	rec := httptest.NewRecorder()

	clientConn := conn.NewClientConn(&mockConn{})
	connCtx := conn.NewContext(clientConn)
	ctx := proxycontext.WithConnContext(req.Context(), connCtx)
	req = req.WithContext(ctx)

	p.entry.ServeHTTP(rec, req)

	c.Assert(rec.Code, qt.Equals, http.StatusProxyAuthRequired)
}

func TestEntryServeHTTPWithValidProxyAuthProceeds(t *testing.T) {
	c := qt.New(t)

	ca, err := cert.NewSelfSignCAMemory()
	c.Assert(err, qt.IsNil)

	config := Config{Addr: ":0"}
	p, err := NewProxy(config, ca)
	c.Assert(err, qt.IsNil)

	p.SetAuthProxy(func(res http.ResponseWriter, req *http.Request) (bool, error) {
		auth := req.Header.Get("Proxy-Authorization")
		return auth == "valid-token", nil
	})

	addon := &testAddon{}
	p.AddAddon(addon)

	req := httptest.NewRequest("CONNECT", "https://example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "valid-token")
	rec := httptest.NewRecorder()

	clientConn := conn.NewClientConn(&mockConn{})
	connCtx := conn.NewContext(clientConn)
	ctx := proxycontext.WithConnContext(req.Context(), connCtx)
	req = req.WithContext(ctx)

	p.entry.ServeHTTP(rec, req)

	c.Assert(addon.requestheadersCalled, qt.IsTrue)
}

type mockConn struct {
	net.Conn
}

func (*mockConn) Close() error                { return nil }
func (*mockConn) Read(b []byte) (int, error)  { return 0, io.EOF }
func (*mockConn) Write(b []byte) (int, error) { return len(b), nil }
func (*mockConn) LocalAddr() net.Addr         { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080} }
func (*mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321}
}
func (*mockConn) SetDeadline(time.Time) error      { return nil }
func (*mockConn) SetReadDeadline(time.Time) error  { return nil }
func (*mockConn) SetWriteDeadline(time.Time) error { return nil }

func TestEntryServeHTTPCONNECTRequestTriggersRequestheaders(t *testing.T) {
	c := qt.New(t)

	ca, err := cert.NewSelfSignCAMemory()
	c.Assert(err, qt.IsNil)

	config := Config{Addr: ":0"}
	p, err := NewProxy(config, ca)
	c.Assert(err, qt.IsNil)

	p.SetShouldInterceptRule(func(req *http.Request) bool {
		return false
	})

	addon := &testAddon{}
	p.AddAddon(addon)

	req := httptest.NewRequest("CONNECT", "https://example.com:443", nil)
	rec := httptest.NewRecorder()

	clientConn := conn.NewClientConn(&mockConn{})
	connCtx := conn.NewContext(clientConn)
	ctx := proxycontext.WithConnContext(req.Context(), connCtx)
	req = req.WithContext(ctx)

	p.entry.ServeHTTP(rec, req)

	c.Assert(addon.requestheadersCalled, qt.IsTrue)
}

func TestEntryShutdownGracefullyStopsServer(t *testing.T) {
	c := qt.New(t)

	ca, err := cert.NewSelfSignCAMemory()
	c.Assert(err, qt.IsNil)

	config := Config{Addr: ":0"}
	p, err := NewProxy(config, ca)
	c.Assert(err, qt.IsNil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = p.Shutdown(ctx)
	c.Assert(err, qt.IsNil)
}

func TestEntryCloseImmediatelyStopsServer(t *testing.T) {
	c := qt.New(t)

	ca, err := cert.NewSelfSignCAMemory()
	c.Assert(err, qt.IsNil)

	config := Config{Addr: ":0"}
	p, err := NewProxy(config, ca)
	c.Assert(err, qt.IsNil)

	err = p.Close()
	c.Assert(err, qt.IsNil)
}
