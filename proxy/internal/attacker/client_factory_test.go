package attacker_test

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy/internal/attacker"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/types"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/upstream"
)

// mockConn is a mock implementation of net.Conn for testing.
type mockConn struct {
	net.Conn
}

func TestDefaultClientFactory(t *testing.T) {
	factory := attacker.NewDefaultClientFactory()

	t.Run("CreateMainClient", func(t *testing.T) {
		c := qt.New(t)
		upstreamManager := upstream.NewManager("", false)
		client := factory.CreateMainClient(upstreamManager, false)

		c.Assert(client, qt.IsNotNil, qt.Commentf("expected client to be created"))
		c.Assert(client.Transport, qt.IsNotNil, qt.Commentf("expected transport to be set"))
		c.Assert(client.CheckRedirect, qt.IsNotNil, qt.Commentf("expected CheckRedirect to be set"))
	})

	t.Run("CreateHTTP2Client", func(t *testing.T) {
		c := qt.New(t)
		// Create a mock TLS connection
		tlsConn := &tls.Conn{}
		client := factory.CreateHTTP2Client(tlsConn)

		c.Assert(client, qt.IsNotNil, qt.Commentf("expected client to be created"))
		c.Assert(client.Transport, qt.IsNotNil, qt.Commentf("expected transport to be set"))
	})

	t.Run("CreatePlainHTTPClient", func(t *testing.T) {
		c := qt.New(t)
		conn := &mockConn{}
		client := factory.CreatePlainHTTPClient(conn)

		c.Assert(client, qt.IsNotNil, qt.Commentf("expected client to be created"))
		c.Assert(client.Transport, qt.IsNotNil, qt.Commentf("expected transport to be set"))
	})

	t.Run("CreateHTTPSClient", func(t *testing.T) {
		c := qt.New(t)
		tlsConn := &tls.Conn{}
		client := factory.CreateHTTPSClient(tlsConn)

		c.Assert(client, qt.IsNotNil, qt.Commentf("expected client to be created"))
		c.Assert(client.Transport, qt.IsNotNil, qt.Commentf("expected transport to be set"))
	})
}

// customClientFactory is a test implementation of types.ClientFactory.
type customClientFactory struct {
	mainClientCalled      bool
	http2ClientCalled     bool
	plainHTTPClientCalled bool
	httpsClientCalled     bool
}

func (f *customClientFactory) CreateMainClient(upstreamManager types.UpstreamManager, insecureSkipVerify bool) *http.Client {
	f.mainClientCalled = true
	return &http.Client{}
}

func (f *customClientFactory) CreateHTTP2Client(tlsConn *tls.Conn) *http.Client {
	f.http2ClientCalled = true
	return &http.Client{}
}

func (f *customClientFactory) CreatePlainHTTPClient(conn net.Conn) *http.Client {
	f.plainHTTPClientCalled = true
	return &http.Client{}
}

func (f *customClientFactory) CreateHTTPSClient(tlsConn *tls.Conn) *http.Client {
	f.httpsClientCalled = true
	return &http.Client{}
}

func TestCustomClientFactory(t *testing.T) {
	factory := &customClientFactory{}

	t.Run("CreateMainClient is called", func(t *testing.T) {
		c := qt.New(t)
		upstreamManager := upstream.NewManager("", false)
		factory.CreateMainClient(upstreamManager, false)

		c.Assert(factory.mainClientCalled, qt.IsTrue, qt.Commentf("expected CreateMainClient to be called"))
	})

	t.Run("CreateHTTP2Client is called", func(t *testing.T) {
		c := qt.New(t)
		tlsConn := &tls.Conn{}
		factory.CreateHTTP2Client(tlsConn)

		c.Assert(factory.http2ClientCalled, qt.IsTrue, qt.Commentf("expected CreateHTTP2Client to be called"))
	})

	t.Run("CreatePlainHTTPClient is called", func(t *testing.T) {
		c := qt.New(t)
		conn := &mockConn{}
		factory.CreatePlainHTTPClient(conn)

		c.Assert(factory.plainHTTPClientCalled, qt.IsTrue, qt.Commentf("expected CreatePlainHTTPClient to be called"))
	})

	t.Run("CreateHTTPSClient is called", func(t *testing.T) {
		c := qt.New(t)
		tlsConn := &tls.Conn{}
		factory.CreateHTTPSClient(tlsConn)

		c.Assert(factory.httpsClientCalled, qt.IsTrue, qt.Commentf("expected CreateHTTPSClient to be called"))
	})
}
