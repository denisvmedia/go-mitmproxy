package attacker

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"

	"github.com/denisvmedia/go-mitmproxy/proxy/internal/types"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/upstream"
)

// mockConn is a mock implementation of net.Conn for testing.
type mockConn struct {
	net.Conn
}

func TestDefaultClientFactory(t *testing.T) {
	factory := NewDefaultClientFactory()

	t.Run("CreateMainClient", func(t *testing.T) {
		upstreamManager := upstream.NewManager("", false)
		client := factory.CreateMainClient(upstreamManager, false)

		if client == nil {
			t.Fatal("expected client to be created")
		}

		if client.Transport == nil {
			t.Fatal("expected transport to be set")
		}

		if client.CheckRedirect == nil {
			t.Fatal("expected CheckRedirect to be set")
		}
	})

	t.Run("CreateHTTP2Client", func(t *testing.T) {
		// Create a mock TLS connection
		tlsConn := &tls.Conn{}
		client := factory.CreateHTTP2Client(tlsConn)

		if client == nil {
			t.Fatal("expected client to be created")
		}

		if client.Transport == nil {
			t.Fatal("expected transport to be set")
		}
	})

	t.Run("CreatePlainHTTPClient", func(t *testing.T) {
		conn := &mockConn{}
		client := factory.CreatePlainHTTPClient(conn)

		if client == nil {
			t.Fatal("expected client to be created")
		}

		if client.Transport == nil {
			t.Fatal("expected transport to be set")
		}
	})

	t.Run("CreateHTTPSClient", func(t *testing.T) {
		tlsConn := &tls.Conn{}
		client := factory.CreateHTTPSClient(tlsConn)

		if client == nil {
			t.Fatal("expected client to be created")
		}

		if client.Transport == nil {
			t.Fatal("expected transport to be set")
		}
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
		upstreamManager := upstream.NewManager("", false)
		factory.CreateMainClient(upstreamManager, false)

		if !factory.mainClientCalled {
			t.Fatal("expected CreateMainClient to be called")
		}
	})

	t.Run("CreateHTTP2Client is called", func(t *testing.T) {
		tlsConn := &tls.Conn{}
		factory.CreateHTTP2Client(tlsConn)

		if !factory.http2ClientCalled {
			t.Fatal("expected CreateHTTP2Client to be called")
		}
	})

	t.Run("CreatePlainHTTPClient is called", func(t *testing.T) {
		conn := &mockConn{}
		factory.CreatePlainHTTPClient(conn)

		if !factory.plainHTTPClientCalled {
			t.Fatal("expected CreatePlainHTTPClient to be called")
		}
	})

	t.Run("CreateHTTPSClient is called", func(t *testing.T) {
		tlsConn := &tls.Conn{}
		factory.CreateHTTPSClient(tlsConn)

		if !factory.httpsClientCalled {
			t.Fatal("expected CreateHTTPSClient to be called")
		}
	})
}
