package proxy_test

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/upstream"
)

type mockConn struct {
	net.Conn
}

func (*mockConn) Close() error                     { return nil }
func (*mockConn) Read(b []byte) (int, error)       { return 0, nil }
func (*mockConn) Write(b []byte) (int, error)      { return len(b), nil }
func (*mockConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*mockConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*mockConn) SetDeadline(time.Time) error      { return nil }
func (*mockConn) SetReadDeadline(time.Time) error  { return nil }
func (*mockConn) SetWriteDeadline(time.Time) error { return nil }

func TestDefaultClientFactoryCreatesMainClientWithHTTP2(t *testing.T) {
	c := qt.New(t)

	factory := proxy.NewDefaultClientFactory()
	upstreamMgr := upstream.NewManager("", false)

	client := factory.CreateMainClient(upstreamMgr, false)

	c.Assert(client, qt.IsNotNil)
	c.Assert(client.Transport, qt.IsNotNil)
	c.Assert(client.CheckRedirect, qt.IsNotNil)
}

func TestDefaultClientFactoryCreatesPlainHTTPClient(t *testing.T) {
	c := qt.New(t)

	factory := proxy.NewDefaultClientFactory()
	mockConn := &mockConn{}

	client := factory.CreatePlainHTTPClient(mockConn)

	c.Assert(client, qt.IsNotNil)
	c.Assert(client.Transport, qt.IsNotNil)
}

func TestDefaultClientFactoryCreatesHTTPSClient(t *testing.T) {
	c := qt.New(t)

	factory := proxy.NewDefaultClientFactory()
	tlsConn := tls.Client(&mockConn{}, &tls.Config{})

	client := factory.CreateHTTPSClient(tlsConn)

	c.Assert(client, qt.IsNotNil)
	c.Assert(client.Transport, qt.IsNotNil)
}
