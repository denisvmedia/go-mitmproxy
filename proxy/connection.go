package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"

	uuid "github.com/satori/go.uuid"
	"go.uber.org/atomic"
)

// client connection.
type ClientConn struct {
	ID                 uuid.UUID
	Conn               net.Conn
	TLS                bool
	NegotiatedProtocol string
	UpstreamCert       bool // Connect to upstream server to look up certificate details. Default: True
	clientHello        *tls.ClientHelloInfo
}

func newClientConn(c net.Conn) *ClientConn {
	return &ClientConn{
		ID:           uuid.NewV4(),
		Conn:         c,
		TLS:          false,
		UpstreamCert: true,
	}
}

func (c *ClientConn) MarshalJSON() ([]byte, error) {
	m := make(map[string]any)
	m["id"] = c.ID
	m["tls"] = c.TLS
	m["address"] = c.Conn.RemoteAddr().String()
	return json.Marshal(m)
}

// server connection.
type ServerConn struct {
	ID      uuid.UUID
	Address string
	Conn    net.Conn

	client   *http.Client
	tlsConn  *tls.Conn
	tlsState *tls.ConnectionState
}

func newServerConn() *ServerConn {
	return &ServerConn{
		ID: uuid.NewV4(),
	}
}

func (c *ServerConn) MarshalJSON() ([]byte, error) {
	m := make(map[string]any)
	m["id"] = c.ID
	m["address"] = c.Address
	peername := ""
	if c.Conn != nil {
		peername = c.Conn.RemoteAddr().String()
	}
	m["peername"] = peername
	return json.Marshal(m)
}

func (c *ServerConn) TLSState() *tls.ConnectionState {
	return c.tlsState
}

// connection context ctx key.
var connContextKey = new(struct{})

// connection context.
type ConnContext struct {
	ClientConn *ClientConn   `json:"clientConn"`
	ServerConn *ServerConn   `json:"serverConn"`
	Intercept  bool          `json:"intercept"` // Indicates whether to parse HTTPS
	FlowCount  atomic.Uint32 `json:"-"`         // Number of HTTP requests made on the same connection

	proxy              *Proxy
	closeAfterResponse bool                        // after http response, http server will close the connection
	dialFn             func(context.Context) error // when begin request, if there no ServerConn, use this func to dial
}

func newConnContext(c net.Conn, proxy *Proxy) *ConnContext {
	clientConn := newClientConn(c)
	return &ConnContext{
		ClientConn: clientConn,
		proxy:      proxy,
	}
}

func (cc *ConnContext) ID() uuid.UUID {
	return cc.ClientConn.ID
}
