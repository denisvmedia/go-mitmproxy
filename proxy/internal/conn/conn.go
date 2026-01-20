package conn

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"

	uuid "github.com/satori/go.uuid"
	"go.uber.org/atomic"
)

// ClientConn represents a client connection.
type ClientConn struct {
	ID                 uuid.UUID
	Conn               net.Conn
	TLS                bool
	NegotiatedProtocol string
	UpstreamCert       bool // Connect to upstream server to look up certificate details. Default: True
	ClientHello        *tls.ClientHelloInfo
	CloseChan          chan struct{} // Channel that is closed when the connection is closed
}

// NewClientConn creates a new ClientConn instance.
func NewClientConn(c net.Conn) *ClientConn {
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

// ServerConn represents a server connection.
type ServerConn struct {
	ID       uuid.UUID
	Address  string
	Conn     net.Conn
	Client   *http.Client
	TLSConn  *tls.Conn
	TLSState *tls.ConnectionState
}

// NewServerConn creates a new ServerConn instance.
func NewServerConn() *ServerConn {
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

// GetTLSState returns the TLS connection state.
func (c *ServerConn) GetTLSState() *tls.ConnectionState {
	return c.TLSState
}

// Context represents the connection context for a proxy connection.
type Context struct {
	ClientConn         *ClientConn                 `json:"clientConn"`
	ServerConn         *ServerConn                 `json:"serverConn"`
	Intercept          bool                        `json:"intercept"` // Indicates whether to parse HTTPS
	FlowCount          atomic.Uint32               `json:"-"`         // Number of HTTP requests made on the same connection
	CloseAfterResponse bool                        // after http response, http server will close the connection
	DialFn             func(context.Context) error `json:"-"` // when begin request, if there no ServerConn, use this func to dial
}

// NewContext creates a new connection context.
func NewContext(clientConn *ClientConn) *Context {
	return &Context{
		ClientConn: clientConn,
	}
}

// ID returns the connection ID.
func (c *Context) ID() uuid.UUID {
	return c.ClientConn.ID
}

// ContextKey is the key for storing Context in context.Context.
var ContextKey = new(struct{})
