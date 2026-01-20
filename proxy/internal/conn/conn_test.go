package conn_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	uuid "github.com/satori/go.uuid"

	"github.com/denisvmedia/go-mitmproxy/proxy/internal/conn"
)

func TestNewClientConnCreatesInstanceWithID(t *testing.T) {
	c := qt.New(t)

	client := conn.NewClientConn(nil)

	c.Assert(client, qt.IsNotNil)
	c.Assert(client.ID, qt.Not(qt.Equals), uuid.UUID{})
	c.Assert(client.TLS, qt.IsFalse)
	c.Assert(client.UpstreamCert, qt.IsTrue)
}

func TestNewServerConnCreatesInstanceWithID(t *testing.T) {
	c := qt.New(t)

	server := conn.NewServerConn()

	c.Assert(server, qt.IsNotNil)
	c.Assert(server.ID, qt.Not(qt.Equals), uuid.UUID{})
}

func TestNewContextCreatesContextWithClientConn(t *testing.T) {
	c := qt.New(t)

	client := conn.NewClientConn(nil)
	connCtx := conn.NewContext(client)

	c.Assert(connCtx, qt.IsNotNil)
	c.Assert(connCtx.ClientConn, qt.Equals, client)
	c.Assert(connCtx.ID(), qt.Equals, client.ID)
}

func TestContextFlowCountStartsAtZero(t *testing.T) {
	c := qt.New(t)

	client := conn.NewClientConn(nil)
	connCtx := conn.NewContext(client)

	c.Assert(connCtx.FlowCount.Load(), qt.Equals, uint32(0))
}

func TestContextFlowCountCanIncrement(t *testing.T) {
	c := qt.New(t)

	client := conn.NewClientConn(nil)
	connCtx := conn.NewContext(client)

	connCtx.FlowCount.Store(5)

	c.Assert(connCtx.FlowCount.Load(), qt.Equals, uint32(5))
}
