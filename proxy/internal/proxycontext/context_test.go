package proxycontext_test

import (
	"context"
	"net/http"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy/internal/conn"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/proxycontext"
)

func TestWithConnContextAndGetConnContext(t *testing.T) {
	c := qt.New(t)

	ctx := context.Background()
	connCtx := conn.NewContext(conn.NewClientConn(nil))

	newCtx := proxycontext.WithConnContext(ctx, connCtx)
	retrieved, ok := proxycontext.GetConnContext(newCtx)

	c.Assert(ok, qt.IsTrue)
	c.Assert(retrieved, qt.Equals, connCtx)
}

func TestGetConnContextReturnsFalseWhenNotPresent(t *testing.T) {
	c := qt.New(t)

	ctx := context.Background()
	_, ok := proxycontext.GetConnContext(ctx)

	c.Assert(ok, qt.IsFalse)
}

func TestWithProxyRequestAndGetProxyRequest(t *testing.T) {
	c := qt.New(t)

	ctx := context.Background()
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	newCtx := proxycontext.WithProxyRequest(ctx, req)
	retrieved, ok := proxycontext.GetProxyRequest(newCtx)

	c.Assert(ok, qt.IsTrue)
	c.Assert(retrieved, qt.Equals, req)
}

func TestGetProxyRequestReturnsFalseWhenNotPresent(t *testing.T) {
	c := qt.New(t)

	ctx := context.Background()
	_, ok := proxycontext.GetProxyRequest(ctx)

	c.Assert(ok, qt.IsFalse)
}
