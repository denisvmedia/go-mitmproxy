package proxycontext

import (
	"context"
	"net/http"

	"github.com/denisvmedia/go-mitmproxy/proxy/internal/conn"
)

type proxyContextKey string

// Private context keys.
var (
	connContextKey proxyContextKey = "connContext"
	proxyReqCtxKey proxyContextKey = "proxyReq"
)

// WithConnContext adds a connection context to the given context.
func WithConnContext(ctx context.Context, connCtx *conn.Context) context.Context {
	return context.WithValue(ctx, connContextKey, connCtx)
}

// GetConnContext retrieves the connection context from the given context.
func GetConnContext(ctx context.Context) (*conn.Context, bool) {
	connCtx, ok := ctx.Value(connContextKey).(*conn.Context)
	return connCtx, ok
}

// WithProxyRequest adds the original proxy request to the given context.
func WithProxyRequest(ctx context.Context, req *http.Request) context.Context {
	return context.WithValue(ctx, proxyReqCtxKey, req)
}

// GetProxyRequest retrieves the original proxy request from the given context.
func GetProxyRequest(ctx context.Context) (*http.Request, bool) {
	req, ok := ctx.Value(proxyReqCtxKey).(*http.Request)
	return req, ok
}
