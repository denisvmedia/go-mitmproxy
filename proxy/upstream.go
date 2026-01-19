package proxy

import (
	"context"
	"net"
	"net/http"
	"net/url"

	"github.com/denisvmedia/go-mitmproxy/internal/helper"
)

// UpstreamManager handles upstream proxy connections and configuration.
// It manages the logic for connecting to upstream servers and determining
// which proxy to use for each request.
type UpstreamManager struct {
	config        *Config
	upstreamProxy func(*http.Request) (*url.URL, error)
}

// NewUpstreamManager creates a new UpstreamManager with the given configuration.
func NewUpstreamManager(config *Config) *UpstreamManager {
	return &UpstreamManager{
		config: config,
	}
}

// SetUpstreamProxy sets a custom upstream proxy function.
// This function will be called to determine the proxy URL for each request.
// If not set, the manager will use the config.Upstream or environment variables.
func (u *UpstreamManager) SetUpstreamProxy(fn func(*http.Request) (*url.URL, error)) {
	u.upstreamProxy = fn
}

// GetUpstreamConn establishes a connection to the upstream server.
// It determines the appropriate proxy (if any) and creates a connection
// to the target server, either directly or through the proxy.
func (u *UpstreamManager) GetUpstreamConn(ctx context.Context, req *http.Request) (net.Conn, error) {
	proxyURL, err := u.GetUpstreamProxyURL(req)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	address := helper.CanonicalAddr(req.URL)
	if proxyURL != nil {
		conn, err = helper.GetProxyConn(ctx, proxyURL, address, u.config.SslInsecure)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	return conn, err
}

// GetUpstreamProxyURL returns the upstream proxy URL for a given request.
// It checks in order:
// 1. Custom upstream proxy function (if set via SetUpstreamProxy)
// 2. Config.Upstream (if configured)
// 3. Environment variables (HTTP_PROXY, HTTPS_PROXY, etc.)
func (u *UpstreamManager) GetUpstreamProxyURL(req *http.Request) (*url.URL, error) {
	if u.upstreamProxy != nil {
		return u.upstreamProxy(req)
	}
	if len(u.config.Upstream) > 0 {
		return url.Parse(u.config.Upstream)
	}
	cReq := &http.Request{URL: &url.URL{Scheme: "https", Host: req.Host}}
	return http.ProxyFromEnvironment(cReq)
}

// RealUpstreamProxy returns a function that resolves upstream proxy for HTTP client transport.
// This is used by the HTTP client to determine the proxy for each request.
// The returned function extracts the original request from the context and uses it
// to determine the appropriate proxy.
func (u *UpstreamManager) RealUpstreamProxy() func(*http.Request) (*url.URL, error) {
	return func(cReq *http.Request) (*url.URL, error) {
		req, ok := cReq.Context().Value(proxyReqCtxKey).(*http.Request)
		if !ok {
			panic("failed to get original request from context")
		}
		return u.GetUpstreamProxyURL(req)
	}
}
