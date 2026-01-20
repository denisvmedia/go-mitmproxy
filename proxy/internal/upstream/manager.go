package upstream

import (
	"context"
	"net"
	"net/http"
	"net/url"

	"github.com/denisvmedia/go-mitmproxy/internal/helper"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/proxycontext"
)

// Manager handles upstream proxy connections and configuration.
// It manages the logic for connecting to upstream servers and determining
// which proxy to use for each request.
type Manager struct {
	// upstream is the upstream proxy address (e.g., "http://proxy:8080").
	// If empty, the manager will use environment variables (HTTP_PROXY, HTTPS_PROXY).
	upstream string

	// sslInsecure controls whether to skip SSL certificate verification
	// when connecting to upstream servers.
	sslInsecure bool

	upstreamProxy func(*http.Request) (*url.URL, error)
}

// NewManager creates a new Manager with the given configuration.
// upstream is the upstream proxy address. If empty, environment variables will be used.
// sslInsecure controls whether to skip SSL certificate verification.
func NewManager(upstream string, sslInsecure bool) *Manager {
	return &Manager{
		upstream:    upstream,
		sslInsecure: sslInsecure,
	}
}

// SetUpstreamProxy sets a custom upstream proxy function.
// This function will be called to determine the proxy URL for each request.
// If not set, the manager will use the config.Upstream or environment variables.
func (m *Manager) SetUpstreamProxy(fn func(*http.Request) (*url.URL, error)) {
	m.upstreamProxy = fn
}

// GetUpstreamConn establishes a connection to the upstream server.
// It determines the appropriate proxy (if any) and creates a connection
// to the target server, either directly or through the proxy.
func (m *Manager) GetUpstreamConn(ctx context.Context, req *http.Request) (net.Conn, error) {
	proxyURL, err := m.GetUpstreamProxyURL(req)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	address := helper.CanonicalAddr(req.URL)
	if proxyURL != nil {
		conn, err = helper.GetProxyConn(ctx, proxyURL, address, m.sslInsecure)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	return conn, err
}

// GetUpstreamProxyURL returns the upstream proxy URL for a given request.
// It checks in order:
// 1. Custom upstream proxy function (if set via SetUpstreamProxy)
// 2. upstream field (if configured)
// 3. Environment variables (HTTP_PROXY, HTTPS_PROXY, etc.)
func (m *Manager) GetUpstreamProxyURL(req *http.Request) (*url.URL, error) {
	if m.upstreamProxy != nil {
		return m.upstreamProxy(req)
	}
	if len(m.upstream) > 0 {
		return url.Parse(m.upstream)
	}
	cReq := &http.Request{URL: &url.URL{Scheme: "https", Host: req.Host}}
	return http.ProxyFromEnvironment(cReq)
}

// RealUpstreamProxy returns a function that resolves upstream proxy for HTTP client transport.
// This is used by the HTTP client to determine the proxy for each request.
// The returned function extracts the original request from the context and uses it
// to determine the appropriate proxy.
func (m *Manager) RealUpstreamProxy() func(*http.Request) (*url.URL, error) {
	return func(cReq *http.Request) (*url.URL, error) {
		req, ok := proxycontext.GetProxyRequest(cReq.Context())
		if !ok {
			panic("failed to get original request from context")
		}
		return m.GetUpstreamProxyURL(req)
	}
}
