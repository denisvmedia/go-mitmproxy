package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"

	"golang.org/x/net/http2"

	"github.com/denisvmedia/go-mitmproxy/cert"
	"github.com/denisvmedia/go-mitmproxy/internal/helper"
	"github.com/denisvmedia/go-mitmproxy/proxy"
)

// CustomClientFactory demonstrates how to create a custom client factory
// for patching or modifying HTTP client behavior.
type CustomClientFactory struct {
	// Embed the default factory to reuse its methods
	*proxy.DefaultClientFactory
}

// NewCustomClientFactory creates a new custom client factory.
func NewCustomClientFactory() *CustomClientFactory {
	return &CustomClientFactory{
		DefaultClientFactory: proxy.NewDefaultClientFactory(),
	}
}

// CreateMainClient overrides the default main client creation.
// This example adds custom headers to all requests made by the main client.
func (f *CustomClientFactory) CreateMainClient(upstreamManager proxy.UpstreamManager, insecureSkipVerify bool) *http.Client {
	// Create the default client
	client := &http.Client{
		Transport: &customTransport{
			base: &http.Transport{
				Proxy:              upstreamManager.RealUpstreamProxy(),
				ForceAttemptHTTP2:  true,
				DisableCompression: true,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: insecureSkipVerify,
					KeyLogWriter:       helper.GetTLSKeyLogWriter(),
				},
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client
}

// customTransport wraps http.Transport to add custom behavior.
type customTransport struct {
	base *http.Transport
}

func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Add a custom header to all requests
	req.Header.Add("X-Custom-Proxy", "go-mitmproxy-custom")
	slog.Info("Custom transport: adding header", "url", req.URL.String())
	return t.base.RoundTrip(req)
}

// Example 2: A client factory that logs all client creations
type LoggingClientFactory struct {
	*proxy.DefaultClientFactory
}

func NewLoggingClientFactory() *LoggingClientFactory {
	return &LoggingClientFactory{
		DefaultClientFactory: proxy.NewDefaultClientFactory(),
	}
}

func (f *LoggingClientFactory) CreateMainClient(upstreamManager proxy.UpstreamManager, insecureSkipVerify bool) *http.Client {
	slog.Info("Creating main client")
	return f.DefaultClientFactory.CreateMainClient(upstreamManager, insecureSkipVerify)
}

func (f *LoggingClientFactory) CreateHTTP2Client(tlsConn *tls.Conn) *http.Client {
	slog.Info("Creating HTTP/2 client")
	return f.DefaultClientFactory.CreateHTTP2Client(tlsConn)
}

func (f *LoggingClientFactory) CreatePlainHTTPClient(conn net.Conn) *http.Client {
	slog.Info("Creating plain HTTP client")
	return f.DefaultClientFactory.CreatePlainHTTPClient(conn)
}

func (f *LoggingClientFactory) CreateHTTPSClient(tlsConn *tls.Conn) *http.Client {
	slog.Info("Creating HTTPS client")
	return f.DefaultClientFactory.CreateHTTPSClient(tlsConn)
}

// Example 3: A client factory that uses HTTP/2 for all connections
type ForceHTTP2ClientFactory struct {
	*proxy.DefaultClientFactory
}

func NewForceHTTP2ClientFactory() *ForceHTTP2ClientFactory {
	return &ForceHTTP2ClientFactory{
		DefaultClientFactory: proxy.NewDefaultClientFactory(),
	}
}

func (f *ForceHTTP2ClientFactory) CreatePlainHTTPClient(conn net.Conn) *http.Client {
	// Override to use HTTP/2 even for plain HTTP connections
	return &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				return conn, nil
			},
			DisableCompression: true,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func main() {
	ca, err := cert.NewSelfSignCA("")
	if err != nil {
		slog.Error("failed to create CA", "error", err)
		return
	}

	// Choose which factory to use:
	// 1. Custom factory with modified behavior
	// clientFactory := NewCustomClientFactory()

	// 2. Logging factory
	clientFactory := NewLoggingClientFactory()

	// 3. Force HTTP/2 factory
	// clientFactory := NewForceHTTP2ClientFactory()

	// Note: To use a custom client factory, you need to create the attacker manually
	// instead of using proxy.NewProxy. This gives you full control over the dependencies.
	slog.Info("This example demonstrates the ClientFactory interface")
	slog.Info("In a real implementation, you would need to create the attacker manually")
	slog.Info("and pass it to the proxy, or extend proxy.NewProxy to accept a ClientFactory")

	// For now, just use the standard proxy
	config := proxy.Config{
		Addr:              ":9080",
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxy(config, ca)
	if err != nil {
		slog.Error("failed to create proxy", "error", err)
		return
	}

	// The clientFactory variable is used to demonstrate the pattern
	_ = clientFactory

	if err := p.Start(); err != nil {
		slog.Error("proxy exited", "error", err)
	}
}

