package types

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/http2"

	"github.com/denisvmedia/go-mitmproxy/internal/helper"
)

// UpstreamManager defines the interface for managing upstream proxy connections.
// This interface allows external implementations to control how the proxy connects
// to upstream servers.
type UpstreamManager interface {
	// RealUpstreamProxy returns a function that resolves upstream proxy for HTTP client transport.
	// This is used by the HTTP client to determine the proxy for each request.
	// The returned function extracts the original request from the context and uses it
	// to determine the appropriate proxy.
	RealUpstreamProxy() func(*http.Request) (*url.URL, error)
}

// ClientFactory is responsible for creating HTTP clients for different scenarios.
// This allows external customization of client creation logic for patching and testing.
type ClientFactory interface {
	// CreateMainClient creates the main fallback/separate client.
	// Used when the request has been modified (different host/scheme) or when
	// UseSeparateClient is set. This client goes through the upstream proxy and supports
	// HTTP/2. It creates new connections rather than reusing existing ones.
	CreateMainClient(upstreamManager UpstreamManager, insecureSkipVerify bool) *http.Client

	// CreateHTTP2Client creates an HTTP/2 server connection client.
	// Created specifically for HTTP/2 connections when the negotiated protocol
	// is "h2". Uses http2.Transport and reuses the existing TLS connection
	// rather than creating new connections.
	CreateHTTP2Client(tlsConn *tls.Conn) *http.Client

	// CreatePlainHTTPClient creates a plain HTTP connection client.
	// Created for plain HTTP (non-TLS) connections. Explicitly disables HTTP/2
	// and reuses the existing plain connection via custom DialContext function.
	// This avoids creating new connections for each request on the same HTTP connection.
	CreatePlainHTTPClient(conn net.Conn) *http.Client

	// CreateHTTPSClient creates an HTTPS/TLS connection client.
	// Created for HTTPS connections after TLS handshake. Reuses the established
	// TLS connection via custom DialTLSContext function and allows HTTP/2
	// negotiation. This maintains persistent connections to upstream servers.
	CreateHTTPSClient(tlsConn *tls.Conn) *http.Client
}

// DefaultClientFactory is the default implementation of ClientFactory.
// It creates clients with the standard configuration used by the proxy.
type DefaultClientFactory struct{}

// NewDefaultClientFactory creates a new DefaultClientFactory.
func NewDefaultClientFactory() *DefaultClientFactory {
	return &DefaultClientFactory{}
}

// CreateMainClient implements ClientFactory.
func (*DefaultClientFactory) CreateMainClient(upstreamManager UpstreamManager, insecureSkipVerify bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:              upstreamManager.RealUpstreamProxy(),
			ForceAttemptHTTP2:  true,
			DisableCompression: true, // To get the original response from the server, set Transport.DisableCompression to true.
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecureSkipVerify,
				KeyLogWriter:       helper.GetTLSKeyLogWriter(),
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// Disable automatic redirects
			return http.ErrUseLastResponse
		},
	}
}

// CreateHTTP2Client implements ClientFactory.
func (*DefaultClientFactory) CreateHTTP2Client(tlsConn *tls.Conn) *http.Client {
	return &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				return tlsConn, nil
			},
			DisableCompression: true,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// Disable automatic redirects
			return http.ErrUseLastResponse
		},
	}
}

// CreatePlainHTTPClient implements ClientFactory.
func (*DefaultClientFactory) CreatePlainHTTPClient(conn net.Conn) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return conn, nil
			},
			ForceAttemptHTTP2:  false, // disable http2
			DisableCompression: true,  // To get the original response from the server, set Transport.DisableCompression to true.
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// Disable automatic redirects
			return http.ErrUseLastResponse
		},
	}
}

// CreateHTTPSClient implements ClientFactory.
func (*DefaultClientFactory) CreateHTTPSClient(tlsConn *tls.Conn) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return tlsConn, nil
			},
			ForceAttemptHTTP2:  true,
			DisableCompression: true, // To get the original response from the server, set Transport.DisableCompression to true.
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// Disable automatic redirects
			return http.ErrUseLastResponse
		},
	}
}

