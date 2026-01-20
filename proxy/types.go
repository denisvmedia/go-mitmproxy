package proxy

import (
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/conn"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/types"
)

// Re-export types from internal packages for external use.
// This maintains backward compatibility while allowing internal packages to share types.

type (
	// Flow represents a complete HTTP request/response flow.
	Flow = types.Flow

	// Request represents an HTTP request in the proxy flow.
	Request = types.Request

	// Response represents an HTTP response in the proxy flow.
	Response = types.Response

	// ClientConn represents a client connection.
	ClientConn = conn.ClientConn

	// ServerConn represents a server connection.
	ServerConn = conn.ServerConn

	// ConnContext represents the connection context.
	ConnContext = conn.Context

	// Addon defines the interface for proxy addons.
	Addon = types.Addon

	// BaseAddon provides default no-op implementations of all Addon methods.
	BaseAddon = types.BaseAddon

	// UpstreamManager defines the interface for managing upstream proxy connections.
	UpstreamManager = types.UpstreamManager

	// ClientFactory is responsible for creating HTTP clients for different scenarios.
	ClientFactory = types.ClientFactory

	// DefaultClientFactory is the default implementation of ClientFactory.
	DefaultClientFactory = types.DefaultClientFactory
)

// NewDefaultClientFactory creates a new DefaultClientFactory.
func NewDefaultClientFactory() *DefaultClientFactory {
	return types.NewDefaultClientFactory()
}
