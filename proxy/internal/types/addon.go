package types

import (
	"io"
	"net/http"

	"github.com/denisvmedia/go-mitmproxy/proxy/internal/conn"
)

// Addon defines the interface for proxy addons.
type Addon interface {
	// A client has connected to mitmproxy. Note that a connection can correspond to multiple HTTP requests.
	ClientConnected(*conn.ClientConn)

	// A client connection has been closed (either by us or the client).
	ClientDisconnected(*conn.ClientConn)

	// Mitmproxy has connected to a server.
	ServerConnected(*conn.Context)

	// A server connection has been closed (either by us or the server).
	ServerDisconnected(*conn.Context)

	// The TLS handshake with the server has been completed successfully.
	TLSEstablishedServer(*conn.Context)

	// HTTP request headers were successfully read. At this point, the body is empty.
	Requestheaders(*Flow)

	// The full HTTP request has been read.
	Request(*Flow)

	// HTTP response headers were successfully read. At this point, the body is empty.
	Responseheaders(*Flow)

	// The full HTTP response has been read.
	Response(*Flow)

	// Stream request body modifier
	StreamRequestModifier(*Flow, io.Reader) io.Reader

	// Stream response body modifier
	StreamResponseModifier(*Flow, io.Reader) io.Reader

	// onAccessProxyServer
	AccessProxyServer(req *http.Request, res http.ResponseWriter)
}

// AddonRegistry manages a collection of addons.
type AddonRegistry interface {
	Get() []Addon
}

// BaseAddon provides default no-op implementations of all Addon methods.
type BaseAddon struct{}

func (*BaseAddon) ClientConnected(*conn.ClientConn)                         {}
func (*BaseAddon) ClientDisconnected(*conn.ClientConn)                      {}
func (*BaseAddon) ServerConnected(*conn.Context)                            {}
func (*BaseAddon) ServerDisconnected(*conn.Context)                         {}
func (*BaseAddon) TLSEstablishedServer(*conn.Context)                       {}
func (*BaseAddon) Requestheaders(*Flow)                                     {}
func (*BaseAddon) Request(*Flow)                                            {}
func (*BaseAddon) Responseheaders(*Flow)                                    {}
func (*BaseAddon) Response(*Flow)                                           {}
func (*BaseAddon) StreamRequestModifier(_ *Flow, in io.Reader) io.Reader    { return in }
func (*BaseAddon) StreamResponseModifier(_ *Flow, in io.Reader) io.Reader   { return in }
func (*BaseAddon) AccessProxyServer(_ *http.Request, _ http.ResponseWriter) {}

// AddonNotifier defines the interface for notifying addons about connection events.
// This is used by the internal conn package to notify about disconnections.
type AddonNotifier interface {
	NotifyClientDisconnected(client *conn.ClientConn)
	NotifyServerDisconnected(connCtx *conn.Context)
}
