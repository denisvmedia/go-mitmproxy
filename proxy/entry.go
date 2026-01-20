// Package proxy implements the HTTP/HTTPS MITM proxy server.
//
// This file (entry.go) contains the HTTP server entry point and request routing logic.
//
// # Overview
//
// The "entry" is the bridge between Go's standard HTTP server and the proxy's
// custom MITM logic. It serves as the initial request handler that routes traffic
// to appropriate handlers based on request type and configuration.
//
// # Architecture
//
// The entry system consists of three main components:
//
//  1. wrapListener: Wraps the TCP listener to intercept and prepare connections
//     - Attaches connection context (ConnContext) to each client connection
//     - Triggers ClientConnected addon events
//
//  2. entry: The HTTP server and request router
//     - Implements http.Handler via ServeHTTP
//     - Routes requests based on method and URL
//     - Manages proxy lifecycle (start, shutdown, close)
//
//  3. Request handlers: Process different types of requests
//     - ServeHTTP: Routes all incoming requests
//     - handleConnect: Handles CONNECT requests for HTTPS tunneling
//     - directTransfer: Transparent tunneling without interception
//     - httpsDialFirstAttack: MITM with upstream-first connection
//     - httpsDialLazyAttack: MITM with client-first connection
//
// # Request Flow
//
// HTTP Proxy Request:
//
//	Client → wrapListener → entry.ServeHTTP → attacker.Attack → Upstream
//
// CONNECT Request (Non-Intercepted):
//
//	Client → wrapListener → entry.ServeHTTP → handleConnect → directTransfer → Upstream
//
// CONNECT Request (Intercepted):
//
//	Client → wrapListener → entry.ServeHTTP → handleConnect → httpsDialLazyAttack → attacker → Upstream
//
// # Connection Context
//
// The entry system maintains connection-level state through ConnContext:
//   - Created by wrapListener.Accept() for each connection
//   - Attached to request context by entry.server.ConnContext
//   - Accessible throughout request lifecycle via proxycontext.GetConnContext()
//   - Contains client connection info, TLS state, interception settings, etc.
//
// # Interception Modes
//
// The proxy supports three modes for CONNECT requests:
//
//  1. Direct Transfer (shouldIntercept = false):
//     - Transparent TCP tunnel without inspection
//     - No certificate forgery
//     - Minimal overhead
//
//  2. Lazy Attack (default, UpstreamCert = false):
//     - Establishes client tunnel first
//     - Peeks at traffic to detect protocol
//     - Connects to upstream based on SNI
//
//  3. Dial-First Attack (UpstreamCert = true):
//     - Connects to upstream first
//     - Obtains real certificate
//     - Creates matching fake certificate for client
package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"

	"github.com/denisvmedia/go-mitmproxy/internal/helper"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/conn"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/proxycontext"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/types"
)

// wrapListener wraps a TCP listener to intercept incoming client connections.
// It decorates each accepted connection with proxy-specific context and triggers
// the ClientConnected addon event before returning the connection to the HTTP server.
//
// This wrapper is essential for:
//   - Creating and attaching connection context (ConnContext) to each client connection
//   - Wrapping raw connections in WrapClientConn for buffering and peeking capabilities
//   - Notifying addons when a new client connects to the proxy
type wrapListener struct {
	net.Listener
	proxy *Proxy
}

func (l *wrapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	proxy := l.proxy
	wc := conn.NewWrapClientConn(c, proxy)

	// Create conn context - this is now the single source of truth
	clientConn := conn.NewClientConn(wc)
	clientConn.CloseChan = wc.CloseChan // Share the close channel
	connCtx := conn.NewContext(clientConn)
	wc.ConnCtx = connCtx

	for _, addon := range proxy.addonRegistry.Get() {
		addon.ClientConnected(connCtx.ClientConn)
	}

	return wc, nil
}

// entry is the HTTP server entry point for the MITM proxy.
//
// The entry struct serves as the bridge between the standard Go HTTP server
// and the proxy's custom request handling logic. It implements http.Handler
// to process incoming HTTP/HTTPS requests and route them appropriately.
//
// Architecture:
//   - Wraps a standard http.Server to leverage Go's HTTP infrastructure
//   - Implements http.Handler interface via ServeHTTP method
//   - Acts as the initial request router, distinguishing between:
//   - CONNECT requests (for HTTPS tunneling)
//   - Regular HTTP proxy requests
//   - Direct requests to the proxy server itself
//
// Lifecycle:
//   - Created by newEntry() during Proxy initialization
//   - Started by start() which begins listening for connections
//   - Stopped by close() for immediate shutdown or shutdown() for graceful shutdown
//
// Request Flow:
//  1. Client connects → wrapListener.Accept() wraps connection
//  2. HTTP server calls entry.ServeHTTP() for each request
//  3. ServeHTTP routes to appropriate handler:
//     - CONNECT → handleConnect() for HTTPS interception
//     - HTTP proxy → attacker.Attack() for HTTP interception
//     - Direct request → AccessProxyServer addon event
type entry struct {
	proxy  *Proxy
	server *http.Server
}

// newEntry creates a new entry point for the proxy server.
//
// This function initializes the HTTP server with custom configuration:
//   - Sets the entry itself as the HTTP handler (implements http.Handler)
//   - Configures ConnContext to attach proxy connection context to each request
//
// The ConnContext function is critical: it extracts the ConnContext from
// WrapClientConn (created by wrapListener) and stores it in the request's
// context.Context, making connection-level state available throughout the
// request lifecycle.
func newEntry(proxy *Proxy) *entry {
	e := &entry{proxy: proxy}
	e.server = &http.Server{
		Addr:    proxy.config.Addr,
		Handler: e,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if wc, ok := c.(*conn.WrapClientConn); ok {
				// Store the conn.Context in the shared context key
				return proxycontext.WithConnContext(ctx, wc.ConnCtx)
			}
			return ctx
		},
	}
	return e
}

// start begins listening for incoming proxy connections.
//
// This method:
//  1. Creates a TCP listener on the configured address (defaults to ":http" if not specified)
//  2. Wraps the listener in wrapListener to intercept and prepare connections
//  3. Starts the HTTP server with the wrapped listener
//
// This is a blocking call that runs until the server is shut down or encounters an error.
func (e *entry) start() error {
	addr := e.server.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	slog.Info("proxy listening", "addr", e.server.Addr)
	pln := &wrapListener{
		Listener: ln,
		proxy:    e.proxy,
	}
	return e.server.Serve(pln)
}

// close immediately stops the proxy server.
//
// This forcefully closes the listener and all active connections.
// Use shutdown() for graceful termination.
func (e *entry) close() error {
	return e.server.Close()
}

// shutdown gracefully stops the proxy server.
//
// This method waits for active connections to complete (up to the context deadline)
// before shutting down. New connections are not accepted after this is called.
func (e *entry) shutdown(ctx context.Context) error {
	return e.server.Shutdown(ctx)
}

// ServeHTTP implements http.Handler and is the main entry point for all HTTP requests.
//
// This method routes incoming requests based on their type:
//
// 1. Proxy Authentication (if configured):
//   - Validates credentials before processing any request
//   - Returns 407 Proxy Authentication Required on failure
//
// 2. CONNECT Requests (HTTPS tunneling):
//   - Routes to handleConnect() for establishing encrypted tunnels
//   - Used for intercepting HTTPS traffic
//
// 3. Direct Requests (non-proxy requests):
//   - Requests without absolute URLs or missing Host header
//   - Triggers AccessProxyServer addon event
//   - Returns 400 Bad Request if addons don't handle it
//
// 4. HTTP Proxy Requests:
//   - Regular HTTP requests with absolute URLs
//   - Routes to attacker.Attack() for interception and forwarding
//
// Request Context:
// The request's context contains ConnContext (via ConnContext function in newEntry),
// which provides access to connection-level state like TLS status, client info, etc.
func (e *entry) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	logger := slog.Default().With(
		"in", "Proxy.entry.ServeHTTP",
		"host", req.Host,
	)
	// Add entry proxy authentication
	if e.proxy.authProxy != nil {
		b, err := e.proxy.authProxy(res, req)
		if !b {
			logger.Error("Proxy authentication failed", "error", err)
			httpError(res, "", http.StatusProxyAuthRequired)
			return
		}
	}
	// proxy via connect tunnel
	if req.Method == "CONNECT" {
		e.handleConnect(res, req)
		return
	}

	if !req.URL.IsAbs() || req.URL.Host == "" {
		res = helper.NewResponseCheck(res)
		for _, addon := range proxy.addonRegistry.Get() {
			addon.AccessProxyServer(req, res)
		}
		if res, ok := res.(*helper.ResponseCheck); ok {
			if !res.Wrote {
				res.WriteHeader(400)
				_, _ = io.WriteString(res, "This is a proxy server, direct requests are not allowed")
			}
		}
		return
	}

	// http proxy
	proxy.attacker.InitHTTPDialFn(req)
	proxy.attacker.Attack(res, req)
}

// handleConnect processes CONNECT requests for HTTPS tunneling.
//
// CONNECT is the HTTP method used to establish a tunnel through the proxy,
// typically for HTTPS traffic. This method determines how to handle the tunnel:
//
// Decision Flow:
//  1. Check shouldIntercept rule (if configured) to decide whether to intercept
//  2. Create a Flow object and trigger Requestheaders addon event
//  3. Route based on interception decision:
//
// Non-Interception Mode (shouldIntercept = false):
//   - directTransfer(): Simply forwards encrypted traffic without inspection
//   - The proxy acts as a transparent tunnel (no MITM)
//
// Interception Mode (shouldIntercept = true):
//   - httpsDialFirstAttack(): Used when UpstreamCert is true
//   - Connects to upstream server first to get its certificate
//   - Then establishes TLS with client using a forged certificate
//   - httpsDialLazyAttack(): Default interception mode
//   - Establishes connection with client first
//   - Peeks at the traffic to determine if it's TLS
//   - Then connects to upstream server
//
// The Flow object tracks the entire request/response lifecycle and is
// accessible to addons for inspection and modification.
func (e *entry) handleConnect(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	logger := slog.Default().With(
		"in", "Proxy.entry.handleConnect",
		"host", req.Host,
	)

	shouldIntercept := proxy.shouldIntercept == nil || proxy.shouldIntercept(req)
	f := types.NewFlow()
	f.Request = types.NewRequest(req)
	connCtx, ok := proxycontext.GetConnContext(req.Context())
	if !ok {
		panic("failed to get ConnContext from request context")
	}
	f.ConnContext = connCtx
	f.ConnContext.Intercept = shouldIntercept
	defer f.Finish()

	// trigger addon event Requestheaders
	for _, addon := range proxy.addonRegistry.Get() {
		addon.Requestheaders(f)
	}

	if !shouldIntercept {
		logger.Debug("begin transpond", "host", req.Host)
		e.directTransfer(res, req, f)
		return
	}

	if f.ConnContext.ClientConn.UpstreamCert {
		e.httpsDialFirstAttack(res, req, f)
		return
	}

	logger.Debug("begin intercept", "host", req.Host)
	e.httpsDialLazyAttack(res, req, f)
}

// establishConnection hijacks the HTTP connection and sends "200 Connection Established".
//
// This is a critical step in CONNECT request handling:
//  1. Hijacks the HTTP connection from the HTTP server
//  2. Sends "200 Connection Established" response to the client
//  3. Creates a Response object in the Flow for addon tracking
//  4. Triggers Responseheaders addon event
//  5. Returns the raw connection for further processing
//
// After this function returns, the connection is no longer managed by the
// HTTP server and must be handled manually. The returned connection can be
// used for:
//   - Direct tunneling (directTransfer)
//   - TLS interception (httpsDialFirstAttack, httpsDialLazyAttack)
func (e *entry) establishConnection(res http.ResponseWriter, f *Flow) (net.Conn, error) {
	cconn, _, err := res.(http.Hijacker).Hijack()
	if err != nil {
		res.WriteHeader(502)
		return nil, err
	}
	_, err = io.WriteString(cconn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		cconn.Close()
		return nil, err
	}

	f.Response = &Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	// trigger addon event Responseheaders
	for _, addon := range e.proxy.addonRegistry.Get() {
		addon.Responseheaders(f)
	}

	return cconn, nil
}

// directTransfer creates a transparent tunnel without interception.
//
// This mode is used when shouldIntercept returns false. The proxy acts as
// a simple TCP tunnel, forwarding encrypted traffic without inspection:
//
// Flow:
//  1. Connects to the upstream server (target of CONNECT request)
//  2. Establishes the tunnel with the client (sends 200 Connection Established)
//  3. Bidirectionally copies data between client and server
//
// Use Cases:
//   - Bypassing MITM for certain domains (e.g., banking sites)
//   - Reducing overhead when inspection is not needed
//   - Avoiding certificate trust issues for specific hosts
//
// The transfer() function handles bidirectional copying until either
// connection closes or encounters an error.
func (e *entry) directTransfer(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	logger := slog.Default().With(
		"in", "Proxy.entry.directTransfer",
		"host", req.Host,
	)

	upstreamConn, err := proxy.upstreamManager.GetUpstreamConn(req.Context(), req)
	if err != nil {
		logger.Error("get upstream conn failed", "error", err)
		res.WriteHeader(502)
		return
	}
	defer upstreamConn.Close()

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		logger.Error("establish connection failed", "error", err)
		return
	}
	defer cconn.Close()

	transfer(logger, upstreamConn, cconn)
}

// httpsDialFirstAttack performs MITM interception by connecting to upstream first.
//
// This "dial-first" approach is used when UpstreamCert is true. It connects to
// the upstream server before establishing the tunnel with the client, allowing
// the proxy to obtain the real server's certificate and create a matching fake.
//
// Flow:
//  1. Connect to upstream server (HTTPSDial)
//  2. Establish tunnel with client (establishConnection)
//  3. Peek at client's first bytes to detect TLS
//  4. Route based on protocol:
//     - Non-TLS: Direct transfer (TODO: handle HTTP, WebSocket)
//     - TLS: Perform TLS interception (HTTPSTLSDial)
//
// Advantages:
//   - Can inspect server certificate before client connection
//   - Useful for certificate pinning scenarios
//   - Allows more accurate certificate forgery
//
// The peek operation uses WrapClientConn's buffering to inspect traffic
// without consuming it, allowing subsequent handlers to process it normally.
func (e *entry) httpsDialFirstAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	logger := slog.Default().With(
		"in", "Proxy.entry.httpsDialFirstAttack",
		"host", req.Host,
	)

	serverConn, err := proxy.attacker.HTTPSDial(req.Context(), req)
	if err != nil {
		logger.Error("httpsDial failed", "error", err)
		res.WriteHeader(502)
		return
	}

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		serverConn.Close()
		logger.Error("establish connection failed", "error", err)
		return
	}

	wcc, ok := cconn.(*conn.WrapClientConn)
	if !ok {
		cconn.Close()
		serverConn.Close()
		logger.Error("failed to cast to WrapClientConn")
		return
	}
	peek, err := wcc.Peek(3)
	if err != nil {
		cconn.Close()
		serverConn.Close()
		logger.Error("peek failed", "error", err)
		return
	}
	if !helper.IsTLS(peek) {
		// todo: http, ws
		transfer(logger, serverConn, cconn)
		cconn.Close()
		serverConn.Close()
		return
	}

	// is tls
	f.ConnContext.ClientConn.TLS = true
	proxy.attacker.HTTPSTLSDial(req.Context(), cconn, serverConn)
}

// httpsDialLazyAttack performs MITM interception by establishing client tunnel first.
//
// This "lazy" approach is the default interception mode. It establishes the
// tunnel with the client first, then peeks at the traffic to determine the
// protocol before connecting to the upstream server.
//
// Flow:
//  1. Establish tunnel with client (establishConnection)
//  2. Peek at client's first bytes to detect protocol
//  3. Route based on protocol:
//     - Non-TLS: Connect to upstream and direct transfer (TODO: handle HTTP, WebSocket)
//     - TLS: Perform lazy TLS interception (HTTPSLazyAttack)
//
// Advantages:
//   - More efficient for most cases (no upstream connection if not needed)
//   - Can detect protocol before committing to upstream connection
//   - Reduces latency for non-TLS traffic
//
// The "lazy" in the name refers to delaying the upstream connection until
// after protocol detection, and in the TLS case, the attacker handles the
// upstream connection establishment internally based on the SNI from the
// client's TLS handshake.
func (e *entry) httpsDialLazyAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	logger := slog.Default().With(
		"in", "Proxy.entry.httpsDialLazyAttack",
		"host", req.Host,
	)

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		logger.Error("establish connection failed", "error", err)
		return
	}

	wcc, ok := cconn.(*conn.WrapClientConn)
	if !ok {
		cconn.Close()
		logger.Error("failed to cast to WrapClientConn")
		return
	}
	peek, err := wcc.Peek(3)
	if err != nil {
		cconn.Close()
		logger.Error("peek failed", "error", err)
		return
	}

	if !helper.IsTLS(peek) {
		// todo: http, ws
		serverConn, err := proxy.attacker.HTTPSDial(req.Context(), req)
		if err != nil {
			cconn.Close()
			logger.Error("httpsDial failed", "error", err)
			return
		}
		transfer(logger, serverConn, cconn)
		serverConn.Close()
		cconn.Close()
		return
	}

	// is tls
	f.ConnContext.ClientConn.TLS = true
	proxy.attacker.HTTPSLazyAttack(req.Context(), cconn, req)
}
