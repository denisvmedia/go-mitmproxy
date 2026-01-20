package attacker

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"golang.org/x/net/http2"

	"github.com/denisvmedia/go-mitmproxy/cert"
	"github.com/denisvmedia/go-mitmproxy/internal/helper"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/conn"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/proxycontext"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/types"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/upstream"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/websocket"
)

// listener is a custom net.Listener implementation that accepts connections
// through a channel. It is used internally by the Attacker to handle intercepted
// HTTP/1.1 connections.
type listener struct {
	connChan chan net.Conn
}

// accept sends a connection to the listener's channel for processing.
func (l *listener) accept(c net.Conn) {
	l.connChan <- c
}

// Accept waits for and returns the next connection to the listener.
func (l *listener) Accept() (net.Conn, error) {
	c := <-l.connChan
	return c, nil
}

// Close closes the listener. This is a no-op for listener.
func (*listener) Close() error { return nil }

// Addr returns the listener's network address. This returns nil for listener.
func (*listener) Addr() net.Addr { return nil }

// attackerConn wraps a net.Conn with its associated connection context.
// It is used to pass connection metadata through the HTTP server's ConnContext.
type attackerConn struct {
	net.Conn
	connCtx *conn.Context
}

// Attacker handles the man-in-the-middle attack functionality for intercepting
// and modifying HTTP/HTTPS traffic. It manages TLS handshakes, certificate generation,
// and proxying of requests between clients and servers.
type Attacker struct {
	ca                 cert.CA
	upstreamManager    *upstream.Manager
	addonRegistry      types.AddonRegistry
	streamLargeBodies  int64
	insecureSkipVerify bool
	wsHandler          *websocket.Handler
	server             *http.Server
	h2Server           *http2.Server
	client             *http.Client
	listener           *listener
	clientFactory      types.ClientFactory
}

// Args contains all dependencies required by the Attacker.
type Args struct {
	CA              cert.CA
	UpstreamManager *upstream.Manager
	AddonRegistry   types.AddonRegistry

	// StreamLargeBodies is the threshold in bytes for switching to streaming mode.
	// Bodies larger than this will be streamed instead of buffered.
	StreamLargeBodies int64

	// InsecureSkipVerify controls whether to skip SSL certificate verification
	// when connecting to upstream servers.
	InsecureSkipVerify bool

	WSHandler *websocket.Handler

	// ClientFactory is used to create HTTP clients for different scenarios.
	// If nil, DefaultClientFactory will be used.
	ClientFactory types.ClientFactory
}

// New creates a new Attacker instance with the given dependencies.
// It initializes the HTTP client, HTTP server, and HTTP/2 server.
// The attacker is configured to handle both HTTP/1.1 and HTTP/2 connections.
func New(args Args) (*Attacker, error) {
	// Use default client factory if none provided
	clientFactory := args.ClientFactory
	if clientFactory == nil {
		clientFactory = NewDefaultClientFactory()
	}

	atk := &Attacker{
		ca:                 args.CA,
		upstreamManager:    args.UpstreamManager,
		addonRegistry:      args.AddonRegistry,
		streamLargeBodies:  args.StreamLargeBodies,
		insecureSkipVerify: args.InsecureSkipVerify,
		wsHandler:          args.WSHandler,
		clientFactory:      clientFactory,
		listener: &listener{
			connChan: make(chan net.Conn),
		},
	}

	// Client #1: Main fallback/separate client
	// Purpose: Used when the request has been modified (different host/scheme) or when
	// UseSeparateClient is set. This client goes through the upstream proxy and supports
	// HTTP/2. It creates new connections rather than reusing existing ones.
	atk.client = atk.clientFactory.CreateMainClient(atk.upstreamManager, args.InsecureSkipVerify)

	atk.server = &http.Server{
		Handler: atk,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return proxycontext.WithConnContext(ctx, c.(*attackerConn).connCtx)
		},
	}

	atk.h2Server = &http2.Server{
		MaxConcurrentStreams: 100, // todo: wait for remote server setting
		NewWriteScheduler:    func() http2.WriteScheduler { return http2.NewPriorityWriteScheduler(nil) },
	}

	return atk, nil
}

// Start begins serving HTTP connections through the attacker's listener.
// This method blocks until the server is shut down or an error occurs.
func (a *Attacker) Start() error {
	return a.server.Serve(a.listener)
}

// NotifyClientDisconnected implements conn.AddonNotifier.
func (a *Attacker) NotifyClientDisconnected(client *conn.ClientConn) {
	for _, addon := range a.addonRegistry.Get() {
		addon.ClientDisconnected(client)
	}
}

// NotifyServerDisconnected implements conn.AddonNotifier.
func (a *Attacker) NotifyServerDisconnected(connCtx *conn.Context) {
	for _, addon := range a.addonRegistry.Get() {
		addon.ServerDisconnected(connCtx)
	}
}

// Addon interface methods that forward to the actual addon implementations.
func (a *Attacker) ClientDisconnected(client *conn.ClientConn) {
	// This is called by the wrapper, we forward to addons
	a.NotifyClientDisconnected(client)
}

func (a *Attacker) ServerDisconnected(connCtx *conn.Context) {
	// This is called by the wrapper, we forward to addons
	a.NotifyServerDisconnected(connCtx)
}

// serveConn handles an intercepted TLS connection from a client.
// It determines the negotiated protocol (HTTP/1.1 or HTTP/2) and routes the connection
// to the appropriate handler. For HTTP/2, it sets up an HTTP/2 server connection.
// For HTTP/1.1, it passes the connection to the HTTP/1.1 listener.
func (a *Attacker) serveConn(clientTLSConn *tls.Conn, connCtx *conn.Context) {
	connCtx.ClientConn.NegotiatedProtocol = clientTLSConn.ConnectionState().NegotiatedProtocol

	if connCtx.ClientConn.NegotiatedProtocol == "h2" && connCtx.ServerConn != nil {
		// Client #2: HTTP/2 server connection client
		// Purpose: Created specifically for HTTP/2 connections when the negotiated protocol
		// is "h2". Uses http2.Transport and reuses the existing TLS connection
		// (connCtx.ServerConn.TLSConn) rather than creating new connections.
		connCtx.ServerConn.Client = a.clientFactory.CreateHTTP2Client(connCtx.ServerConn.TLSConn)

		ctx := proxycontext.WithConnContext(context.Background(), connCtx)
		ctx, cancel := context.WithCancel(ctx)
		go func() {
			<-connCtx.ClientConn.CloseChan
			cancel()
		}()
		go func() {
			a.h2Server.ServeConn(clientTLSConn, &http2.ServeConnOpts{
				Context:    ctx,
				Handler:    a,
				BaseConfig: a.server,
			})
		}()
		return
	}

	a.listener.accept(&attackerConn{
		Conn:    clientTLSConn,
		connCtx: connCtx,
	})
}

// ServeHTTP implements the http.Handler interface for the Attacker.
// It handles incoming HTTP requests, including WebSocket upgrades and regular HTTP/HTTPS requests.
// This method ensures the request URL is properly formatted before passing it to the Attack method.
func (a *Attacker) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if strings.EqualFold(req.Header.Get("Connection"), "Upgrade") && strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		// wss
		a.wsHandler.HandleWSS(res, req)
		return
	}

	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	a.Attack(res, req)
}

// InitHTTPDialFn initializes the dial function for plain HTTP connections.
// This function is called lazily when the first HTTP request is made on a connection.
// It establishes a connection to the upstream server and configures an HTTP/1.1 client.
func (a *Attacker) InitHTTPDialFn(req *http.Request) {
	connCtx, ok := proxycontext.GetConnContext(req.Context())
	if !ok {
		panic("failed to get ConnContext from request context")
	}
	connCtx.DialFn = func(ctx context.Context) error {
		addr := helper.CanonicalAddr(req.URL)
		c, err := a.upstreamManager.GetUpstreamConn(ctx, req)
		if err != nil {
			return err
		}
		cw := conn.NewWrapServerConn(c, connCtx, a)

		serverConn := conn.NewServerConn()
		serverConn.Conn = cw
		serverConn.Address = addr
		// Client #3: Plain HTTP connection client
		// Purpose: Created for plain HTTP (non-TLS) connections. Explicitly disables HTTP/2
		// and reuses the existing plain connection (cw) via custom DialContext function.
		// This avoids creating new connections for each request on the same HTTP connection.
		serverConn.Client = a.clientFactory.CreatePlainHTTPClient(cw)

		connCtx.ServerConn = serverConn
		for _, addon := range a.addonRegistry.Get() {
			addon.ServerConnected(connCtx)
		}

		return nil
	}
}

// serverTLSHandshake performs a TLS handshake with the upstream server.
// It uses the client's ClientHello information to mimic the client's TLS configuration
// when connecting to the server. This helps maintain transparency in the MITM process.
func (a *Attacker) serverTLSHandshake(ctx context.Context, connCtx *conn.Context) error {
	clientHello := connCtx.ClientConn.ClientHello
	serverConn := connCtx.ServerConn

	serverTLSConfig := &tls.Config{
		InsecureSkipVerify: a.insecureSkipVerify,
		KeyLogWriter:       helper.GetTLSKeyLogWriter(),
		ServerName:         clientHello.ServerName,
		NextProtos:         clientHello.SupportedProtos,
		// CurvePreferences:   clientHello.SupportedCurves, // todo: will cause errors if enabled
		CipherSuites: clientHello.CipherSuites,
	}
	if len(clientHello.SupportedVersions) > 0 {
		minVersion := clientHello.SupportedVersions[0]
		maxVersion := clientHello.SupportedVersions[0]
		for _, version := range clientHello.SupportedVersions {
			if version < minVersion {
				minVersion = version
			}
			if version > maxVersion {
				maxVersion = version
			}
		}
		serverTLSConfig.MinVersion = minVersion
		serverTLSConfig.MaxVersion = maxVersion
	}
	serverTLSConn := tls.Client(serverConn.Conn, serverTLSConfig)
	serverConn.TLSConn = serverTLSConn
	if err := serverTLSConn.HandshakeContext(ctx); err != nil {
		return err
	}
	serverTLSState := serverTLSConn.ConnectionState()
	serverConn.TLSState = &serverTLSState
	for _, addon := range a.addonRegistry.Get() {
		addon.TLSEstablishedServer(connCtx)
	}

	// Client #4: HTTPS/TLS connection client
	// Purpose: Created for HTTPS connections after TLS handshake. Reuses the established
	// TLS connection (serverTLSConn) via custom DialTLSContext function and allows HTTP/2
	// negotiation. This maintains persistent connections to upstream servers.
	serverConn.Client = a.clientFactory.CreateHTTPSClient(serverTLSConn)

	return nil
}

// InitHTTPSDialFn initializes the dial function for HTTPS connections.
// This function is called lazily when the first HTTPS request is made on a connection.
// It establishes both a plain connection and performs the TLS handshake with the upstream server.
func (a *Attacker) InitHTTPSDialFn(req *http.Request) {
	connCtx, ok := proxycontext.GetConnContext(req.Context())
	if !ok {
		panic("failed to get ConnContext from request context")
	}

	connCtx.DialFn = func(ctx context.Context) error {
		_, err := a.HTTPSDial(ctx, req)
		if err != nil {
			return err
		}
		if err := a.serverTLSHandshake(ctx, connCtx); err != nil {
			return err
		}
		return nil
	}
}

// HttpsDial establishes a plain TCP connection to the upstream HTTPS server.
// It creates a server connection and notifies addons that the server connection has been established.
// The TLS handshake is performed separately by serverTLSHandshake.
func (a *Attacker) HTTPSDial(ctx context.Context, req *http.Request) (net.Conn, error) {
	connCtx, ok := proxycontext.GetConnContext(req.Context())
	if !ok {
		panic("failed to get ConnContext from request context")
	}

	plainConn, err := a.upstreamManager.GetUpstreamConn(ctx, req)
	if err != nil {
		return nil, err
	}

	serverConn := conn.NewServerConn()
	serverConn.Address = req.Host
	serverConn.Conn = conn.NewWrapServerConn(plainConn, connCtx, a)
	connCtx.ServerConn = serverConn
	for _, addon := range a.addonRegistry.Get() {
		addon.ServerConnected(connCtx)
	}

	return serverConn.Conn, nil
}

// HTTPSTLSDial performs a full MITM TLS handshake for HTTPS connections.
// It coordinates the TLS handshakes between the client and proxy, and between the proxy and server.
// The process involves:
// 1. Starting a client TLS handshake in a goroutine
// 2. Receiving the client's ClientHello
// 3. Performing a server TLS handshake with the upstream server
// 4. Generating a certificate for the client based on the server's negotiated protocol
// 5. Completing the client TLS handshake
// 6. Passing the connection to serveConn for HTTP request handling.
func (a *Attacker) HTTPSTLSDial(ctx context.Context, cconn, sconn net.Conn) {
	connCtx, ok := proxycontext.GetConnContext(ctx)
	if !ok {
		panic("failed to get ConnContext from request context")
	}
	logger := slog.With(
		"in", "Proxy.attacker.httpsTlsDial",
		"host", connCtx.ClientConn.Conn.RemoteAddr().String(),
	)

	var clientHello *tls.ClientHelloInfo
	clientHelloChan := make(chan *tls.ClientHelloInfo)
	serverTLSStateChan := make(chan *tls.ConnectionState)
	errChan1 := make(chan error, 1)
	errChan2 := make(chan error, 1)
	clientHandshakeDoneChan := make(chan struct{})

	clientTLSConn := tls.Server(cconn, &tls.Config{
		SessionTicketsDisabled: true, // Set this to true to ensure GetConfigForClient is called every time
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHelloChan <- chi
			nextProtos := make([]string, 0)

			// wait server handshake finish
			select {
			case err := <-errChan2:
				return nil, err
			case serverTLSState := <-serverTLSStateChan:
				if serverTLSState.NegotiatedProtocol != "" {
					nextProtos = append([]string{serverTLSState.NegotiatedProtocol}, nextProtos...)
				}
			}

			c, err := a.ca.GetCert(chi.ServerName)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				SessionTicketsDisabled: true,
				Certificates:           []tls.Certificate{*c},
				NextProtos:             nextProtos,
			}, nil
		},
	})
	go func() {
		if err := clientTLSConn.HandshakeContext(ctx); err != nil {
			errChan1 <- err
			return
		}
		close(clientHandshakeDoneChan)
	}()

	// get clientHello from client
	select {
	case err := <-errChan1:
		cconn.Close()
		sconn.Close()
		logger.Error("client handshake failed", "error", err)
		return
	case clientHello = <-clientHelloChan:
	}
	connCtx.ClientConn.ClientHello = clientHello

	if err := a.serverTLSHandshake(ctx, connCtx); err != nil {
		cconn.Close()
		sconn.Close()
		errChan2 <- err
		logger.Error("server TLS handshake failed", "error", err)
		return
	}
	serverTLSStateChan <- connCtx.ServerConn.TLSState

	// wait client handshake finish
	select {
	case err := <-errChan1:
		cconn.Close()
		sconn.Close()
		logger.Error("client handshake failed", "error", err)
		return
	case <-clientHandshakeDoneChan:
	}

	// will go to Attacker.ServeHTTP
	a.serveConn(clientTLSConn, connCtx)
}

// HTTPSLazyAttack performs a lazy MITM TLS handshake for HTTPS connections.
// Unlike HttpsTLSDial, this method only performs the client TLS handshake without
// immediately connecting to the upstream server. The server connection is established
// lazily when the first request is made. This approach only supports HTTP/1.1.
func (a *Attacker) HTTPSLazyAttack(ctx context.Context, cconn net.Conn, req *http.Request) {
	connCtx, ok := proxycontext.GetConnContext(ctx)
	if !ok {
		panic("failed to get ConnContext from request context")
	}
	logger := slog.With(
		"in", "Proxy.attacker.httpsLazyAttack",
		"host", connCtx.ClientConn.Conn.RemoteAddr().String(),
	)

	clientTLSConn := tls.Server(cconn, &tls.Config{
		SessionTicketsDisabled: true, // Set this to true to ensure GetConfigForClient is called every time
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			connCtx.ClientConn.ClientHello = chi
			c, err := a.ca.GetCert(chi.ServerName)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				SessionTicketsDisabled: true,
				Certificates:           []tls.Certificate{*c},
				NextProtos:             []string{"http/1.1"}, // only support http/1.1
			}, nil
		},
	})
	if err := clientTLSConn.HandshakeContext(ctx); err != nil {
		cconn.Close()
		logger.Error("client handshake failed", "error", err)
		return
	}

	// will go to Attacker.ServeHTTP
	a.InitHTTPSDialFn(req)
	a.serveConn(clientTLSConn, connCtx)
}

// executeProxyRequest creates and executes the proxy request to the upstream server.
// It handles both separate client mode (for modified requests) and connection reuse mode.
// The method returns the upstream server's response or an error if the request fails.
func (a *Attacker) executeProxyRequest(f *types.Flow, req *http.Request, reqBody io.Reader, rawReqURLHost, rawReqURLScheme string, res http.ResponseWriter, logger *slog.Logger) (*http.Response, error) {
	proxyReqCtx := proxycontext.WithProxyRequest(req.Context(), req)
	proxyReq, err := http.NewRequestWithContext(proxyReqCtx, f.Request.Method, f.Request.URL.String(), reqBody)
	if err != nil {
		logger.Error("failed to create proxy request", "error", err)
		res.WriteHeader(502)
		return nil, err
	}

	for key, value := range f.Request.Header {
		for _, v := range value {
			proxyReq.Header.Add(key, v)
		}
	}

	useSeparateClient := f.UseSeparateClient
	if !useSeparateClient {
		if rawReqURLHost != f.Request.URL.Host || rawReqURLScheme != f.Request.URL.Scheme {
			useSeparateClient = true
		}
	}

	var proxyRes *http.Response
	if useSeparateClient {
		proxyRes, err = a.client.Do(proxyReq)
		if err != nil {
			logErr(logger, err)
			res.WriteHeader(502)
			return nil, err
		}
		return proxyRes, nil
	}

	// Establish connection if needed
	if f.ConnContext.ServerConn == nil && f.ConnContext.DialFn != nil {
		if err := f.ConnContext.DialFn(req.Context()); err != nil {
			// Check for authentication failure
			logger.Error("dial upstream failed", "error", err)
			if strings.Contains(err.Error(), "Proxy Authentication Required") {
				httpError(res, "", http.StatusProxyAuthRequired)
				return nil, err
			}
			res.WriteHeader(502)
			return nil, err
		}
	}

	proxyRes, err = f.ConnContext.ServerConn.Client.Do(proxyReq)
	if err != nil {
		logErr(logger, err)
		res.WriteHeader(502)
		return nil, err
	}

	logger.Debug("got response", "status", proxyRes.StatusCode, "contentLength", proxyRes.ContentLength)
	return proxyRes, nil
}

// handleResponseHeadersAddons triggers the Responseheaders addon event for all registered addons.
// It returns true if any addon provides an early response (by setting f.Response.Body),
// indicating that the normal response flow should be bypassed.
func (a *Attacker) handleResponseHeadersAddons(f *types.Flow) bool {
	for _, addon := range a.addonRegistry.Get() {
		addon.Responseheaders(f)
		if f.Response.Body != nil {
			return true // early response
		}
	}
	return false
}

// readResponseBody reads and buffers the response body from the upstream server.
// If the response body is too large (exceeds StreamLargeBodies threshold), it switches
// to streaming mode. In non-streaming mode, it triggers the Response addon event.
// Returns the response body reader and a boolean indicating success.
func (a *Attacker) readResponseBody(f *types.Flow, proxyRes *http.Response, logger *slog.Logger) (io.Reader, bool) {
	var resBody io.Reader = proxyRes.Body
	if f.Stream {
		return resBody, true
	}

	streamThreshold := a.streamLargeBodies
	resBuf, r, err := helper.ReaderToBuffer(proxyRes.Body, streamThreshold)
	resBody = r
	if err != nil {
		logger.Error("failed to buffer response body", "error", err)
		return nil, false
	}

	if resBuf == nil {
		logger.Warn("response body too large, switching to stream", "threshold", streamThreshold)
		f.Stream = true
		return resBody, true
	}

	f.Response.Body = resBuf
	logger.Debug("buffered response body", "size", len(resBuf))

	// trigger addon event Response
	for _, addon := range a.addonRegistry.Get() {
		addon.Response(f)
	}

	logger.Debug("after Response addon", "bodySize", len(f.Response.Body))
	return resBody, true
}

// replyToClient sends the HTTP response back to the client.
// It writes the response headers, status code, and body (from multiple possible sources).
// The body can come from a reader, a BodyReader field, or a Body byte slice.
func (*Attacker) replyToClient(res http.ResponseWriter, response *types.Response, body io.Reader, logger *slog.Logger) {
	logger.Debug("replyToClient", "bodyReader", body != nil, "responseBodyReader", response.BodyReader != nil, "responseBodyLen", len(response.Body))
	if response.Header != nil {
		for key, value := range response.Header {
			for _, v := range value {
				res.Header().Add(key, v)
			}
		}
	}
	if response.Close {
		res.Header().Add("Connection", "close")
	}
	res.WriteHeader(response.StatusCode)

	if body != nil {
		n, err := io.Copy(res, body)
		logger.Debug("wrote from body reader", "bytes", n)
		if err != nil {
			logErr(logger, err)
		}
	}
	if response.BodyReader != nil {
		n, err := io.Copy(res, response.BodyReader)
		logger.Debug("wrote from response.BodyReader", "bytes", n)
		if err != nil {
			logErr(logger, err)
		}
	}
	if len(response.Body) > 0 {
		n, err := res.Write(response.Body)
		logger.Debug("wrote from response.Body", "bytes", n, "body", string(response.Body), "err", err)
		if err != nil {
			logErr(logger, err)
		}
	}

	// Flush the response
	if flusher, ok := res.(http.Flusher); ok {
		flusher.Flush()
		logger.Debug("flushed response")
	}
}

// handleRequestAddons triggers the Requestheaders addon event for all registered addons.
// It returns true if any addon provides an early response (by setting f.Response),
// indicating that the request should not be forwarded to the upstream server.
func (a *Attacker) handleRequestAddons(f *types.Flow) bool {
	for _, addon := range a.addonRegistry.Get() {
		addon.Requestheaders(f)
		if f.Response != nil {
			return true // early response
		}
	}
	return false
}

// readRequestBody reads and buffers the request body from the client.
// If the request body is too large (exceeds StreamLargeBodies threshold), it switches
// to streaming mode. In non-streaming mode, it triggers the Request addon event.
// Returns the request body reader and a boolean indicating success.
func (a *Attacker) readRequestBody(f *types.Flow, req *http.Request, logger *slog.Logger) (io.Reader, bool) {
	var reqBody io.Reader = req.Body
	if f.Stream {
		return reqBody, true
	}

	streamThreshold := a.streamLargeBodies
	reqBuf, r, err := helper.ReaderToBuffer(req.Body, streamThreshold)
	reqBody = r
	if err != nil {
		logger.Error("failed to buffer request body", "error", err)
		return nil, false
	}

	if reqBuf == nil {
		logger.Warn("request body too large, switching to stream", "threshold", streamThreshold)
		f.Stream = true
		return reqBody, true
	}

	f.Request.Body = reqBuf

	// trigger addon event Request
	for _, addon := range a.addonRegistry.Get() {
		addon.Request(f)
		if f.Response != nil {
			return nil, true // early response
		}
	}
	return bytes.NewReader(f.Request.Body), true
}

// Attack is the main request handling method that processes HTTP/HTTPS requests.
// It orchestrates the complete request/response flow:
// 1. Creates a new Flow and associates it with the connection context
// 2. Triggers Requestheaders addon event
// 3. Reads and buffers the request body (or streams if too large)
// 4. Triggers Request addon event
// 5. Applies stream request modifiers
// 6. Executes the proxy request to the upstream server
// 7. Triggers Responseheaders addon event
// 8. Reads and buffers the response body (or streams if too large)
// 9. Triggers Response addon event
// 10. Applies stream response modifiers
// 11. Sends the response back to the client
//
// The method includes panic recovery to handle addon errors gracefully.
func (a *Attacker) Attack(res http.ResponseWriter, req *http.Request) {
	logger := slog.With(
		"in", "Proxy.attacker.attack",
		"url", req.URL,
		"method", req.Method,
	)

	// when addons panic
	defer func() {
		if err := recover(); err != nil {
			logger.Warn("Recovered from panic in Attacker.attack", "error", err)
		}
	}()

	connCtx, ok := proxycontext.GetConnContext(req.Context())
	if !ok {
		panic("failed to get ConnContext from request context")
	}

	// Create flow directly
	f := types.NewFlow()
	f.Request = types.NewRequest(req)
	f.ConnContext = connCtx
	defer f.Finish()

	connCtx.FlowCount.Add(1)

	rawReqURLHost := f.Request.URL.Host
	rawReqURLScheme := f.Request.URL.Scheme

	// trigger addon event Requestheaders
	if a.handleRequestAddons(f) {
		a.replyToClient(res, f.Response, nil, logger)
		return
	}

	// Read request body
	reqBody, ok := a.readRequestBody(f, req, logger)
	if !ok {
		res.WriteHeader(502)
		return
	}
	if f.Response != nil {
		a.replyToClient(res, f.Response, nil, logger)
		return
	}

	for _, addon := range a.addonRegistry.Get() {
		reqBody = addon.StreamRequestModifier(f, reqBody)
	}

	proxyRes, err := a.executeProxyRequest(f, req, reqBody, rawReqURLHost, rawReqURLScheme, res, logger)
	if err != nil {
		return
	}

	if proxyRes.Close {
		connCtx.CloseAfterResponse = true
	}

	defer proxyRes.Body.Close()

	f.Response = &types.Response{
		StatusCode: proxyRes.StatusCode,
		Header:     proxyRes.Header,
		Close:      proxyRes.Close,
	}

	// trigger addon event Responseheaders
	if a.handleResponseHeadersAddons(f) {
		a.replyToClient(res, f.Response, nil, logger)
		return
	}

	// Read response body
	resBody, ok := a.readResponseBody(f, proxyRes, logger)
	if !ok {
		res.WriteHeader(502)
		return
	}

	for _, addon := range a.addonRegistry.Get() {
		resBody = addon.StreamResponseModifier(f, resBody)
	}

	a.replyToClient(res, f.Response, resBody, logger)
}
