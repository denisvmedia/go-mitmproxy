package proxy

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
)

// attackerListener is a custom net.Listener implementation that accepts connections
// through a channel. It is used internally by the Attacker to handle intercepted
// HTTP/1.1 connections.
type attackerListener struct {
	connChan chan net.Conn
}

// accept sends a connection to the listener's channel for processing.
func (l *attackerListener) accept(conn net.Conn) {
	l.connChan <- conn
}

// Accept waits for and returns the next connection to the listener.
func (l *attackerListener) Accept() (net.Conn, error) {
	c := <-l.connChan
	return c, nil
}

// Close closes the listener. This is a no-op for attackerListener.
func (*attackerListener) Close() error { return nil }

// Addr returns the listener's network address. This returns nil for attackerListener.
func (*attackerListener) Addr() net.Addr { return nil }

// attackerConn wraps a net.Conn with its associated connection context.
// It is used to pass connection metadata through the HTTP server's ConnContext.
type attackerConn struct {
	net.Conn
	connCtx *ConnContext
}

// Attacker handles the man-in-the-middle attack functionality for intercepting
// and modifying HTTP/HTTPS traffic. It manages TLS handshakes, certificate generation,
// and proxying of requests between clients and servers.
type Attacker struct {
	ca              cert.CA
	upstreamManager *UpstreamManager
	addonManager    *AddonRegistry
	config          *Config
	server          *http.Server
	h2Server        *http2.Server
	client          *http.Client
	listener        *attackerListener
}

// AttackerArgs contains all dependencies required by the Attacker.
type AttackerArgs struct {
	CA              cert.CA
	UpstreamManager *UpstreamManager
	AddonRegistry   *AddonRegistry
	Config          *Config
}

// NewAttacker creates a new Attacker instance with the given dependencies.
// It initializes the HTTP client, HTTP server, and HTTP/2 server.
// The attacker is configured to handle both HTTP/1.1 and HTTP/2 connections.
func NewAttacker(deps AttackerArgs) (*Attacker, error) {
	a := &Attacker{
		ca:              deps.CA,
		upstreamManager: deps.UpstreamManager,
		addonManager:    deps.AddonRegistry,
		config:          deps.Config,
		client: &http.Client{
			Transport: &http.Transport{
				Proxy:              deps.UpstreamManager.RealUpstreamProxy(),
				ForceAttemptHTTP2:  true,
				DisableCompression: true, // To get the original response from the server, set Transport.DisableCompression to true.
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: deps.Config.GetSslInsecure(),
					KeyLogWriter:       helper.GetTLSKeyLogWriter(),
				},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// Disable automatic redirects
				return http.ErrUseLastResponse
			},
		},
		listener: &attackerListener{
			connChan: make(chan net.Conn),
		},
	}

	a.server = &http.Server{
		Handler: a,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, c.(*attackerConn).connCtx)
		},
	}

	a.h2Server = &http2.Server{
		MaxConcurrentStreams: 100, // todo: wait for remote server setting
		NewWriteScheduler:    func() http2.WriteScheduler { return http2.NewPriorityWriteScheduler(nil) },
	}

	return a, nil
}

// Start begins serving HTTP connections through the attacker's listener.
// This method blocks until the server is shut down or an error occurs.
func (a *Attacker) Start() error {
	return a.server.Serve(a.listener)
}

// serveConn handles an intercepted TLS connection from a client.
// It determines the negotiated protocol (HTTP/1.1 or HTTP/2) and routes the connection
// to the appropriate handler. For HTTP/2, it sets up an HTTP/2 server connection.
// For HTTP/1.1, it passes the connection to the HTTP/1.1 listener.
func (a *Attacker) serveConn(clientTLSConn *tls.Conn, connCtx *ConnContext) {
	connCtx.ClientConn.NegotiatedProtocol = clientTLSConn.ConnectionState().NegotiatedProtocol

	if connCtx.ClientConn.NegotiatedProtocol == "h2" && connCtx.ServerConn != nil {
		connCtx.ServerConn.client = &http.Client{
			Transport: &http2.Transport{
				DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
					return connCtx.ServerConn.tlsConn, nil
				},
				DisableCompression: true,
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				// Disable automatic redirects
				return http.ErrUseLastResponse
			},
		}

		ctx := context.WithValue(context.Background(), connContextKey, connCtx)
		ctx, cancel := context.WithCancel(ctx)
		go func() {
			<-connCtx.ClientConn.Conn.(*wrapClientConn).closeChan
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
		defaultWebSocket.wss(res, req)
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
	connCtx, ok := req.Context().Value(connContextKey).(*ConnContext)
	if !ok {
		panic("failed to get ConnContext from request context")
	}
	connCtx.dialFn = func(ctx context.Context) error {
		addr := helper.CanonicalAddr(req.URL)
		c, err := a.upstreamManager.GetUpstreamConn(ctx, req)
		if err != nil {
			return err
		}
		cw := &wrapServerConn{
			Conn:    c,
			proxy:   connCtx.proxy,
			connCtx: connCtx,
		}

		serverConn := newServerConn()
		serverConn.Conn = cw
		serverConn.Address = addr
		serverConn.client = &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return cw, nil
				},
				ForceAttemptHTTP2:  false, // disable http2
				DisableCompression: true,  // To get the original response from the server, set Transport.DisableCompression to true.
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				// Disable automatic redirects
				return http.ErrUseLastResponse
			},
		}

		connCtx.ServerConn = serverConn
		for _, addon := range a.addonManager.Get() {
			addon.ServerConnected(connCtx)
		}

		return nil
	}
}

// serverTLSHandshake performs a TLS handshake with the upstream server.
// It uses the client's ClientHello information to mimic the client's TLS configuration
// when connecting to the server. This helps maintain transparency in the MITM process.
func (a *Attacker) serverTLSHandshake(ctx context.Context, connCtx *ConnContext) error {
	clientHello := connCtx.ClientConn.clientHello
	serverConn := connCtx.ServerConn

	serverTLSConfig := &tls.Config{
		InsecureSkipVerify: a.config.GetSslInsecure(),
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
	serverConn.tlsConn = serverTLSConn
	if err := serverTLSConn.HandshakeContext(ctx); err != nil {
		return err
	}
	serverTLSState := serverTLSConn.ConnectionState()
	serverConn.tlsState = &serverTLSState
	for _, addon := range a.addonManager.Get() {
		addon.TLSEstablishedServer(connCtx)
	}

	serverConn.client = &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return serverTLSConn, nil
			},
			ForceAttemptHTTP2:  true,
			DisableCompression: true, // To get the original response from the server, set Transport.DisableCompression to true.
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// Disable automatic redirects
			return http.ErrUseLastResponse
		},
	}

	return nil
}

// InitHTTPSDialFn initializes the dial function for HTTPS connections.
// This function is called lazily when the first HTTPS request is made on a connection.
// It establishes both a plain connection and performs the TLS handshake with the upstream server.
func (a *Attacker) InitHTTPSDialFn(req *http.Request) {
	connCtx, ok := req.Context().Value(connContextKey).(*ConnContext)
	if !ok {
		panic("failed to get ConnContext from request context")
	}

	connCtx.dialFn = func(ctx context.Context) error {
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
	connCtx, ok := req.Context().Value(connContextKey).(*ConnContext)
	if !ok {
		panic("failed to get ConnContext from request context")
	}

	plainConn, err := a.upstreamManager.GetUpstreamConn(ctx, req)
	if err != nil {
		return nil, err
	}

	serverConn := newServerConn()
	serverConn.Address = req.Host
	serverConn.Conn = &wrapServerConn{
		Conn:    plainConn,
		proxy:   connCtx.proxy,
		connCtx: connCtx,
	}
	connCtx.ServerConn = serverConn
	for _, addon := range a.addonManager.Get() {
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
func (a *Attacker) HTTPSTLSDial(ctx context.Context, cconn, conn net.Conn) {
	connCtx := cconn.(*wrapClientConn).connCtx
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
		conn.Close()
		logger.Error("client handshake failed", "error", err)
		return
	case clientHello = <-clientHelloChan:
	}
	connCtx.ClientConn.clientHello = clientHello

	if err := a.serverTLSHandshake(ctx, connCtx); err != nil {
		cconn.Close()
		conn.Close()
		errChan2 <- err
		logger.Error("server TLS handshake failed", "error", err)
		return
	}
	serverTLSStateChan <- connCtx.ServerConn.tlsState

	// wait client handshake finish
	select {
	case err := <-errChan1:
		cconn.Close()
		conn.Close()
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
	connCtx := cconn.(*wrapClientConn).connCtx
	logger := slog.With(
		"in", "Proxy.attacker.httpsLazyAttack",
		"host", connCtx.ClientConn.Conn.RemoteAddr().String(),
	)

	clientTLSConn := tls.Server(cconn, &tls.Config{
		SessionTicketsDisabled: true, // Set this to true to ensure GetConfigForClient is called every time
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			connCtx.ClientConn.clientHello = chi
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
func (a *Attacker) executeProxyRequest(f *Flow, req *http.Request, reqBody io.Reader, rawReqURLHost, rawReqURLScheme string, res http.ResponseWriter, logger *slog.Logger) (*http.Response, error) {
	proxyReqCtx := context.WithValue(req.Context(), proxyReqCtxKey, req)
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
	if f.ConnContext.ServerConn == nil && f.ConnContext.dialFn != nil {
		if err := f.ConnContext.dialFn(req.Context()); err != nil {
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

	proxyRes, err = f.ConnContext.ServerConn.client.Do(proxyReq)
	if err != nil {
		logErr(logger, err)
		res.WriteHeader(502)
		return nil, err
	}

	return proxyRes, nil
}

// handleResponseHeadersAddons triggers the Responseheaders addon event for all registered addons.
// It returns true if any addon provides an early response (by setting f.Response.Body),
// indicating that the normal response flow should be bypassed.
func (a *Attacker) handleResponseHeadersAddons(f *Flow) bool {
	for _, addon := range a.addonManager.Get() {
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
func (a *Attacker) readResponseBody(f *Flow, proxyRes *http.Response, logger *slog.Logger) (io.Reader, bool) {
	var resBody io.Reader = proxyRes.Body
	if f.Stream {
		return resBody, true
	}

	streamThreshold := a.config.GetStreamLargeBodies()
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

	// trigger addon event Response
	for _, addon := range a.addonManager.Get() {
		addon.Response(f)
	}

	return resBody, true
}

// replyToClient sends the HTTP response back to the client.
// It writes the response headers, status code, and body (from multiple possible sources).
// The body can come from a reader, a BodyReader field, or a Body byte slice.
func (*Attacker) replyToClient(res http.ResponseWriter, response *Response, body io.Reader, logger *slog.Logger) {
	if response.Header != nil {
		for key, value := range response.Header {
			for _, v := range value {
				res.Header().Add(key, v)
			}
		}
	}
	if response.close {
		res.Header().Add("Connection", "close")
	}
	res.WriteHeader(response.StatusCode)

	if body != nil {
		_, err := io.Copy(res, body)
		if err != nil {
			logErr(logger, err)
		}
	}
	if response.BodyReader != nil {
		_, err := io.Copy(res, response.BodyReader)
		if err != nil {
			logErr(logger, err)
		}
	}
	if len(response.Body) > 0 {
		_, err := res.Write(response.Body)
		if err != nil {
			logErr(logger, err)
		}
	}
}

// handleRequestAddons triggers the Requestheaders addon event for all registered addons.
// It returns true if any addon provides an early response (by setting f.Response),
// indicating that the request should not be forwarded to the upstream server.
func (a *Attacker) handleRequestAddons(f *Flow) bool {
	for _, addon := range a.addonManager.Get() {
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
func (a *Attacker) readRequestBody(f *Flow, req *http.Request, logger *slog.Logger) (io.Reader, bool) {
	var reqBody io.Reader = req.Body
	if f.Stream {
		return reqBody, true
	}

	streamThreshold := a.config.GetStreamLargeBodies()
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
	for _, addon := range a.addonManager.Get() {
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

	f := newFlow()
	f.Request = newRequest(req)
	connCtx, ok := req.Context().Value(connContextKey).(*ConnContext)
	if !ok {
		panic("failed to get ConnContext from request context")
	}
	f.ConnContext = connCtx
	defer f.finish()

	f.ConnContext.FlowCount.Add(1)

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

	for _, addon := range a.addonManager.Get() {
		reqBody = addon.StreamRequestModifier(f, reqBody)
	}

	proxyRes, err := a.executeProxyRequest(f, req, reqBody, rawReqURLHost, rawReqURLScheme, res, logger)
	if err != nil {
		return
	}

	if proxyRes.Close {
		f.ConnContext.closeAfterResponse = true
	}

	defer proxyRes.Body.Close()

	f.Response = &Response{
		StatusCode: proxyRes.StatusCode,
		Header:     proxyRes.Header,
		close:      proxyRes.Close,
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

	for _, addon := range a.addonManager.Get() {
		resBody = addon.StreamResponseModifier(f, resBody)
	}

	a.replyToClient(res, f.Response, resBody, logger)
}
