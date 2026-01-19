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

type attackerListener struct {
	connChan chan net.Conn
}

func (l *attackerListener) accept(conn net.Conn) {
	l.connChan <- conn
}

func (l *attackerListener) Accept() (net.Conn, error) {
	c := <-l.connChan
	return c, nil
}
func (*attackerListener) Close() error   { return nil }
func (*attackerListener) Addr() net.Addr { return nil }

type attackerConn struct {
	net.Conn
	connCtx *ConnContext
}

type attacker struct {
	proxy    *Proxy
	ca       cert.CA
	server   *http.Server
	h2Server *http2.Server
	client   *http.Client
	listener *attackerListener
}

func newAttacker(proxy *Proxy) (*attacker, error) {
	ca, err := newCa(proxy.Opts)
	if err != nil {
		return nil, err
	}

	a := &attacker{
		proxy: proxy,
		ca:    ca,
		client: &http.Client{
			Transport: &http.Transport{
				Proxy:              proxy.realUpstreamProxy(),
				ForceAttemptHTTP2:  true,
				DisableCompression: true, // To get the original response from the server, set Transport.DisableCompression to true.
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: proxy.Opts.SslInsecure,
					KeyLogWriter:       helper.GetTLSKeyLogWriter(),
				},
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
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

func newCa(opts *Options) (cert.CA, error) {
	newCaFunc := opts.NewCaFunc
	if newCaFunc != nil {
		return newCaFunc()
	}
	return cert.NewSelfSignCA(opts.CaRootPath)
}

func (a *attacker) start() error {
	return a.server.Serve(a.listener)
}

func (a *attacker) serveConn(clientTLSConn *tls.Conn, connCtx *ConnContext) {
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

func (a *attacker) ServeHTTP(res http.ResponseWriter, req *http.Request) {
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
	a.attack(res, req)
}

func (a *attacker) initHTTPDialFn(req *http.Request) {
	connCtx, ok := req.Context().Value(connContextKey).(*ConnContext)
	if !ok {
		panic("failed to get ConnContext from request context")
	}
	connCtx.dialFn = func(ctx context.Context) error {
		addr := helper.CanonicalAddr(req.URL)
		c, err := a.proxy.getUpstreamConn(ctx, req)
		if err != nil {
			return err
		}
		proxy := a.proxy
		cw := &wrapServerConn{
			Conn:    c,
			proxy:   proxy,
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
		for _, addon := range proxy.Addons {
			addon.ServerConnected(connCtx)
		}

		return nil
	}
}

// send clientHello to server, server handshake.
func (a *attacker) serverTLSHandshake(ctx context.Context, connCtx *ConnContext) error {
	proxy := a.proxy
	clientHello := connCtx.ClientConn.clientHello
	serverConn := connCtx.ServerConn

	serverTLSConfig := &tls.Config{
		InsecureSkipVerify: proxy.Opts.SslInsecure,
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
	for _, addon := range proxy.Addons {
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

func (a *attacker) initHTTPSDialFn(req *http.Request) {
	connCtx, ok := req.Context().Value(connContextKey).(*ConnContext)
	if !ok {
		panic("failed to get ConnContext from request context")
	}

	connCtx.dialFn = func(ctx context.Context) error {
		_, err := a.httpsDial(ctx, req)
		if err != nil {
			return err
		}
		if err := a.serverTLSHandshake(ctx, connCtx); err != nil {
			return err
		}
		return nil
	}
}

func (a *attacker) httpsDial(ctx context.Context, req *http.Request) (net.Conn, error) {
	proxy := a.proxy
	connCtx, ok := req.Context().Value(connContextKey).(*ConnContext)
	if !ok {
		panic("failed to get ConnContext from request context")
	}

	plainConn, err := proxy.getUpstreamConn(ctx, req)
	if err != nil {
		return nil, err
	}

	serverConn := newServerConn()
	serverConn.Address = req.Host
	serverConn.Conn = &wrapServerConn{
		Conn:    plainConn,
		proxy:   proxy,
		connCtx: connCtx,
	}
	connCtx.ServerConn = serverConn
	for _, addon := range connCtx.proxy.Addons {
		addon.ServerConnected(connCtx)
	}

	return serverConn.Conn, nil
}

func (a *attacker) httpsTLSDial(ctx context.Context, cconn, conn net.Conn) {
	connCtx := cconn.(*wrapClientConn).connCtx
	logger := slog.Default().With(
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

	// will go to attacker.ServeHTTP
	a.serveConn(clientTLSConn, connCtx)
}

func (a *attacker) httpsLazyAttack(ctx context.Context, cconn net.Conn, req *http.Request) {
	connCtx := cconn.(*wrapClientConn).connCtx
	logger := slog.Default().With(
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

	// will go to attacker.ServeHTTP
	a.initHTTPSDialFn(req)
	a.serveConn(clientTLSConn, connCtx)
}

func (a *attacker) executeProxyRequest(f *Flow, req *http.Request, reqBody io.Reader, rawReqURLHost, rawReqURLScheme string, res http.ResponseWriter, logger *slog.Logger) (*http.Response, error) {
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

func (*attacker) handleResponseHeadersAddons(f *Flow, proxy *Proxy) bool {
	for _, addon := range proxy.Addons {
		addon.Responseheaders(f)
		if f.Response.Body != nil {
			return true // early response
		}
	}
	return false
}

func (*attacker) readResponseBody(f *Flow, proxyRes *http.Response, proxy *Proxy, logger *slog.Logger) (io.Reader, bool) {
	var resBody io.Reader = proxyRes.Body
	if f.Stream {
		return resBody, true
	}

	resBuf, r, err := helper.ReaderToBuffer(proxyRes.Body, proxy.Opts.StreamLargeBodies)
	resBody = r
	if err != nil {
		logger.Error("failed to buffer response body", "error", err)
		return nil, false
	}

	if resBuf == nil {
		logger.Warn("response body too large, switching to stream", "threshold", proxy.Opts.StreamLargeBodies)
		f.Stream = true
		return resBody, true
	}

	f.Response.Body = resBuf

	// trigger addon event Response
	for _, addon := range proxy.Addons {
		addon.Response(f)
	}

	return resBody, true
}

func (*attacker) replyToClient(res http.ResponseWriter, response *Response, body io.Reader, logger *slog.Logger) {
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

func (*attacker) handleRequestAddons(f *Flow, proxy *Proxy) bool {
	for _, addon := range proxy.Addons {
		addon.Requestheaders(f)
		if f.Response != nil {
			return true // early response
		}
	}
	return false
}

func (*attacker) readRequestBody(f *Flow, req *http.Request, proxy *Proxy, logger *slog.Logger) (io.Reader, bool) {
	var reqBody io.Reader = req.Body
	if f.Stream {
		return reqBody, true
	}

	reqBuf, r, err := helper.ReaderToBuffer(req.Body, proxy.Opts.StreamLargeBodies)
	reqBody = r
	if err != nil {
		logger.Error("failed to buffer request body", "error", err)
		return nil, false
	}

	if reqBuf == nil {
		logger.Warn("request body too large, switching to stream", "threshold", proxy.Opts.StreamLargeBodies)
		f.Stream = true
		return reqBody, true
	}

	f.Request.Body = reqBuf

	// trigger addon event Request
	for _, addon := range proxy.Addons {
		addon.Request(f)
		if f.Response != nil {
			return nil, true // early response
		}
	}
	return bytes.NewReader(f.Request.Body), true
}

func (a *attacker) attack(res http.ResponseWriter, req *http.Request) {
	proxy := a.proxy

	logger := slog.Default().With(
		"in", "Proxy.attacker.attack",
		"url", req.URL,
		"method", req.Method,
	)

	// when addons panic
	defer func() {
		if err := recover(); err != nil {
			logger.Warn("Recovered from panic in attacker.attack", "error", err)
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
	if a.handleRequestAddons(f, proxy) {
		a.replyToClient(res, f.Response, nil, logger)
		return
	}

	// Read request body
	reqBody, ok := a.readRequestBody(f, req, proxy, logger)
	if !ok {
		res.WriteHeader(502)
		return
	}
	if f.Response != nil {
		a.replyToClient(res, f.Response, nil, logger)
		return
	}

	for _, addon := range proxy.Addons {
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
	if a.handleResponseHeadersAddons(f, proxy) {
		a.replyToClient(res, f.Response, nil, logger)
		return
	}

	// Read response body
	resBody, ok := a.readResponseBody(f, proxyRes, proxy, logger)
	if !ok {
		res.WriteHeader(502)
		return
	}

	for _, addon := range proxy.Addons {
		resBody = addon.StreamResponseModifier(f, resBody)
	}

	a.replyToClient(res, f.Response, resBody, logger)
}
