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

// wrap tcpListener for remote client.
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

type entry struct {
	proxy  *Proxy
	server *http.Server
}

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

func (e *entry) close() error {
	return e.server.Close()
}

func (e *entry) shutdown(ctx context.Context) error {
	return e.server.Shutdown(ctx)
}

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
