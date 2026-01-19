package proxy

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/denisvmedia/go-mitmproxy/internal/helper"
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
	wc := newWrapClientConn(c, proxy)
	connCtx := newConnContext(wc, proxy)
	wc.connCtx = connCtx

	for _, addon := range proxy.Addons {
		addon.ClientConnected(connCtx.ClientConn)
	}

	return wc, nil
}

// wrap tcpConn for remote client.
type wrapClientConn struct {
	net.Conn
	r       *bufio.Reader
	proxy   *Proxy
	connCtx *ConnContext

	closeMu   sync.Mutex
	closed    bool
	closeErr  error
	closeChan chan struct{}
}

func newWrapClientConn(c net.Conn, proxy *Proxy) *wrapClientConn {
	return &wrapClientConn{
		Conn:      c,
		r:         bufio.NewReader(c),
		proxy:     proxy,
		closeChan: make(chan struct{}),
	}
}

func (c *wrapClientConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

func (c *wrapClientConn) Read(data []byte) (int, error) {
	return c.r.Read(data)
}

func (c *wrapClientConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	slog.Debug("wrapClientConn close", "remoteAddr", c.connCtx.ClientConn.Conn.RemoteAddr().String())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()
	close(c.closeChan)

	for _, addon := range c.proxy.Addons {
		addon.ClientDisconnected(c.connCtx.ClientConn)
	}

	if c.connCtx.ServerConn != nil && c.connCtx.ServerConn.Conn != nil {
		c.connCtx.ServerConn.Conn.Close()
	}

	return c.closeErr
}

// wrap tcpConn for remote server.
type wrapServerConn struct {
	net.Conn
	proxy   *Proxy
	connCtx *ConnContext

	closeMu  sync.Mutex
	closed   bool
	closeErr error
}

func (c *wrapServerConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	slog.Debug("wrapServerConn close", "remoteAddr", c.connCtx.ClientConn.Conn.RemoteAddr().String())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()

	for _, addon := range c.proxy.Addons {
		addon.ServerDisconnected(c.connCtx)
	}

	if !c.connCtx.ClientConn.TLS {
		_ = c.connCtx.ClientConn.Conn.(*wrapClientConn).Conn.(*net.TCPConn).CloseRead()
	} else if !c.connCtx.closeAfterResponse {
		// if keep-alive connection close
		c.connCtx.ClientConn.Conn.Close()
	}

	return c.closeErr
}

type entry struct {
	proxy  *Proxy
	server *http.Server
}

func newEntry(proxy *Proxy) *entry {
	e := &entry{proxy: proxy}
	e.server = &http.Server{
		Addr:    proxy.Opts.Addr,
		Handler: e,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, c.(*wrapClientConn).connCtx)
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
		for _, addon := range proxy.Addons {
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
	proxy.attacker.initHTTPDialFn(req)
	proxy.attacker.attack(res, req)
}

func (e *entry) handleConnect(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	logger := slog.Default().With(
		"in", "Proxy.entry.handleConnect",
		"host", req.Host,
	)

	shouldIntercept := proxy.shouldIntercept == nil || proxy.shouldIntercept(req)
	f := newFlow()
	f.Request = newRequest(req)
	connCtx, ok := req.Context().Value(connContextKey).(*ConnContext)
	if !ok {
		panic("failed to get ConnContext from request context")
	}
	f.ConnContext = connCtx
	f.ConnContext.Intercept = shouldIntercept
	defer f.finish()

	// trigger addon event Requestheaders
	for _, addon := range proxy.Addons {
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
	for _, addon := range e.proxy.Addons {
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

	conn, err := proxy.getUpstreamConn(req.Context(), req)
	if err != nil {
		logger.Error("get upstream conn failed", "error", err)
		res.WriteHeader(502)
		return
	}
	defer conn.Close()

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		logger.Error("establish connection failed", "error", err)
		return
	}
	defer cconn.Close()

	transfer(logger, conn, cconn)
}

func (e *entry) httpsDialFirstAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	logger := slog.Default().With(
		"in", "Proxy.entry.httpsDialFirstAttack",
		"host", req.Host,
	)

	conn, err := proxy.attacker.httpsDial(req.Context(), req)
	if err != nil {
		logger.Error("httpsDial failed", "error", err)
		res.WriteHeader(502)
		return
	}

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		conn.Close()
		logger.Error("establish connection failed", "error", err)
		return
	}

	peek, err := cconn.(*wrapClientConn).Peek(3)
	if err != nil {
		cconn.Close()
		conn.Close()
		logger.Error("peek failed", "error", err)
		return
	}
	if !helper.IsTLS(peek) {
		// todo: http, ws
		transfer(logger, conn, cconn)
		cconn.Close()
		conn.Close()
		return
	}

	// is tls
	f.ConnContext.ClientConn.TLS = true
	proxy.attacker.httpsTLSDial(req.Context(), cconn, conn)
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

	peek, err := cconn.(*wrapClientConn).Peek(3)
	if err != nil {
		cconn.Close()
		logger.Error("peek failed", "error", err)
		return
	}

	if !helper.IsTLS(peek) {
		// todo: http, ws
		conn, err := proxy.attacker.httpsDial(req.Context(), req)
		if err != nil {
			cconn.Close()
			logger.Error("httpsDial failed", "error", err)
			return
		}
		transfer(logger, conn, cconn)
		conn.Close()
		cconn.Close()
		return
	}

	// is tls
	f.ConnContext.ClientConn.TLS = true
	proxy.attacker.httpsLazyAttack(req.Context(), cconn, req)
}
