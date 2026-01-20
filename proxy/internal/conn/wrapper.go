package conn

import (
	"bufio"
	"log/slog"
	"net"
	"sync"
)

// AddonNotifier defines callbacks for addon notifications.
type AddonNotifier interface {
	NotifyClientDisconnected(*ClientConn)
	NotifyServerDisconnected(*Context)
}

// WrapClientConn wraps a net.Conn for remote client connections.
type WrapClientConn struct {
	net.Conn
	r             *bufio.Reader
	ConnCtx       *Context
	addonNotifier AddonNotifier

	closeMu   sync.Mutex
	closed    bool
	closeErr  error
	CloseChan chan struct{}
}

// NewWrapClientConn creates a new wrapped client connection.
func NewWrapClientConn(c net.Conn, addonNotifier AddonNotifier) *WrapClientConn {
	return &WrapClientConn{
		Conn:          c,
		r:             bufio.NewReader(c),
		addonNotifier: addonNotifier,
		CloseChan:     make(chan struct{}),
	}
}

// Peek returns the next n bytes without advancing the reader.
func (c *WrapClientConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

// Read reads data from the connection.
func (c *WrapClientConn) Read(data []byte) (int, error) {
	return c.r.Read(data)
}

// Close closes the connection and notifies addons.
func (c *WrapClientConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	slog.Debug("WrapClientConn close", "remoteAddr", c.ConnCtx.ClientConn.Conn.RemoteAddr().String())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()
	close(c.CloseChan)

	if c.addonNotifier != nil {
		c.addonNotifier.NotifyClientDisconnected(c.ConnCtx.ClientConn)
	}

	if c.ConnCtx.ServerConn != nil && c.ConnCtx.ServerConn.Conn != nil {
		c.ConnCtx.ServerConn.Conn.Close()
	}

	return c.closeErr
}

// WrapServerConn wraps a net.Conn for remote server connections.
type WrapServerConn struct {
	net.Conn
	ConnCtx       *Context
	addonNotifier AddonNotifier

	closeMu  sync.Mutex
	closed   bool
	closeErr error
}

// NewWrapServerConn creates a new wrapped server connection.
func NewWrapServerConn(c net.Conn, connCtx *Context, addonNotifier AddonNotifier) *WrapServerConn {
	return &WrapServerConn{
		Conn:          c,
		ConnCtx:       connCtx,
		addonNotifier: addonNotifier,
	}
}

// Close closes the connection and notifies addons.
func (c *WrapServerConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}
	slog.Debug("WrapServerConn close", "remoteAddr", c.ConnCtx.ClientConn.Conn.RemoteAddr().String())

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()

	if c.addonNotifier != nil {
		c.addonNotifier.NotifyServerDisconnected(c.ConnCtx)
	}

	if !c.ConnCtx.ClientConn.TLS {
		// Try to close read on the client connection
		if wcc, ok := c.ConnCtx.ClientConn.Conn.(*WrapClientConn); ok {
			if tcpConn, ok := wcc.Conn.(*net.TCPConn); ok {
				_ = tcpConn.CloseRead()
			}
		}
	} else if !c.ConnCtx.CloseAfterResponse {
		// if keep-alive connection close
		c.ConnCtx.ClientConn.Conn.Close()
	}

	return c.closeErr
}
