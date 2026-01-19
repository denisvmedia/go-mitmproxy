package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

var normalErrMsgs []string = []string{
	"read: connection reset by peer",
	"write: broken pipe",
	"i/o timeout",
	"net/http: TLS handshake timeout",
	"io: read/write on closed pipe",
	"connect: connection refused",
	"connect: connection reset by peer",
	"use of closed network connection",
}

// Only print unexpected error messages.
func logErr(logger *slog.Logger, err error) {
	msg := err.Error()

	for _, str := range normalErrMsgs {
		if strings.Contains(msg, str) {
			logger.Debug("normal error", "error", err)
			return
		}
	}

	logger.Error("unexpected error", "error", err)
}

// Transfer traffic.
func transfer(logger *slog.Logger, server, client io.ReadWriteCloser) {
	done := make(chan struct{})
	defer close(done)

	errChan := make(chan error)
	go func() {
		_, err := io.Copy(server, client)
		logger.Debug("client copy end", "error", err)
		client.Close()
		select {
		case <-done:
			return
		case errChan <- err:
			return
		}
	}()
	go func() {
		_, err := io.Copy(client, server)
		logger.Debug("server copy end", "error", err)
		server.Close()

		if clientConn, ok := client.(*wrapClientConn); ok {
			err := clientConn.Conn.(*net.TCPConn).CloseRead()
			logger.Debug("clientConn.Conn.(*net.TCPConn).CloseRead()", "error", err)
		}

		select {
		case <-done:
			return
		case errChan <- err:
			return
		}
	}()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			logErr(logger, err)
			return // If there's an error, return immediately
		}
	}
}

func httpError(w http.ResponseWriter, errMsg string, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`) // Indicates that the proxy server requires client credentials
	w.WriteHeader(code)
	fmt.Fprintln(w, errMsg)
}
