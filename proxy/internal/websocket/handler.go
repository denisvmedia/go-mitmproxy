package websocket

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

// Handler implements WebSocket handling for the proxy.
type Handler struct{}

// New creates a new WebSocket handler.
func New() *Handler {
	return &Handler{}
}

// HandleWSS handles WebSocket Secure (WSS) connections.
// It upgrades the connection and forwards traffic between client and server.
func (h *Handler) HandleWSS(res http.ResponseWriter, req *http.Request) {
	logger := slog.Default().With(
		"in", "websocket.HandleWSS",
		"host", req.Host,
	)

	upgradeBuf, err := httputil.DumpRequest(req, false)
	if err != nil {
		logger.Error("DumpRequest failed", "error", err)
		res.WriteHeader(502)
		return
	}

	cconn, _, err := res.(http.Hijacker).Hijack()
	if err != nil {
		slog.Error("Hijack failed", "error", err)
		res.WriteHeader(502)
		return
	}
	defer cconn.Close()

	host := req.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		slog.Error("tls.Dial failed", "error", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(upgradeBuf)
	if err != nil {
		logger.Error("wss upgrade failed", "error", err)
		return
	}
	transfer(logger, conn, cconn)
}

// transfer bidirectionally transfers data between two connections.
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

		select {
		case <-done:
			return
		case errChan <- err:
			return
		}
	}()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			logger.Debug("transfer error", "error", err)
			return // If there's an error, return immediately
		}
	}
}

// logErr logs errors, filtering out common expected errors.
func logErr(logger *slog.Logger, err error) {
	if err == nil {
		return
	}
	if err == io.EOF {
		return
	}
	if err == io.ErrUnexpectedEOF {
		return
	}
	msg := err.Error()
	if msg == "read: connection reset by peer" {
		return
	}
	if msg == "write: broken pipe" {
		return
	}
	if strings.Contains(msg, "use of closed network connection") {
		return
	}
	if strings.Contains(msg, "i/o timeout") {
		return
	}
	if strings.Contains(msg, "operation was canceled") {
		return
	}
	if strings.Contains(msg, "context canceled") {
		return
	}
	if strings.Contains(msg, "TLS handshake timeout") {
		return
	}
	if strings.Contains(msg, "server closed idle connection") {
		return
	}
	if strings.Contains(msg, "http: server closed idle connection") {
		return
	}
	if strings.Contains(msg, "connection reset by peer") {
		return
	}
	if strings.Contains(msg, "broken pipe") {
		return
	}
	if strings.Contains(msg, "deadline exceeded") {
		return
	}
	if strings.Contains(msg, "operation timed out") {
		return
	}

	_ = time.Now() // Suppress unused import warning
	logger.Error("unexpected error", "error", err)
}

