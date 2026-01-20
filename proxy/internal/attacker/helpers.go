package attacker

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

var normalErrMsgs = []string{
	"read: connection reset by peer",
	"write: broken pipe",
	"i/o timeout",
	"net/http: TLS handshake timeout",
	"io: read/write on closed pipe",
	"connect: connection refused",
	"connect: connection reset by peer",
	"use of closed network connection",
}

// logErr logs errors, filtering out normal/expected errors.
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

// httpError writes an HTTP error response.
func httpError(w http.ResponseWriter, errMsg string, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
	w.WriteHeader(code)
	fmt.Fprintln(w, errMsg)
}
