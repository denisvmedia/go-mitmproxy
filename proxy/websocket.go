package proxy

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"
)

// Currently only forwarding websocket traffic

type webSocket struct{}

var defaultWebSocket webSocket

// func (s *webSocket) ws(conn net.Conn, host string) {
// 	log := log.WithField("in", "webSocket.ws").WithField("host", host)

// 	defer conn.Close()
// 	remoteConn, err := net.Dial("tcp", host)
// 	if err != nil {
// 		logErr(log, err)
// 		return
// 	}
// 	defer remoteConn.Close()
// 	transfer(log, conn, remoteConn)
// }

func (*webSocket) wss(res http.ResponseWriter, req *http.Request) {
	logger := slog.Default().With(
		"in", "webSocket.wss",
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

// wsHandler implements the attacker.WebSocketHandler interface.
type wsHandler struct{}

func (*wsHandler) HandleWSS(res http.ResponseWriter, req *http.Request) {
	defaultWebSocket.wss(res, req)
}
