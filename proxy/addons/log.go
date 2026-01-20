package addons

import (
	"log/slog"
	"time"

	"github.com/denisvmedia/go-mitmproxy/proxy"
)

// LogAddon logs connection and flow events using the global slog logger.
type LogAddon struct {
	proxy.BaseAddon
}

func (*LogAddon) ClientConnected(client *proxy.ClientConn) {
	slog.Info("client connected", "remoteAddr", client.Conn.RemoteAddr().String())
}

func (*LogAddon) ClientDisconnected(client *proxy.ClientConn) {
	slog.Info("client disconnected", "remoteAddr", client.Conn.RemoteAddr().String())
}

func (*LogAddon) ServerConnected(connCtx *proxy.ConnContext) {
	slog.Info("server connected",
		"clientAddr", connCtx.ClientConn.Conn.RemoteAddr().String(),
		"serverAddr", connCtx.ServerConn.Address,
		"localAddr", connCtx.ServerConn.Conn.LocalAddr().String(),
		"remoteAddr", connCtx.ServerConn.Conn.RemoteAddr().String(),
	)
}

func (*LogAddon) ServerDisconnected(connCtx *proxy.ConnContext) {
	slog.Info("server disconnected",
		"clientAddr", connCtx.ClientConn.Conn.RemoteAddr().String(),
		"serverAddr", connCtx.ServerConn.Address,
		"localAddr", connCtx.ServerConn.Conn.LocalAddr().String(),
		"remoteAddr", connCtx.ServerConn.Conn.RemoteAddr().String(),
		"flowCount", connCtx.FlowCount.Load(),
	)
}

func (*LogAddon) Requestheaders(f *proxy.Flow) {
	slog.Debug("request headers",
		"clientAddr", f.ConnContext.ClientConn.Conn.RemoteAddr().String(),
		"method", f.Request.Method,
		"url", f.Request.URL.String(),
	)
	start := time.Now()
	go func() {
		<-f.Done()
		var statusCode int
		if f.Response != nil {
			statusCode = f.Response.StatusCode
		}
		var contentLen int
		if f.Response != nil && f.Response.Body != nil {
			contentLen = len(f.Response.Body)
		}
		slog.Info("request completed",
			"clientAddr", f.ConnContext.ClientConn.Conn.RemoteAddr().String(),
			"method", f.Request.Method,
			"url", f.Request.URL.String(),
			"status", statusCode,
			"contentLength", contentLen,
			"durationMs", time.Since(start).Milliseconds(),
		)
	}()
}
