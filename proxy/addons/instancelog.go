package addons

import (
	"time"

	"github.com/denisvmedia/go-mitmproxy/proxy"
)

// InstanceLogAddon logs with instance identification.
type InstanceLogAddon struct {
	proxy.BaseAddon
	logger *proxy.InstanceLogger
}

// NewInstanceLogAddonWithFile creates a new instance-aware log addon with file output.
func NewInstanceLogAddonWithFile(addr, instanceName, logFilePath string) *InstanceLogAddon {
	return &InstanceLogAddon{
		logger: proxy.NewInstanceLoggerWithFile(addr, instanceName, logFilePath),
	}
}

// SetLogger allows setting a custom instance logger.
func (adn *InstanceLogAddon) SetLogger(logger *proxy.InstanceLogger) {
	adn.logger = logger
}

func (adn *InstanceLogAddon) ClientConnected(client *proxy.ClientConn) {
	adn.logger.WithFields(map[string]any{
		"client_addr": client.Conn.RemoteAddr().String(),
		"event":       "client_connected",
	}).Info("Client connected")
}

func (adn *InstanceLogAddon) ClientDisconnected(client *proxy.ClientConn) {
	adn.logger.WithFields(map[string]any{
		"client_addr": client.Conn.RemoteAddr().String(),
		"event":       "client_disconnected",
	}).Info("Client disconnected")
}

func (adn *InstanceLogAddon) ServerConnected(connCtx *proxy.ConnContext) {
	adn.logger.WithFields(map[string]any{
		"client_addr": connCtx.ClientConn.Conn.RemoteAddr().String(),
		"server_addr": connCtx.ServerConn.Address,
		"local_addr":  connCtx.ServerConn.Conn.LocalAddr().String(),
		"remote_addr": connCtx.ServerConn.Conn.RemoteAddr().String(),
		"event":       "server_connected",
	}).Info("Server connected")
}

func (adn *InstanceLogAddon) ServerDisconnected(connCtx *proxy.ConnContext) {
	adn.logger.WithFields(map[string]any{
		"client_addr": connCtx.ClientConn.Conn.RemoteAddr().String(),
		"server_addr": connCtx.ServerConn.Address,
		"local_addr":  connCtx.ServerConn.Conn.LocalAddr().String(),
		"remote_addr": connCtx.ServerConn.Conn.RemoteAddr().String(),
		"flow_count":  connCtx.FlowCount.Load(),
		"event":       "server_disconnected",
	}).Info("Server disconnected")
}

func (adn *InstanceLogAddon) Requestheaders(f *proxy.Flow) {
	start := time.Now()

	adn.logger.WithFields(map[string]any{
		"client_addr": f.ConnContext.ClientConn.Conn.RemoteAddr().String(),
		"method":      f.Request.Method,
		"url":         f.Request.URL.String(),
		"event":       "request_headers",
	}).Debug("Request headers received")

	// Log completion asynchronously
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

		adn.logger.WithFields(map[string]any{
			"client_addr": f.ConnContext.ClientConn.Conn.RemoteAddr().String(),
			"method":      f.Request.Method,
			"url":         f.Request.URL.String(),
			"status_code": statusCode,
			"content_len": contentLen,
			"duration_ms": time.Since(start).Milliseconds(),
			"event":       "request_completed",
		}).Info("Request completed")
	}()
}

func (adn *InstanceLogAddon) TLSEstablishedServer(connCtx *proxy.ConnContext) {
	adn.logger.WithFields(map[string]any{
		"client_addr": connCtx.ClientConn.Conn.RemoteAddr().String(),
		"server_addr": connCtx.ServerConn.Address,
		"event":       "tls_established",
	}).Debug("TLS connection established with server")
}

func (adn *InstanceLogAddon) Request(f *proxy.Flow) {
	bodyLen := 0
	if f.Request.Body != nil {
		bodyLen = len(f.Request.Body)
	}

	adn.logger.WithFields(map[string]any{
		"client_addr": f.ConnContext.ClientConn.Conn.RemoteAddr().String(),
		"method":      f.Request.Method,
		"url":         f.Request.URL.String(),
		"body_len":    bodyLen,
		"event":       "request_body",
	}).Debug("Full request received")
}

func (adn *InstanceLogAddon) Response(f *proxy.Flow) {
	bodyLen := 0
	if f.Response != nil && f.Response.Body != nil {
		bodyLen = len(f.Response.Body)
	}

	adn.logger.WithFields(map[string]any{
		"client_addr": f.ConnContext.ClientConn.Conn.RemoteAddr().String(),
		"method":      f.Request.Method,
		"url":         f.Request.URL.String(),
		"status_code": f.Response.StatusCode,
		"body_len":    bodyLen,
		"event":       "response_body",
	}).Debug("Full response received")
}
