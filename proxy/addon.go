package proxy

import (
	"io"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

type Addon interface {
	// A client has connected to mitmproxy. Note that a connection can correspond to multiple HTTP requests.
	ClientConnected(*ClientConn)

	// A client connection has been closed (either by us or the client).
	ClientDisconnected(*ClientConn)

	// Mitmproxy has connected to a server.
	ServerConnected(*ConnContext)

	// A server connection has been closed (either by us or the server).
	ServerDisconnected(*ConnContext)

	// The TLS handshake with the server has been completed successfully.
	TLSEstablishedServer(*ConnContext)

	// HTTP request headers were successfully read. At this point, the body is empty.
	Requestheaders(*Flow)

	// The full HTTP request has been read.
	Request(*Flow)

	// HTTP response headers were successfully read. At this point, the body is empty.
	Responseheaders(*Flow)

	// The full HTTP response has been read.
	Response(*Flow)

	// Stream request body modifier
	StreamRequestModifier(*Flow, io.Reader) io.Reader

	// Stream response body modifier
	StreamResponseModifier(*Flow, io.Reader) io.Reader

	// onAccessProxyServer
	AccessProxyServer(req *http.Request, res http.ResponseWriter)
}

// BaseAddon do nothing.
type BaseAddon struct{}

func (*BaseAddon) ClientConnected(*ClientConn)                              {}
func (*BaseAddon) ClientDisconnected(*ClientConn)                           {}
func (*BaseAddon) ServerConnected(*ConnContext)                             {}
func (*BaseAddon) ServerDisconnected(*ConnContext)                          {}
func (*BaseAddon) TLSEstablishedServer(*ConnContext)                        {}
func (*BaseAddon) Requestheaders(*Flow)                                     {}
func (*BaseAddon) Request(*Flow)                                            {}
func (*BaseAddon) Responseheaders(*Flow)                                    {}
func (*BaseAddon) Response(*Flow)                                           {}
func (*BaseAddon) StreamRequestModifier(_ *Flow, in io.Reader) io.Reader    { return in }
func (*BaseAddon) StreamResponseModifier(_ *Flow, in io.Reader) io.Reader   { return in }
func (*BaseAddon) AccessProxyServer(_ *http.Request, _ http.ResponseWriter) {}

// LogAddon log connection and flow.
type LogAddon struct {
	BaseAddon
}

func (*LogAddon) ClientConnected(client *ClientConn) {
	log.Infof("%v client connect\n", client.Conn.RemoteAddr())
}

func (*LogAddon) ClientDisconnected(client *ClientConn) {
	log.Infof("%v client disconnect\n", client.Conn.RemoteAddr())
}

func (*LogAddon) ServerConnected(connCtx *ConnContext) {
	log.Infof("%v server connect %v (%v->%v)\n", connCtx.ClientConn.Conn.RemoteAddr(), connCtx.ServerConn.Address, connCtx.ServerConn.Conn.LocalAddr(), connCtx.ServerConn.Conn.RemoteAddr())
}

func (*LogAddon) ServerDisconnected(connCtx *ConnContext) {
	log.Infof("%v server disconnect %v (%v->%v) - %v\n", connCtx.ClientConn.Conn.RemoteAddr(), connCtx.ServerConn.Address, connCtx.ServerConn.Conn.LocalAddr(), connCtx.ServerConn.Conn.RemoteAddr(), connCtx.FlowCount.Load())
}

func (*LogAddon) Requestheaders(f *Flow) {
	log.Debugf("%v Requestheaders %v %v\n", f.ConnContext.ClientConn.Conn.RemoteAddr(), f.Request.Method, f.Request.URL.String())
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
		log.Infof("%v %v %v %v %v - %v ms\n", f.ConnContext.ClientConn.Conn.RemoteAddr(), f.Request.Method, f.Request.URL.String(), statusCode, contentLen, time.Since(start).Milliseconds())
	}()
}

type UpstreamCertAddon struct {
	BaseAddon
	UpstreamCert bool // Connect to upstream server to look up certificate details.
}

func NewUpstreamCertAddon(upstreamCert bool) *UpstreamCertAddon {
	return &UpstreamCertAddon{UpstreamCert: upstreamCert}
}

func (adn *UpstreamCertAddon) ClientConnected(conn *ClientConn) {
	conn.UpstreamCert = adn.UpstreamCert
}
