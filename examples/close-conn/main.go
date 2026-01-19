package main

import (
	"log/slog"

	"github.com/denisvmedia/go-mitmproxy/proxy"
)

//
// When the proxy forwards HTTPS requests, go-mitmproxy by default initiates an SSL connection with the target server first.
// 1. If you do not want to establish a connection with the target server, such as:
//    Generating a response directly in the RequestHeaders or Request Hook and returning it to the client.
// 2. Or if you want the proxy to establish a connect connection with the client first, delaying the connection with the target service until a real HTTPS request is made.
//
// => Then you can refer to the following code
//    set client.UpstreamCert = false in the ClientConnected Hook.

type CloseConn struct {
	proxy.BaseAddon
}

func (*CloseConn) ClientConnected(client *proxy.ClientConn) {
	// necessary
	client.UpstreamCert = false
}

func (*CloseConn) Requestheaders(f *proxy.Flow) {
	// give some response to client
	// then will not request remote server
	f.Response = &proxy.Response{
		StatusCode: 502,
	}
}

func main() {
	opts := &proxy.Options{
		Addr:              ":9080",
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		slog.Error("failed to create proxy", "error", err)
		return
	}

	p.AddAddon(&CloseConn{})
	p.AddAddon(&proxy.LogAddon{})

	if err := p.Start(); err != nil {
		slog.Error("proxy exited", "error", err)
	}
}
