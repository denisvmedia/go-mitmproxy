package main

import (
	"log/slog"

	"github.com/denisvmedia/go-mitmproxy/proxy"
)

type RewriteHost struct {
	proxy.BaseAddon
}

func (*RewriteHost) ClientConnected(client *proxy.ClientConn) {
	// necessary
	client.UpstreamCert = false
}

func (*RewriteHost) Requestheaders(f *proxy.Flow) {
	slog.Info("rewrite host request",
		"host", f.Request.URL.Host,
		"method", f.Request.Method,
		"scheme", f.Request.URL.Scheme,
	)
	f.Request.URL.Host = "www.baidu.com"
	f.Request.URL.Scheme = "http"
	slog.Info("rewrite host result", "url", f.Request.URL)
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

	p.AddAddon(&RewriteHost{})
	p.AddAddon(&proxy.LogAddon{})

	if err := p.Start(); err != nil {
		slog.Error("proxy exited", "error", err)
	}
}
