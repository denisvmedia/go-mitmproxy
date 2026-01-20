package main

import (
	"log/slog"
	"net"
	"net/http"

	"github.com/denisvmedia/go-mitmproxy/proxy"
)

func main() {
	config := proxy.Config{
		Addr:              ":8081",
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxy(config, NewTrustedCA())
	if err != nil {
		slog.Error("failed to create proxy", "error", err)
		return
	}
	p.SetShouldInterceptRule(func(req *http.Request) bool {
		host, _, err2 := net.SplitHostPort(req.URL.Host)
		if err2 != nil {
			return false
		}
		return host == "your-domain.xx.com" || host == "your-domain2.xx.com" // filter your-domain
	})
	p.AddAddon(&YourAddOn{})
	if err := p.Start(); err != nil {
		slog.Error("proxy exited", "error", err)
	}
}

type YourAddOn struct {
	proxy.BaseAddon
}

func (*YourAddOn) ClientConnected(client *proxy.ClientConn) {
	client.UpstreamCert = false // don't connect to upstream server
}

func (*YourAddOn) Request(flow *proxy.Flow) {
	flow.Done()
	resp := &proxy.Response{
		StatusCode: 200,
		Header:     nil,
		Body:       []byte("changed response"),
		BodyReader: nil,
	}
	flow.Response = resp
}
