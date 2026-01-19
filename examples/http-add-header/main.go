package main

import (
	"log/slog"
	"strconv"

	"github.com/denisvmedia/go-mitmproxy/cert"
	"github.com/denisvmedia/go-mitmproxy/proxy"
)

type AddHeader struct {
	proxy.BaseAddon
	count int
}

func (a *AddHeader) Responseheaders(f *proxy.Flow) {
	a.count++
	f.Response.Header.Add("x-count", strconv.Itoa(a.count))
}

func main() {
	ca, err := cert.NewSelfSignCA("")
	if err != nil {
		slog.Error("failed to create CA", "error", err)
		return
	}

	config := &proxy.Config{
		Addr:              ":9080",
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxyWithDefaults(config, ca)
	if err != nil {
		slog.Error("failed to create proxy", "error", err)
		return
	}

	p.AddAddon(&AddHeader{})

	if err := p.Start(); err != nil {
		slog.Error("proxy exited", "error", err)
	}
}
