package main

import (
	"log/slog"
	"strconv"

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
	opts := &proxy.Options{
		Addr:              ":9080",
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		slog.Error("failed to create proxy", "error", err)
		return
	}

	p.AddAddon(&AddHeader{})

	if err := p.Start(); err != nil {
		slog.Error("proxy exited", "error", err)
	}
}
