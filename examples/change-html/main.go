package main

import (
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/denisvmedia/go-mitmproxy/cert"
	"github.com/denisvmedia/go-mitmproxy/proxy"
)

var titleRegexp = regexp.MustCompile("(<title>)(.*?)(</title>)")

type ChangeHTML struct {
	proxy.BaseAddon
}

func (*ChangeHTML) Response(f *proxy.Flow) {
	contentType := f.Response.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		return
	}

	// change html <title> end with: " - go-mitmproxy"
	f.Response.ReplaceToDecodedBody()
	f.Response.Body = titleRegexp.ReplaceAll(f.Response.Body, []byte("${1}${2} - go-mitmproxy${3}"))
	f.Response.Header.Set("Content-Length", strconv.Itoa(len(f.Response.Body)))
}

func main() {
	ca, err := cert.NewSelfSignCA("")
	if err != nil {
		slog.Error("failed to create CA", "error", err)
		return
	}

	config := proxy.Config{
		Addr:              ":9080",
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxy(config, ca)
	if err != nil {
		slog.Error("failed to create proxy", "error", err)
		return
	}

	p.AddAddon(&ChangeHTML{})

	if err := p.Start(); err != nil {
		slog.Error("proxy exited", "error", err)
	}
}
