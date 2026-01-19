package main

import (
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

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
	opts := &proxy.Options{
		Addr:              ":9080",
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	p.AddAddon(&ChangeHTML{})

	log.Fatal(p.Start())
}
