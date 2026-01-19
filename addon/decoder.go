package addon

import "github.com/denisvmedia/go-mitmproxy/proxy"

// decode content-encoding then respond to client

type Decoder struct {
	proxy.BaseAddon
}

func (*Decoder) Response(f *proxy.Flow) {
	f.Response.ReplaceToDecodedBody()
}
