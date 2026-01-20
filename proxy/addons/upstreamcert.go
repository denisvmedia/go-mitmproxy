package addons

import "github.com/denisvmedia/go-mitmproxy/proxy"

type UpstreamCertAddon struct {
	proxy.BaseAddon
	UpstreamCert bool // Connect to upstream server to look up certificate details.
}

func NewUpstreamCertAddon(upstreamCert bool) *UpstreamCertAddon {
	return &UpstreamCertAddon{UpstreamCert: upstreamCert}
}

func (adn *UpstreamCertAddon) ClientConnected(conn *proxy.ClientConn) {
	conn.UpstreamCert = adn.UpstreamCert
}
