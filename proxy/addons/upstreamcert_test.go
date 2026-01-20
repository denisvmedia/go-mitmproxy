package addons_test

import (
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy"
	"github.com/denisvmedia/go-mitmproxy/proxy/addons"
)

func TestUpstreamCertAddonSetsFlag(t *testing.T) {
	c := qt.New(t)

	client := &proxy.ClientConn{}
	addon := addons.NewUpstreamCertAddon(true)
	addon.ClientConnected(client)

	c.Assert(client.UpstreamCert, qt.IsTrue)
}

func TestUpstreamCertAddonCanDisableFlag(t *testing.T) {
	c := qt.New(t)

	client := &proxy.ClientConn{UpstreamCert: true}
	addon := addons.NewUpstreamCertAddon(false)
	addon.ClientConnected(client)

	c.Assert(client.UpstreamCert, qt.IsFalse)
}
