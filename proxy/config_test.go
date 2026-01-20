package proxy_test

import (
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/cert"
	"github.com/denisvmedia/go-mitmproxy/proxy"
)

func TestConfigStreamLargeBodiesDefaultIsApplied(t *testing.T) {
	c := qt.New(t)

	ca, err := cert.NewSelfSignCAMemory()
	c.Assert(err, qt.IsNil)

	cfg := proxy.Config{Addr: ":0"}
	p, err := proxy.NewProxy(cfg, ca)
	c.Assert(err, qt.IsNil)

	c.Assert(p, qt.IsNotNil)
}

func TestConfigWithCustomStreamLargeBodies(t *testing.T) {
	c := qt.New(t)

	ca, err := cert.NewSelfSignCAMemory()
	c.Assert(err, qt.IsNil)

	cfg := proxy.Config{
		Addr:              ":0",
		StreamLargeBodies: 2048,
	}

	p, err := proxy.NewProxy(cfg, ca)
	c.Assert(err, qt.IsNil)
	c.Assert(p, qt.IsNotNil)
}

func TestConfigWithUpstreamProxy(t *testing.T) {
	c := qt.New(t)

	ca, err := cert.NewSelfSignCAMemory()
	c.Assert(err, qt.IsNil)

	cfg := proxy.Config{
		Addr:     ":0",
		Upstream: "http://upstream:3128",
	}

	p, err := proxy.NewProxy(cfg, ca)
	c.Assert(err, qt.IsNil)
	c.Assert(p, qt.IsNotNil)
}
