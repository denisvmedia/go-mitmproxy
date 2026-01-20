package upstream_test

import (
	"net/http"
	"net/url"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy/internal/upstream"
)

func TestNewManagerCreatesInstance(t *testing.T) {
	c := qt.New(t)

	mgr := upstream.NewManager("http://proxy:8080", true)

	c.Assert(mgr, qt.IsNotNil)
}

func TestManagerGetUpstreamProxyURLReturnsConfiguredUpstream(t *testing.T) {
	c := qt.New(t)

	mgr := upstream.NewManager("http://proxy:8080", false)
	req := &http.Request{
		URL:  &url.URL{Scheme: "https", Host: "example.com"},
		Host: "example.com",
	}

	proxyURL, err := mgr.GetUpstreamProxyURL(req)

	c.Assert(err, qt.IsNil)
	c.Assert(proxyURL, qt.IsNotNil)
	c.Assert(proxyURL.String(), qt.Equals, "http://proxy:8080")
}

func TestManagerGetUpstreamProxyURLUsesCustomFunction(t *testing.T) {
	c := qt.New(t)

	mgr := upstream.NewManager("", false)
	customURL, _ := url.Parse("http://custom:9090")

	mgr.SetUpstreamProxy(func(_ *http.Request) (*url.URL, error) {
		return customURL, nil
	})

	req := &http.Request{
		URL:  &url.URL{Scheme: "https", Host: "example.com"},
		Host: "example.com",
	}

	proxyURL, err := mgr.GetUpstreamProxyURL(req)

	c.Assert(err, qt.IsNil)
	c.Assert(proxyURL.String(), qt.Equals, "http://custom:9090")
}
