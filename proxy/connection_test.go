package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
)

func testGetResponse(c *qt.C, endpoint string, client *http.Client) *http.Response {
	c.Helper()
	req, err := http.NewRequest("GET", endpoint, nil)
	c.Assert(err, qt.IsNil)
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	c.Assert(err, qt.IsNil)
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	c.Assert(err, qt.IsNil)
	return resp
}

type testConnectionAddon struct {
	BaseAddon
}

func (*testConnectionAddon) Response(f *Flow) {
	tlsStr := "0"
	if f.ConnContext.ClientConn.TLS {
		tlsStr = "1"
	}
	f.Response.Header.Add("tls", tlsStr)

	pStr := "null"
	if f.ConnContext.ClientConn.NegotiatedProtocol != "" {
		pStr = f.ConnContext.ClientConn.NegotiatedProtocol
	}
	f.Response.Header.Add("protocol", pStr)
}

func TestConnection(t *testing.T) {
	c := qt.New(t)
	helper := &testProxyHelper{
		server:    &http.Server{},
		proxyAddr: ":29087",
	}
	helper.init(c)
	helper.server.TLSConfig.NextProtos = []string{"h2"}
	httpEndpoint := helper.httpEndpoint
	httpsEndpoint := helper.httpsEndpoint
	testProxy := helper.testProxy
	testProxy.AddAddon(&testConnectionAddon{})
	getProxyClient := helper.getProxyClient
	defer helper.ln.Close()
	go func() { _ = helper.server.Serve(helper.ln) }()
	defer helper.tlsPlainLn.Close()
	go func() { _ = helper.server.ServeTLS(helper.tlsPlainLn, "", "") }()
	go func() { _ = testProxy.Start() }()
	time.Sleep(time.Millisecond * 10) // wait for test proxy startup

	t.Run("ClientConn state", func(t *testing.T) {
		t.Run("http", func(t *testing.T) {
			c := qt.New(t)
			client := getProxyClient()
			resp := testGetResponse(c, httpEndpoint, client)
			c.Assert(resp.Header.Get("tls"), qt.Equals, "0")
			c.Assert(resp.Header.Get("protocol"), qt.Equals, "null")
		})

		t.Run("https", func(t *testing.T) {
			c := qt.New(t)
			client := getProxyClient()
			resp := testGetResponse(c, httpsEndpoint, client)
			c.Assert(resp.Header.Get("tls"), qt.Equals, "1")
			c.Assert(resp.Header.Get("protocol"), qt.Equals, "null")
		})

		t.Run("h2", func(t *testing.T) {
			c := qt.New(t)
			client := &http.Client{
				Transport: &http.Transport{
					ForceAttemptHTTP2: true,
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
					Proxy: func(r *http.Request) (*url.URL, error) {
						return url.Parse("http://127.0.0.1" + helper.proxyAddr)
					},
				},
			}
			resp := testGetResponse(c, httpsEndpoint, client)
			c.Assert(resp.Header.Get("tls"), qt.Equals, "1")
			c.Assert(resp.Header.Get("protocol"), qt.Equals, "h2")
		})
	})
}

func TestConnectionOffUpstreamCert(t *testing.T) {
	c := qt.New(t)
	helper := &testProxyHelper{
		server:    &http.Server{},
		proxyAddr: ":29088",
	}
	helper.init(c)
	helper.server.TLSConfig.NextProtos = []string{"h2"}
	httpEndpoint := helper.httpEndpoint
	httpsEndpoint := helper.httpsEndpoint
	testProxy := helper.testProxy
	testProxy.AddAddon(NewUpstreamCertAddon(false))
	testProxy.AddAddon(&testConnectionAddon{})
	getProxyClient := helper.getProxyClient
	defer helper.ln.Close()
	go func() { _ = helper.server.Serve(helper.ln) }()
	defer helper.tlsPlainLn.Close()
	go func() { _ = helper.server.ServeTLS(helper.tlsPlainLn, "", "") }()
	go func() { _ = testProxy.Start() }()
	time.Sleep(time.Millisecond * 10) // wait for test proxy startup

	t.Run("ClientConn state", func(t *testing.T) {
		t.Run("http", func(t *testing.T) {
			c := qt.New(t)
			client := getProxyClient()
			resp := testGetResponse(c, httpEndpoint, client)
			c.Assert(resp.Header.Get("tls"), qt.Equals, "0")
			c.Assert(resp.Header.Get("protocol"), qt.Equals, "null")
		})

		t.Run("https", func(t *testing.T) {
			c := qt.New(t)
			client := getProxyClient()
			resp := testGetResponse(c, httpsEndpoint, client)
			c.Assert(resp.Header.Get("tls"), qt.Equals, "1")
			c.Assert(resp.Header.Get("protocol"), qt.Equals, "null")
		})

		t.Run("h2 not support", func(t *testing.T) {
			c := qt.New(t)
			client := &http.Client{
				Transport: &http.Transport{
					ForceAttemptHTTP2: true,
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
					Proxy: func(r *http.Request) (*url.URL, error) {
						return url.Parse("http://127.0.0.1" + helper.proxyAddr)
					},
				},
			}
			resp := testGetResponse(c, httpsEndpoint, client)
			c.Assert(resp.Header.Get("tls"), qt.Equals, "1")
			c.Assert(resp.Header.Get("protocol"), qt.Equals, "http/1.1")
		})
	})
}
