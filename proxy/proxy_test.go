package proxy_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/cert"
	"github.com/denisvmedia/go-mitmproxy/proxy"
	"github.com/denisvmedia/go-mitmproxy/proxy/addons"
)

func testSendRequest(c *qt.C, endpoint string, client *http.Client, bodyWant string) {
	c.Helper()
	req, err := http.NewRequest("GET", endpoint, nil)
	c.Assert(err, qt.IsNil)
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	c.Assert(err, qt.IsNil)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	c.Assert(err, qt.IsNil)
	c.Assert(string(body), qt.Equals, bodyWant)
}

type testProxyHelper struct {
	server    *http.Server
	proxyAddr string

	ln                     net.Listener
	tlsPlainLn             net.Listener
	tlsLn                  net.Listener
	httpEndpoint           string
	httpsEndpoint          string
	testOrderAddonInstance *testOrderAddon
	testProxy              *proxy.Proxy
	getProxyClient         func() *http.Client
}

func (hlp *testProxyHelper) init(c *qt.C) {
	c.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	hlp.server.Handler = mux

	// start http server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, qt.IsNil)
	hlp.ln = ln

	// start https server
	tlsPlainLn, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, qt.IsNil)
	hlp.tlsPlainLn = tlsPlainLn
	ca, err := cert.NewSelfSignCAMemory()
	c.Assert(err, qt.IsNil)
	tlsCert, err := ca.GetCert("localhost")
	c.Assert(err, qt.IsNil)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}
	hlp.server.TLSConfig = tlsConfig
	hlp.tlsLn = tls.NewListener(tlsPlainLn, tlsConfig)

	httpEndpoint := "http://" + ln.Addr().String() + "/"
	httpsPort := tlsPlainLn.Addr().(*net.TCPAddr).Port
	httpsEndpoint := "https://localhost:" + strconv.Itoa(httpsPort) + "/"
	hlp.httpEndpoint = httpEndpoint
	hlp.httpsEndpoint = httpsEndpoint

	// start proxy
	proxyCA, err := cert.NewSelfSignCA("")
	c.Assert(err, qt.IsNil)

	config := proxy.Config{
		Addr:               hlp.proxyAddr, // some random port
		InsecureSkipVerify: true,
	}

	var testProxy *proxy.Proxy
	testProxy, err = proxy.NewProxy(config, proxyCA)
	c.Assert(err, qt.IsNil)
	testProxy.AddAddon(&interceptAddon{})
	testOrderAddonInstance := &testOrderAddon{
		orders: make([]string, 0),
	}
	testProxy.AddAddon(testOrderAddonInstance)
	hlp.testOrderAddonInstance = testOrderAddonInstance
	hlp.testProxy = testProxy

	getProxyClient := func() *http.Client {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				Proxy: func(r *http.Request) (*url.URL, error) {
					return url.Parse("http://127.0.0.1" + hlp.proxyAddr)
				},
			},
		}
	}
	hlp.getProxyClient = getProxyClient
}

// addon for test intercept.
type interceptAddon struct {
	proxy.BaseAddon
}

func (*interceptAddon) Request(f *proxy.Flow) {
	// intercept request, should not send request to real endpoint
	if f.Request.URL.Path == "/intercept-request" {
		f.Response = &proxy.Response{
			StatusCode: 200,
			Body:       []byte("intercept-request"),
		}
	}
}

func (*interceptAddon) Response(f *proxy.Flow) {
	if f.Request.URL.Path == "/intercept-response" {
		f.Response = &proxy.Response{
			StatusCode: 200,
			Body:       []byte("intercept-response"),
		}
	}
}

// addon for test functions' execute order.
type testOrderAddon struct {
	proxy.BaseAddon
	orders []string
	mu     sync.Mutex
}

func (adn *testOrderAddon) reset() {
	adn.mu.Lock()
	defer adn.mu.Unlock()
	adn.orders = make([]string, 0)
}

func (adn *testOrderAddon) contains(c *qt.C, name string) {
	c.Helper()
	adn.mu.Lock()
	defer adn.mu.Unlock()
	for _, n := range adn.orders {
		if name == n {
			return
		}
	}
	c.Fatalf("expected contains %s, but not", name)
}

func (adn *testOrderAddon) before(c *qt.C, a, b string) {
	c.Helper()
	adn.mu.Lock()
	defer adn.mu.Unlock()
	aIndex, bIndex := -1, -1
	for i, n := range adn.orders {
		if a == n {
			aIndex = i
		} else if b == n {
			bIndex = i
		}
	}
	if aIndex == -1 {
		c.Fatalf("expected contains %s, but not", a)
	}
	if bIndex == -1 {
		c.Fatalf("expected contains %s, but not", b)
	}
	if aIndex > bIndex {
		c.Fatalf("expected %s executed before %s, but not", a, b)
	}
}

func (adn *testOrderAddon) ClientConnected(*proxy.ClientConn) {
	adn.mu.Lock()
	defer adn.mu.Unlock()
	adn.orders = append(adn.orders, "ClientConnected")
}
func (adn *testOrderAddon) ClientDisconnected(*proxy.ClientConn) {
	adn.mu.Lock()
	defer adn.mu.Unlock()
	adn.orders = append(adn.orders, "ClientDisconnected")
}
func (adn *testOrderAddon) ServerConnected(*proxy.ConnContext) {
	adn.mu.Lock()
	defer adn.mu.Unlock()
	adn.orders = append(adn.orders, "ServerConnected")
}
func (adn *testOrderAddon) ServerDisconnected(*proxy.ConnContext) {
	adn.mu.Lock()
	defer adn.mu.Unlock()
	adn.orders = append(adn.orders, "ServerDisconnected")
}
func (adn *testOrderAddon) TLSEstablishedServer(*proxy.ConnContext) {
	adn.mu.Lock()
	defer adn.mu.Unlock()
	adn.orders = append(adn.orders, "TLSEstablishedServer")
}
func (adn *testOrderAddon) Requestheaders(*proxy.Flow) {
	adn.mu.Lock()
	defer adn.mu.Unlock()
	adn.orders = append(adn.orders, "Requestheaders")
}
func (adn *testOrderAddon) Request(*proxy.Flow) {
	adn.mu.Lock()
	defer adn.mu.Unlock()
	adn.orders = append(adn.orders, "Request")
}
func (adn *testOrderAddon) Responseheaders(*proxy.Flow) {
	adn.mu.Lock()
	defer adn.mu.Unlock()
	adn.orders = append(adn.orders, "Responseheaders")
}
func (adn *testOrderAddon) Response(*proxy.Flow) {
	adn.mu.Lock()
	defer adn.mu.Unlock()
	adn.orders = append(adn.orders, "Response")
}
func (adn *testOrderAddon) StreamRequestModifier(f *proxy.Flow, in io.Reader) io.Reader {
	adn.mu.Lock()
	defer adn.mu.Unlock()
	adn.orders = append(adn.orders, "StreamRequestModifier")
	return in
}
func (adn *testOrderAddon) StreamResponseModifier(f *proxy.Flow, in io.Reader) io.Reader {
	adn.mu.Lock()
	defer adn.mu.Unlock()
	adn.orders = append(adn.orders, "StreamResponseModifier")
	return in
}

func TestProxy(t *testing.T) {
	c := qt.New(t)
	helper := &testProxyHelper{
		server:    &http.Server{},
		proxyAddr: ":29080",
	}
	helper.init(c)
	httpEndpoint := helper.httpEndpoint
	httpsEndpoint := helper.httpsEndpoint
	testOrderAddonInstance := helper.testOrderAddonInstance
	testProxy := helper.testProxy
	getProxyClient := helper.getProxyClient
	defer helper.ln.Close()
	go func() { _ = helper.server.Serve(helper.ln) }()
	defer helper.tlsPlainLn.Close()
	go func() { _ = helper.server.Serve(helper.tlsLn) }()
	go func() { _ = testProxy.Start() }()
	time.Sleep(time.Millisecond * 10) // wait for test proxy startup

	t.Run("test http server", func(t *testing.T) {
		c := qt.New(t)
		testSendRequest(c, httpEndpoint, nil, "ok")
	})

	t.Run("test https server", func(t *testing.T) {
		t.Run("should generate not trusted error", func(t *testing.T) {
			c := qt.New(t)
			_, err := http.Get(httpsEndpoint)
			c.Assert(err, qt.IsNotNil, qt.Commentf("should have error"))
			msg := err.Error()
			c.Assert(strings.Contains(msg, "certificate is not trusted") ||
				strings.Contains(msg, "certificate signed by unknown authority"), qt.IsTrue,
				qt.Commentf("should get not trusted error, but got %s", msg))
		})

		t.Run("should get ok when InsecureSkipVerify", func(t *testing.T) {
			c := qt.New(t)
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}
			testSendRequest(c, httpsEndpoint, client, "ok")
		})
	})

	t.Run("test proxy", func(t *testing.T) {
		proxyClient := getProxyClient()

		t.Run("can proxy http", func(t *testing.T) {
			c := qt.New(t)
			testSendRequest(c, httpEndpoint, proxyClient, "ok")
		})

		t.Run("can proxy https", func(t *testing.T) {
			c := qt.New(t)
			testSendRequest(c, httpsEndpoint, proxyClient, "ok")
		})

		t.Run("can intercept request", func(t *testing.T) {
			t.Run("http", func(t *testing.T) {
				c := qt.New(t)
				testSendRequest(c, httpEndpoint+"intercept-request", proxyClient, "intercept-request")
			})
			t.Run("https", func(t *testing.T) {
				c := qt.New(t)
				testSendRequest(c, httpsEndpoint+"intercept-request", proxyClient, "intercept-request")
			})
		})

		t.Run("can intercept request with wrong host", func(t *testing.T) {
			t.Run("http", func(t *testing.T) {
				c := qt.New(t)
				httpEndpoint := "http://some-wrong-host/"
				testSendRequest(c, httpEndpoint+"intercept-request", proxyClient, "intercept-request")
			})
			t.Run("https can't", func(t *testing.T) {
				c := qt.New(t)
				httpsEndpoint := "https://some-wrong-host/"
				_, err := http.Get(httpsEndpoint + "intercept-request")
				c.Assert(err, qt.IsNotNil, qt.Commentf("should have error"))
				c.Assert(strings.Contains(err.Error(), "dial tcp"), qt.IsTrue,
					qt.Commentf("should get dial error, but got %s", err.Error()))
			})
		})

		t.Run("can intercept response", func(t *testing.T) {
			t.Run("http", func(t *testing.T) {
				c := qt.New(t)
				testSendRequest(c, httpEndpoint+"intercept-response", proxyClient, "intercept-response")
			})
			t.Run("https", func(t *testing.T) {
				c := qt.New(t)
				testSendRequest(c, httpsEndpoint+"intercept-response", proxyClient, "intercept-response")
			})
		})
	})

	t.Run("test proxy when DisableKeepAlives", func(t *testing.T) {
		proxyClient := getProxyClient()
		proxyClient.Transport.(*http.Transport).DisableKeepAlives = true

		t.Run("http", func(t *testing.T) {
			c := qt.New(t)
			testSendRequest(c, httpEndpoint, proxyClient, "ok")
		})

		t.Run("https", func(t *testing.T) {
			c := qt.New(t)
			testSendRequest(c, httpsEndpoint, proxyClient, "ok")
		})
	})

	t.Run("should trigger disconnect functions when DisableKeepAlives", func(t *testing.T) {
		proxyClient := getProxyClient()
		proxyClient.Transport.(*http.Transport).DisableKeepAlives = true

		t.Run("http", func(t *testing.T) {
			c := qt.New(t)
			time.Sleep(time.Millisecond * 10)
			testOrderAddonInstance.reset()
			testSendRequest(c, httpEndpoint, proxyClient, "ok")
			time.Sleep(time.Millisecond * 10)
			testOrderAddonInstance.contains(c, "ClientDisconnected")
			testOrderAddonInstance.contains(c, "ServerDisconnected")
		})

		t.Run("https", func(t *testing.T) {
			c := qt.New(t)
			time.Sleep(time.Millisecond * 10)
			testOrderAddonInstance.reset()
			testSendRequest(c, httpsEndpoint, proxyClient, "ok")
			time.Sleep(time.Millisecond * 10)
			testOrderAddonInstance.contains(c, "ClientDisconnected")
			testOrderAddonInstance.contains(c, "ServerDisconnected")
		})
	})

	t.Run("should not have eof error when DisableKeepAlives", func(t *testing.T) {
		proxyClient := getProxyClient()
		proxyClient.Transport.(*http.Transport).DisableKeepAlives = true
		t.Run("http", func(t *testing.T) {
			c := qt.New(t)
			for i := 0; i < 10; i++ {
				testSendRequest(c, httpEndpoint, proxyClient, "ok")
			}
		})
		t.Run("https", func(t *testing.T) {
			c := qt.New(t)
			for i := 0; i < 10; i++ {
				testSendRequest(c, httpsEndpoint, proxyClient, "ok")
			}
		})
	})

	t.Run("should trigger disconnect functions when client side trigger off", func(t *testing.T) {
		proxyClient := getProxyClient()
		var clientConn net.Conn
		proxyClient.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			clientConn = c
			return c, err
		}

		t.Run("http", func(t *testing.T) {
			c := qt.New(t)
			time.Sleep(time.Millisecond * 10)
			testOrderAddonInstance.reset()
			testSendRequest(c, httpEndpoint, proxyClient, "ok")
			clientConn.Close()
			time.Sleep(time.Millisecond * 10)
			testOrderAddonInstance.contains(c, "ClientDisconnected")
			testOrderAddonInstance.contains(c, "ServerDisconnected")
			testOrderAddonInstance.before(c, "ClientDisconnected", "ServerDisconnected")
		})

		t.Run("https", func(t *testing.T) {
			c := qt.New(t)
			time.Sleep(time.Millisecond * 10)
			testOrderAddonInstance.reset()
			testSendRequest(c, httpsEndpoint, proxyClient, "ok")
			clientConn.Close()
			time.Sleep(time.Millisecond * 10)
			testOrderAddonInstance.contains(c, "ClientDisconnected")
			testOrderAddonInstance.contains(c, "ServerDisconnected")
			testOrderAddonInstance.before(c, "ClientDisconnected", "ServerDisconnected")
		})
	})
}

func TestProxyWhenServerNotKeepAlive(t *testing.T) {
	c := qt.New(t)
	server := &http.Server{}
	server.SetKeepAlivesEnabled(false)
	helper := &testProxyHelper{
		server:    server,
		proxyAddr: ":29081",
	}
	helper.init(c)
	httpEndpoint := helper.httpEndpoint
	httpsEndpoint := helper.httpsEndpoint
	testOrderAddonInstance := helper.testOrderAddonInstance
	testProxy := helper.testProxy
	getProxyClient := helper.getProxyClient
	defer helper.ln.Close()
	go func() { _ = helper.server.Serve(helper.ln) }()
	defer helper.tlsPlainLn.Close()
	go func() { _ = helper.server.Serve(helper.tlsLn) }()
	go func() { _ = testProxy.Start() }()
	time.Sleep(time.Millisecond * 10) // wait for test proxy startup

	t.Run("should not have eof error when server side DisableKeepAlives", func(t *testing.T) {
		proxyClient := getProxyClient()
		t.Run("http", func(t *testing.T) {
			c := qt.New(t)
			for i := 0; i < 10; i++ {
				testSendRequest(c, httpEndpoint, proxyClient, "ok")
			}
		})
		t.Run("https", func(t *testing.T) {
			c := qt.New(t)
			for i := 0; i < 10; i++ {
				testSendRequest(c, httpsEndpoint, proxyClient, "ok")
			}
		})
	})

	t.Run("should trigger disconnect functions when server DisableKeepAlives", func(t *testing.T) {
		proxyClient := getProxyClient()

		t.Run("http", func(t *testing.T) {
			c := qt.New(t)
			time.Sleep(time.Millisecond * 10)
			testOrderAddonInstance.reset()
			testSendRequest(c, httpEndpoint, proxyClient, "ok")
			time.Sleep(time.Millisecond * 10)
			testOrderAddonInstance.contains(c, "ClientDisconnected")
			testOrderAddonInstance.contains(c, "ServerDisconnected")
			testOrderAddonInstance.before(c, "ServerDisconnected", "ClientDisconnected")
		})

		t.Run("https", func(t *testing.T) {
			c := qt.New(t)
			time.Sleep(time.Millisecond * 10)
			testOrderAddonInstance.reset()
			testSendRequest(c, httpsEndpoint, proxyClient, "ok")
			time.Sleep(time.Millisecond * 10)
			testOrderAddonInstance.contains(c, "ClientDisconnected")
			testOrderAddonInstance.contains(c, "ServerDisconnected")
			testOrderAddonInstance.before(c, "ServerDisconnected", "ClientDisconnected")
		})
	})
}

func TestProxyWhenServerKeepAliveButCloseImmediately(t *testing.T) {
	c := qt.New(t)
	helper := &testProxyHelper{
		server: &http.Server{
			IdleTimeout: time.Millisecond * 10,
		},
		proxyAddr: ":29082",
	}
	helper.init(c)
	httpEndpoint := helper.httpEndpoint
	httpsEndpoint := helper.httpsEndpoint
	testOrderAddonInstance := helper.testOrderAddonInstance
	testProxy := helper.testProxy
	getProxyClient := helper.getProxyClient
	defer helper.ln.Close()
	go func() { _ = helper.server.Serve(helper.ln) }()
	defer helper.tlsPlainLn.Close()
	go func() { _ = helper.server.Serve(helper.tlsLn) }()
	go func() { _ = testProxy.Start() }()
	time.Sleep(time.Millisecond * 10) // wait for test proxy startup

	t.Run("should not have eof error when server close connection immediately", func(t *testing.T) {
		proxyClient := getProxyClient()
		t.Run("http", func(t *testing.T) {
			c := qt.New(t)
			for i := 0; i < 10; i++ {
				testSendRequest(c, httpEndpoint, proxyClient, "ok")
			}
		})
		t.Run("http wait server closed", func(t *testing.T) {
			c := qt.New(t)
			for i := 0; i < 10; i++ {
				testSendRequest(c, httpEndpoint, proxyClient, "ok")
				time.Sleep(time.Millisecond * 20)
			}
		})
		t.Run("https", func(t *testing.T) {
			c := qt.New(t)
			for i := 0; i < 10; i++ {
				testSendRequest(c, httpsEndpoint, proxyClient, "ok")
			}
		})
		t.Run("https wait server closed", func(t *testing.T) {
			c := qt.New(t)
			for i := 0; i < 10; i++ {
				testSendRequest(c, httpsEndpoint, proxyClient, "ok")
				time.Sleep(time.Millisecond * 20)
			}
		})
	})

	t.Run("should trigger disconnect functions when server close connection immediately", func(t *testing.T) {
		proxyClient := getProxyClient()

		t.Run("http", func(t *testing.T) {
			c := qt.New(t)
			time.Sleep(time.Millisecond * 10)
			testOrderAddonInstance.reset()
			testSendRequest(c, httpEndpoint, proxyClient, "ok")
			time.Sleep(time.Millisecond * 20)
			testOrderAddonInstance.contains(c, "ClientDisconnected")
			testOrderAddonInstance.contains(c, "ServerDisconnected")
			testOrderAddonInstance.before(c, "ServerDisconnected", "ClientDisconnected")
		})

		t.Run("https", func(t *testing.T) {
			c := qt.New(t)
			time.Sleep(time.Millisecond * 10)
			testOrderAddonInstance.reset()
			testSendRequest(c, httpsEndpoint, proxyClient, "ok")
			time.Sleep(time.Millisecond * 20)
			testOrderAddonInstance.contains(c, "ClientDisconnected")
			testOrderAddonInstance.contains(c, "ServerDisconnected")
			testOrderAddonInstance.before(c, "ServerDisconnected", "ClientDisconnected")
		})
	})
}

func TestProxyClose(t *testing.T) {
	c := qt.New(t)
	helper := &testProxyHelper{
		server:    &http.Server{},
		proxyAddr: ":29083",
	}
	helper.init(c)
	httpEndpoint := helper.httpEndpoint
	httpsEndpoint := helper.httpsEndpoint
	testProxy := helper.testProxy
	getProxyClient := helper.getProxyClient
	defer helper.ln.Close()
	go func() { _ = helper.server.Serve(helper.ln) }()
	defer helper.tlsPlainLn.Close()
	go func() { _ = helper.server.Serve(helper.tlsLn) }()

	errCh := make(chan error)
	go func() {
		err := testProxy.Start()
		errCh <- err
	}()

	time.Sleep(time.Millisecond * 10) // wait for test proxy startup

	proxyClient := getProxyClient()
	testSendRequest(c, httpEndpoint, proxyClient, "ok")
	testSendRequest(c, httpsEndpoint, proxyClient, "ok")

	err := testProxy.Close()
	c.Assert(err, qt.IsNil, qt.Commentf("close got error %v", err))

	select {
	case err := <-errCh:
		c.Assert(errors.Is(err, http.ErrServerClosed), qt.IsTrue,
			qt.Commentf("expected ErrServerClosed error, but got %v", err))
	case <-time.After(time.Millisecond * 10):
		c.Fatal("close timeout")
	}
}

func TestProxyShutdown(t *testing.T) {
	c := qt.New(t)
	helper := &testProxyHelper{
		server:    &http.Server{},
		proxyAddr: ":29084",
	}
	helper.init(c)
	httpEndpoint := helper.httpEndpoint
	httpsEndpoint := helper.httpsEndpoint
	testProxy := helper.testProxy
	getProxyClient := helper.getProxyClient
	defer helper.ln.Close()
	go func() { _ = helper.server.Serve(helper.ln) }()
	defer helper.tlsPlainLn.Close()
	go func() { _ = helper.server.Serve(helper.tlsLn) }()

	errCh := make(chan error)
	go func() {
		err := testProxy.Start()
		errCh <- err
	}()

	time.Sleep(time.Millisecond * 10) // wait for test proxy startup

	proxyClient := getProxyClient()
	testSendRequest(c, httpEndpoint, proxyClient, "ok")
	testSendRequest(c, httpsEndpoint, proxyClient, "ok")

	err := testProxy.Shutdown(context.Background())
	c.Assert(err, qt.IsNil, qt.Commentf("shutdown got error %v", err))

	select {
	case err := <-errCh:
		c.Assert(errors.Is(err, http.ErrServerClosed), qt.IsTrue,
			qt.Commentf("expected ErrServerClosed error, but got %v", err))
	case <-time.After(time.Millisecond * 10):
		c.Fatal("shutdown timeout")
	}
}

func TestOnUpstreamCert(t *testing.T) {
	c := qt.New(t)
	helper := &testProxyHelper{
		server:    &http.Server{},
		proxyAddr: ":29085",
	}
	helper.init(c)
	httpEndpoint := helper.httpEndpoint
	httpsEndpoint := helper.httpsEndpoint
	testOrderAddonInstance := helper.testOrderAddonInstance
	testProxy := helper.testProxy
	getProxyClient := helper.getProxyClient
	defer helper.ln.Close()
	go func() { _ = helper.server.Serve(helper.ln) }()
	defer helper.tlsPlainLn.Close()
	go func() { _ = helper.server.Serve(helper.tlsLn) }()
	go func() { _ = testProxy.Start() }()
	time.Sleep(time.Millisecond * 10) // wait for test proxy startup

	proxyClient := getProxyClient()

	t.Run("http", func(t *testing.T) {
		c := qt.New(t)
		time.Sleep(time.Millisecond * 10)
		testOrderAddonInstance.reset()
		testSendRequest(c, httpEndpoint, proxyClient, "ok")
		time.Sleep(time.Millisecond * 10)
		testOrderAddonInstance.before(c, "Requestheaders", "ServerConnected")
	})

	t.Run("https", func(t *testing.T) {
		c := qt.New(t)
		time.Sleep(time.Millisecond * 10)
		testOrderAddonInstance.reset()
		testSendRequest(c, httpsEndpoint, proxyClient, "ok")
		time.Sleep(time.Millisecond * 10)
		testOrderAddonInstance.before(c, "ServerConnected", "Requestheaders")
		testOrderAddonInstance.contains(c, "TLSEstablishedServer")
	})
}

func TestOffUpstreamCert(t *testing.T) {
	c := qt.New(t)
	helper := &testProxyHelper{
		server:    &http.Server{},
		proxyAddr: ":29086",
	}
	helper.init(c)
	httpEndpoint := helper.httpEndpoint
	httpsEndpoint := helper.httpsEndpoint
	testOrderAddonInstance := helper.testOrderAddonInstance
	testProxy := helper.testProxy
	testProxy.AddAddon(addons.NewUpstreamCertAddon(false))
	getProxyClient := helper.getProxyClient
	defer helper.ln.Close()
	go func() { _ = helper.server.Serve(helper.ln) }()
	defer helper.tlsPlainLn.Close()
	go func() { _ = helper.server.Serve(helper.tlsLn) }()
	go func() { _ = testProxy.Start() }()
	time.Sleep(time.Millisecond * 10) // wait for test proxy startup

	proxyClient := getProxyClient()

	t.Run("http", func(t *testing.T) {
		c := qt.New(t)
		time.Sleep(time.Millisecond * 10)
		testOrderAddonInstance.reset()
		testSendRequest(c, httpEndpoint, proxyClient, "ok")
		time.Sleep(time.Millisecond * 10)
		testOrderAddonInstance.before(c, "Requestheaders", "ServerConnected")
	})

	t.Run("https", func(t *testing.T) {
		c := qt.New(t)
		time.Sleep(time.Millisecond * 10)
		testOrderAddonInstance.reset()
		testSendRequest(c, httpsEndpoint, proxyClient, "ok")
		time.Sleep(time.Millisecond * 10)
		testOrderAddonInstance.before(c, "Requestheaders", "ServerConnected")
		testOrderAddonInstance.contains(c, "TLSEstablishedServer")
	})
}
