package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"

	"github.com/denisvmedia/go-mitmproxy/cert"
	"github.com/denisvmedia/go-mitmproxy/internal/helper"
)

type Options struct {
	Debug             int
	Addr              string
	StreamLargeBodies int64 // When request or response body is larger than this number of bytes, switch to stream mode
	SslInsecure       bool
	CaRootPath        string
	NewCaFunc         func() (cert.CA, error) // Function to create CA
	Upstream          string
	LogFilePath       string // Path to write logs to file
}

type Proxy struct {
	Opts    *Options
	Version string
	Addons  []Addon

	entry           *entry
	attacker        *attacker
	shouldIntercept func(req *http.Request) bool              // req is received by proxy.server
	upstreamProxy   func(req *http.Request) (*url.URL, error) // req is received by proxy.server, not client request
	authProxy       func(res http.ResponseWriter, req *http.Request) (bool, error)
}

// proxy.server req context key.
var proxyReqCtxKey = new(struct{})

func NewProxy(opts *Options) (*Proxy, error) {
	if opts.StreamLargeBodies <= 0 {
		opts.StreamLargeBodies = 1024 * 1024 * 5 // default: 5mb
	}

	proxy := &Proxy{
		Opts:    opts,
		Version: "1.8.8",
		Addons:  make([]Addon, 0),
	}

	proxy.entry = newEntry(proxy)

	attacker, err := newAttacker(proxy)
	if err != nil {
		return nil, err
	}
	proxy.attacker = attacker

	return proxy, nil
}

func (prx *Proxy) AddAddon(addon Addon) {
	prx.Addons = append(prx.Addons, addon)
}

func (prx *Proxy) Start() error {
	go func() {
		if err := prx.attacker.start(); err != nil {
			log.Error(err)
		}
	}()
	return prx.entry.start()
}

func (prx *Proxy) Close() error {
	return prx.entry.close()
}

func (prx *Proxy) Shutdown(ctx context.Context) error {
	return prx.entry.shutdown(ctx)
}

func (prx *Proxy) GetCertificate() x509.Certificate {
	return *prx.attacker.ca.GetRootCA()
}

func (prx *Proxy) GetCertificateByCN(commonName string) (*tls.Certificate, error) {
	return prx.attacker.ca.GetCert(commonName)
}

func (prx *Proxy) SetShouldInterceptRule(rule func(req *http.Request) bool) {
	prx.shouldIntercept = rule
}

func (prx *Proxy) SetUpstreamProxy(fn func(req *http.Request) (*url.URL, error)) {
	prx.upstreamProxy = fn
}

func (prx *Proxy) realUpstreamProxy() func(*http.Request) (*url.URL, error) {
	return func(cReq *http.Request) (*url.URL, error) {
		req, ok := cReq.Context().Value(proxyReqCtxKey).(*http.Request)
		if !ok {
			panic("failed to get original request from context")
		}
		return prx.getUpstreamProxyURL(req)
	}
}

func (prx *Proxy) getUpstreamProxyURL(req *http.Request) (*url.URL, error) {
	if prx.upstreamProxy != nil {
		return prx.upstreamProxy(req)
	}
	if len(prx.Opts.Upstream) > 0 {
		return url.Parse(prx.Opts.Upstream)
	}
	cReq := &http.Request{URL: &url.URL{Scheme: "https", Host: req.Host}}
	return http.ProxyFromEnvironment(cReq)
}

func (prx *Proxy) getUpstreamConn(ctx context.Context, req *http.Request) (net.Conn, error) {
	proxyURL, err := prx.getUpstreamProxyURL(req)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	address := helper.CanonicalAddr(req.URL)
	if proxyURL != nil {
		conn, err = helper.GetProxyConn(ctx, proxyURL, address, prx.Opts.SslInsecure)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	return conn, err
}

func (prx *Proxy) SetAuthProxy(fn func(res http.ResponseWriter, req *http.Request) (bool, error)) {
	prx.authProxy = fn
}
