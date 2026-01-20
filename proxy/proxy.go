package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/denisvmedia/go-mitmproxy/cert"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/addonregistry"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/attacker"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/conn"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/upstream"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/websocket"
	"github.com/denisvmedia/go-mitmproxy/version"
)

type Proxy struct {
	Version         string
	config          Config
	addonRegistry   *addonregistry.Registry
	upstreamManager *upstream.Manager

	entry           *entry
	attacker        *attacker.Attacker
	ca              cert.CA
	shouldIntercept func(req *http.Request) bool // req is received by proxy.server
	authProxy       func(res http.ResponseWriter, req *http.Request) (bool, error)
}

// NewProxy creates a new Proxy with the given configuration and CA.
// This function creates all internal dependencies with default settings.
func NewProxy(config Config, ca cert.CA) (*Proxy, error) {
	// Set default for StreamLargeBodies if not specified
	if config.StreamLargeBodies <= 0 {
		config.StreamLargeBodies = 1024 * 1024 * 5 // default: 5mb
	}

	addonRegistry := addonregistry.New()
	upstreamManager := upstream.NewManager(config.Upstream, config.InsecureSkipVerify)
	wsHandler := websocket.New()

	atk, err := attacker.New(attacker.Args{
		CA:                 ca,
		UpstreamManager:    upstreamManager,
		AddonRegistry:      addonRegistry,
		StreamLargeBodies:  config.StreamLargeBodies,
		InsecureSkipVerify: config.InsecureSkipVerify,
		WSHandler:          wsHandler,
		ClientFactory:      config.ClientFactory,
	})
	if err != nil {
		return nil, err
	}

	proxy := &Proxy{
		Version:         version.Version,
		config:          config,
		addonRegistry:   addonRegistry,
		upstreamManager: upstreamManager,
		attacker:        atk,
		ca:              ca,
	}

	proxy.entry = newEntry(proxy)

	return proxy, nil
}

func (p *Proxy) AddAddon(addon Addon) {
	p.addonRegistry.Add(addon)
}

func (p *Proxy) Start() error {
	go func() {
		if err := p.attacker.Start(); err != nil {
			slog.Error("attacker start failed", "error", err)
		}
	}()
	return p.entry.start()
}

func (p *Proxy) Close() error {
	return p.entry.close()
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	return p.entry.shutdown(ctx)
}

func (p *Proxy) GetCertificate() x509.Certificate {
	return *p.ca.GetRootCA()
}

func (p *Proxy) GetCertificateByCN(commonName string) (*tls.Certificate, error) {
	return p.ca.GetCert(commonName)
}

func (p *Proxy) SetShouldInterceptRule(rule func(req *http.Request) bool) {
	p.shouldIntercept = rule
}

func (p *Proxy) SetUpstreamProxy(fn func(req *http.Request) (*url.URL, error)) {
	p.upstreamManager.SetUpstreamProxy(fn)
}

func (p *Proxy) SetAuthProxy(fn func(res http.ResponseWriter, req *http.Request) (bool, error)) {
	p.authProxy = fn
}

// NotifyClientDisconnected implements conn.AddonNotifier interface.
func (p *Proxy) NotifyClientDisconnected(clientConn *conn.ClientConn) {
	for _, addon := range p.addonRegistry.Get() {
		addon.ClientDisconnected(clientConn)
	}
}

// NotifyServerDisconnected implements conn.AddonNotifier interface.
func (p *Proxy) NotifyServerDisconnected(connCtx *conn.Context) {
	for _, addon := range p.addonRegistry.Get() {
		addon.ServerDisconnected(connCtx)
	}
}
