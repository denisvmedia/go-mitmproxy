package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/denisvmedia/go-mitmproxy/cert"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/attacker"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/conn"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/upstream"
)

// Options contains settings for creating a CA.
// This is kept for backward compatibility with the NewCA function.
type Options struct {
	CaRootPath string
	NewCaFunc  func() (cert.CA, error) // Function to create CA
}

type Proxy struct {
	Version         string
	config          *Config
	addonRegistry   *AddonRegistry
	upstreamManager *upstream.Manager

	entry           *entry
	attacker        *attacker.Attacker
	ca              cert.CA
	shouldIntercept func(req *http.Request) bool // req is received by proxy.server
	authProxy       func(res http.ResponseWriter, req *http.Request) (bool, error)
}

// NewProxy creates a new Proxy with the given dependencies.
// All dependencies must be created and configured before calling this function.
// For a simpler API with default configuration, use NewProxyWithDefaults.
func NewProxy(config *Config, ca cert.CA, addonRegistry *AddonRegistry, upstreamManager *upstream.Manager, atk *attacker.Attacker) (*Proxy, error) {
	if config.StreamLargeBodies <= 0 {
		config.StreamLargeBodies = 1024 * 1024 * 5 // default: 5mb
	}

	proxy := &Proxy{
		Version:         "1.8.8",
		config:          config,
		addonRegistry:   addonRegistry,
		upstreamManager: upstreamManager,
		attacker:        atk,
		ca:              ca,
	}

	proxy.entry = newEntry(proxy)

	return proxy, nil
}

// NewProxyWithDefaults creates a new Proxy with default UpstreamManager and Attacker.
// This is a convenience function for simple use cases. For more control over
// UpstreamManager and Attacker configuration, create them separately and use NewProxy.
func NewProxyWithDefaults(config *Config, ca cert.CA) (*Proxy, error) {
	addonRegistry := NewAddonRegistry()
	upstreamManager := upstream.NewManager(config)

	atk, err := attacker.New(attacker.Args{
		CA:              ca,
		UpstreamManager: upstreamManager,
		AddonRegistry:   addonRegistry,
		Config:          config,
		WSHandler:       &wsHandler{},
	})
	if err != nil {
		return nil, err
	}

	return NewProxy(config, ca, addonRegistry, upstreamManager, atk)
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
