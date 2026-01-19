package main

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/denisvmedia/go-mitmproxy/cert"
	"github.com/denisvmedia/go-mitmproxy/proxy"
)

type UserAuth struct {
	Username string
	Password string
}

// AuthEntrypAuth handles the proxy authentication for the entry point.
func (usr *UserAuth) AuthEntrypAuth(_ http.ResponseWriter, req *http.Request) (bool, error) {
	get := req.Header.Get("Proxy-Authorization")
	if get == "" {
		return false, errors.New("empty auth")
	}
	auth := usr.parseRequestAuth(get)
	if !auth {
		return false, errors.New("error auth")
	}
	return true, nil
}

// parseRequestAuth decodes and validates the Proxy-Authorization header.
func (usr *UserAuth) parseRequestAuth(proxyAuth string) bool {
	if !strings.HasPrefix(proxyAuth, "Basic ") {
		return false
	}
	encodedAuth := strings.TrimPrefix(proxyAuth, "Basic ")
	decodedAuth, err := base64.StdEncoding.DecodeString(encodedAuth)
	if err != nil {
		slog.Warn("Failed to decode Proxy-Authorization header", "error", err)
		return false
	}

	n := strings.SplitN(string(decodedAuth), ":", 2)
	if len(n) < 2 {
		return false
	}
	if usr.Username != n[0] || usr.Password != n[1] {
		return false
	}
	return true
}

func main() {
	ca, err := cert.NewSelfSignCA("")
	if err != nil {
		slog.Error("failed to create CA", "error", err)
		return
	}

	config := &proxy.Config{
		Addr:              ":9080",
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxyWithDefaults(config, ca)
	if err != nil {
		slog.Error("failed to create proxy", "error", err)
		return
	}
	auth := &UserAuth{
		Username: "proxy",
		Password: "proxy",
	}
	// Set up the authentication handler for the proxy.
	p.SetAuthProxy(auth.AuthEntrypAuth)
	p.AddAddon(&proxy.LogAddon{})

	if err := p.Start(); err != nil {
		slog.Error("proxy exited", "error", err)
	}
}
