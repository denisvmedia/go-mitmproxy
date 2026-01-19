package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/denisvmedia/go-mitmproxy/addon"
	"github.com/denisvmedia/go-mitmproxy/cert"
	"github.com/denisvmedia/go-mitmproxy/internal/helper"
	"github.com/denisvmedia/go-mitmproxy/proxy"
	"github.com/denisvmedia/go-mitmproxy/web"
)

type Config struct {
	version bool // show go-mitmproxy version

	Addr         string   // proxy listen addr
	WebAddr      string   // web interface listen addr
	SslInsecure  bool     // not verify upstream server SSL/TLS certificates.
	IgnoreHosts  []string // a list of ignore hosts
	AllowHosts   []string // a list of allow hosts
	CertPath     string   // path of generate cert files
	Debug        int      // debug mode: 1 - print debug log, 2 - show debug from
	Dump         string   // dump filename
	DumpLevel    int      // dump level: 0 - header, 1 - header + body
	Upstream     string   // upstream proxy
	UpstreamCert bool     // Connect to upstream server to look up certificate details. Default: True
	MapRemote    string   // map remote config filename
	MapLocal     string   // map local config filename
	LogFile      string   // log file path

	filename string // read config from the filename

	ProxyAuth string // Require proxy authentication

}

func main() {
	config := loadConfig()

	// Configure global slog logger.
	level := slog.LevelInfo
	addSource := false
	if config.Debug > 0 {
		level = slog.LevelDebug
		addSource = true // include file:line in debug mode only
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     level,
		AddSource: addSource,
	}))
	slog.SetDefault(logger)

	ca, err := cert.NewSelfSignCA(config.CertPath)
	if err != nil {
		slog.Error("failed to create CA", "error", err)
		os.Exit(1)
	}

	proxyConfig := &proxy.Config{
		Addr:              config.Addr,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       config.SslInsecure,
		Upstream:          config.Upstream,
	}

	p, err := proxy.NewProxyWithDefaults(proxyConfig, ca)
	if err != nil {
		slog.Error("failed to create proxy", "error", err)
		os.Exit(1)
	}

	if config.version {
		fmt.Println("go-mitmproxy: " + p.Version)
		os.Exit(0)
	}

	slog.Info("go-mitmproxy started", slog.String("version", p.Version))

	if len(config.IgnoreHosts) > 0 {
		p.SetShouldInterceptRule(func(req *http.Request) bool {
			return !helper.MatchHost(req.Host, config.IgnoreHosts)
		})
	}
	if len(config.AllowHosts) > 0 {
		p.SetShouldInterceptRule(func(req *http.Request) bool {
			return helper.MatchHost(req.Host, config.AllowHosts)
		})
	}

	if !config.UpstreamCert {
		p.AddAddon(proxy.NewUpstreamCertAddon(false))
		slog.Info("UpstreamCert config false")
	}

	if config.ProxyAuth != "" && strings.ToLower(config.ProxyAuth) != "any" {
		slog.Info("Enable entry authentication")
		auth := NewDefaultBasicAuth(config.ProxyAuth)
		p.SetAuthProxy(auth.EntryAuth)
	}

	if config.LogFile != "" {
		// Use instance logger with file output
		p.AddAddon(proxy.NewInstanceLogAddonWithFile(config.Addr, "", config.LogFile))
		slog.Info("Logging to file", slog.String("file", config.LogFile))
	} else {
		// Use default logger
		p.AddAddon(&proxy.LogAddon{})
	}
	p.AddAddon(web.NewWebAddon(config.WebAddr))

	if config.MapRemote != "" {
		mapRemote, err := addon.NewMapRemoteFromFile(config.MapRemote)
		if err != nil {
			slog.Warn("load map remote error", "error", err)
		} else {
			p.AddAddon(mapRemote)
		}
	}

	if config.MapLocal != "" {
		mapLocal, err := addon.NewMapLocalFromFile(config.MapLocal)
		if err != nil {
			slog.Warn("load map local error", "error", err)
		} else {
			p.AddAddon(mapLocal)
		}
	}

	if config.Dump != "" {
		dumper := addon.NewDumperWithFilename(config.Dump, config.DumpLevel)
		p.AddAddon(dumper)
	}

	if err := p.Start(); err != nil {
		slog.Error("proxy exited", "error", err)
		os.Exit(1)
	}
}
