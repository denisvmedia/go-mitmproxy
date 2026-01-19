package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/denisvmedia/go-mitmproxy/cert"
)

// Generate fake/test server certificates

type Config struct {
	commonName string
}

func loadConfig() *Config {
	config := new(Config)
	flag.StringVar(&config.commonName, "commonName", "", "server commonName")
	flag.Parse() //revive:disable-line:deep-exit -- ok for cmd/*
	return config
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	config := loadConfig()
	if config.commonName == "" {
		slog.Error("commonName required")
		os.Exit(1)
	}

	caAPI, err := cert.NewSelfSignCA("")
	if err != nil {
		panic(err)
	}
	selfSignCA, ok := caAPI.(*cert.SelfSignCA)
	if !ok {
		panic("caAPI is not a *cert.SelfSignCA")
	}

	tlsCert, err := selfSignCA.DummyCert(config.commonName)
	if err != nil {
		panic(err)
	}

	fmt.Fprintf(os.Stdout, "%v-cert.pem\n", config.commonName)
	err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Certificate[0]})
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stdout, "\n%v-key.pem\n", config.commonName)

	keyBytes, err := x509.MarshalPKCS8PrivateKey(&selfSignCA.PrivateKey)
	if err != nil {
		panic(err)
	}
	err = pem.Encode(os.Stdout, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		panic(err)
	}
}
