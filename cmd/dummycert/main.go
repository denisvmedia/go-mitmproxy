package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

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
	log.SetLevel(log.InfoLevel)
	log.SetReportCaller(false)
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	config := loadConfig()
	if config.commonName == "" {
		log.Fatal("commonName required")
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
