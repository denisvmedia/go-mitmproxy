package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"sync"

	"github.com/golang/groupcache/lru"
	"github.com/golang/groupcache/singleflight"

	"github.com/denisvmedia/go-mitmproxy/cert"
)

type TrustedCA struct {
	cache   *lru.Cache
	group   *singleflight.Group
	cacheMu sync.Mutex
}

func NewTrustedCA() cert.CA {
	ca := &TrustedCA{
		cache: lru.New(100),
		group: new(singleflight.Group),
	}
	return ca
}

func (*TrustedCA) GetRootCA() *x509.Certificate {
	panic("not supported")
}

func (ca *TrustedCA) GetCert(commonName string) (*tls.Certificate, error) {
	ca.cacheMu.Lock()
	if val, ok := ca.cache.Get(commonName); ok {
		ca.cacheMu.Unlock()
		slog.Debug("TrustedCA GetCert cache hit", "commonName", commonName)
		tlsCert, ok := val.(*tls.Certificate)
		if !ok {
			return nil, errors.New("cached value is not a tls.Certificate")
		}
		return tlsCert, nil
	}
	ca.cacheMu.Unlock()

	val, err := ca.group.Do(commonName, func() (any, error) {
		certificate, err := ca.loadCert(commonName)
		if err == nil {
			ca.cacheMu.Lock()
			ca.cache.Add(commonName, certificate)
			ca.cacheMu.Unlock()
		}
		return certificate, err
	})

	if err != nil {
		return nil, err
	}

	tlsCert, ok := val.(*tls.Certificate)
	if !ok {
		return nil, errors.New("loaded value is not a tls.Certificate")
	}
	return tlsCert, nil
}

func (*TrustedCA) loadCert(commonName string) (*tls.Certificate, error) {
	switch commonName {
	case "your-domain.xx.com":
		certificate, err := tls.LoadX509KeyPair("cert Path", "key Path")
		if err != nil {
			return nil, err
		}
		return &certificate, err
	case "your-domain2.xx.com":
		certificate, err := tls.X509KeyPair([]byte("cert Block"), []byte("key Block"))
		if err != nil {
			return nil, err
		}
		return &certificate, err
	default:
		return nil, errors.New("invalid certificate name")
	}
}
