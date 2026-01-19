package main

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

type DefaultBasicAuth struct {
	Auth map[string]string
}

// Create a new BasicAuth instance from a user:password string.
func NewDefaultBasicAuth(auth string) *DefaultBasicAuth {
	basicAuth := &DefaultBasicAuth{
		Auth: make(map[string]string),
	}
	for _, e := range strings.Split(auth, "|") {
		n := strings.SplitN(e, ":", 2)
		if len(n) != 2 {
			slog.Error("invalid proxy auth format", slog.String("value", e))
			os.Exit(1) //revive:disable-line:deep-exit -- ok for cmd/*
		}
		basicAuth.Auth[n[0]] = n[1]
	}
	return basicAuth
}

// Validate proxy authentication.
func (usr *DefaultBasicAuth) EntryAuth(_ http.ResponseWriter, req *http.Request) (bool, error) {
	get := req.Header.Get("Proxy-Authorization")
	if get == "" {
		return false, errors.New("missing authentication")
	}
	ret := usr.parseRequestAuth(get)
	if !ret {
		return false, errors.New("invalid credentials")
	}
	return true, nil
}

// Parse and verify the Proxy-Authorization header.
func (usr *DefaultBasicAuth) parseRequestAuth(proxyAuth string) bool {
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
	if s, ok := usr.Auth[n[0]]; !ok || s != n[1] {
		return false
	}
	return true
}
