package helper

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// GetProxyConn connect proxy
// ref: http/transport.go dialConn func
func GetProxyConn(ctx context.Context, proxyURL *url.URL, address string, sslInsecure bool) (net.Conn, error) {
	var conn net.Conn
	if proxyURL.Scheme == "socks5" {
		// Check for socks5 authentication info
		proxyAuth := &proxy.Auth{}
		if proxyURL.User != nil {
			user := proxyURL.User.Username()
			pass, _ := proxyURL.User.Password()
			proxyAuth.User = user
			proxyAuth.Password = pass
		}
		dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, proxyAuth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		dc, ok := dialer.(interface {
			DialContext(ctx context.Context, network, addr string) (net.Conn, error)
		})
		if !ok {
			return nil, errors.New("SOCKS5 dialer does not support DialContext")
		}
		conn, err = dc.DialContext(ctx, "tcp", address)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return conn, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, err
	}
	// If the proxy URL is HTTPS, perform TLS handshake
	if proxyURL.Scheme == "https" {
		tlsConfig := &tls.Config{
			ServerName:         proxyURL.Hostname(), // Set server name for TLS handshake
			InsecureSkipVerify: sslInsecure,
			// Additional TLS configurations can be added here
		}
		// Wrap the original connection as a TLS connection
		tlsConn := tls.Client(conn, tlsConfig)
		// Perform TLS handshake
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close() // Handshake failed, close connection
			return nil, err
		}
		conn = tlsConn // Replace the original connection with the TLS connection
	}
	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: http.Header{},
	}
	if proxyURL.User != nil {
		connectReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(proxyURL.User.String())))
	}
	connectCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()
	didReadResponse := make(chan struct{}) // closed after CONNECT write+read is done or fails
	var resp *http.Response
	// Write the CONNECT request & read the response.
	go func() {
		defer close(didReadResponse)
		err = connectReq.Write(conn)
		if err != nil {
			return
		}
		// Okay to use and discard buffered reader here, because
		// TLS server will not speak until spoken to.
		br := bufio.NewReader(conn)
		resp, err = http.ReadResponse(br, connectReq)
	}()
	select {
	case <-connectCtx.Done():
		conn.Close()
		<-didReadResponse
		return nil, connectCtx.Err()
	case <-didReadResponse:
		// resp or err now set
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		_, text, ok := strings.Cut(resp.Status, " ")
		conn.Close()
		if !ok {
			return nil, errors.New("unknown status code")
		}
		return nil, errors.New(text)
	}
	return conn, nil
}
