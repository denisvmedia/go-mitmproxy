package helper

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
)

// Try to read Reader into buffer
// If the limit is not reached, successfully read into buffer
// Otherwise buffer returns nil, and a new Reader is returned with state before reading.
func ReaderToBuffer(r io.Reader, limit int64) ([]byte, io.Reader, error) {
	buf := bytes.NewBuffer(make([]byte, 0))
	lr := io.LimitReader(r, limit)

	_, err := io.Copy(buf, lr)
	if err != nil {
		return nil, nil, err
	}

	// Reached the limit
	if int64(buf.Len()) == limit {
		// Return a new Reader
		return nil, io.MultiReader(bytes.NewBuffer(buf.Bytes()), r), nil
	}

	// Return buffer
	return buf.Bytes(), nil, nil
}

func NewStructFromFile(filename string, v any) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return err
	}
	return nil
}

var portMap = map[string]string{
	"http":   "80",
	"https":  "443",
	"socks5": "1080",
}

// CanonicalAddr returns url.Host but always with a ":port" suffix.
func CanonicalAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = portMap[u.Scheme]
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// https://github.com/mitmproxy/mitmproxy/blob/main/mitmproxy/net/tls.py is_tls_record_magic
func IsTLS(buf []byte) bool {
	if buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x03 {
		return true
	}
	return false
}

type ResponseCheck struct {
	http.ResponseWriter
	Wrote bool
}

func NewResponseCheck(r http.ResponseWriter) http.ResponseWriter {
	return &ResponseCheck{
		ResponseWriter: r,
	}
}

func (r *ResponseCheck) WriteHeader(statusCode int) {
	r.Wrote = true
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *ResponseCheck) Write(b []byte) (int, error) {
	r.Wrote = true
	return r.ResponseWriter.Write(b)
}
