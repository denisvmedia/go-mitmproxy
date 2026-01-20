package addons_test

import (
	"bytes"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy"
	"github.com/denisvmedia/go-mitmproxy/proxy/addons"
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/types"
)

type mockAddr struct {
	addr string
}

func (mockAddr) Network() string  { return "tcp" }
func (m mockAddr) String() string { return m.addr }

type mockConn struct {
	net.Conn
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (m *mockConn) RemoteAddr() net.Addr { return m.remoteAddr }
func (m *mockConn) LocalAddr() net.Addr  { return m.localAddr }
func (*mockConn) Close() error           { return nil }

func captureLog(fn func()) string {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldLogger)

	fn()
	return buf.String()
}

func TestLogAddonClientConnectedWritesLogWithRemoteAddr(t *testing.T) {
	c := qt.New(t)

	addon := &addons.LogAddon{}
	client := &proxy.ClientConn{
		Conn: &mockConn{remoteAddr: mockAddr{"192.168.1.50:54321"}},
	}

	output := captureLog(func() {
		addon.ClientConnected(client)
	})

	c.Assert(output, qt.Contains, "client connected")
	c.Assert(output, qt.Contains, "192.168.1.50:54321")
}

func TestLogAddonClientDisconnectedWritesLogWithRemoteAddr(t *testing.T) {
	c := qt.New(t)

	addon := &addons.LogAddon{}
	client := &proxy.ClientConn{
		Conn: &mockConn{remoteAddr: mockAddr{"10.0.0.100:12345"}},
	}

	output := captureLog(func() {
		addon.ClientDisconnected(client)
	})

	c.Assert(output, qt.Contains, "client disconnected")
	c.Assert(output, qt.Contains, "10.0.0.100:12345")
}

func TestLogAddonServerConnectedWritesLogWithAddresses(t *testing.T) {
	c := qt.New(t)

	addon := &addons.LogAddon{}
	connCtx := &proxy.ConnContext{
		ClientConn: &proxy.ClientConn{
			Conn: &mockConn{remoteAddr: mockAddr{"127.0.0.1:9999"}},
		},
		ServerConn: &proxy.ServerConn{
			Address: "api.example.com:443",
			Conn: &mockConn{
				remoteAddr: mockAddr{"93.184.216.34:443"},
				localAddr:  mockAddr{"192.168.1.10:55555"},
			},
		},
	}

	output := captureLog(func() {
		addon.ServerConnected(connCtx)
	})

	c.Assert(output, qt.Contains, "server connected")
	c.Assert(output, qt.Contains, "127.0.0.1:9999")
	c.Assert(output, qt.Contains, "api.example.com:443")
	c.Assert(output, qt.Contains, "93.184.216.34:443")
	c.Assert(output, qt.Contains, "192.168.1.10:55555")
}

func TestLogAddonServerDisconnectedWritesLogWithFlowCount(t *testing.T) {
	c := qt.New(t)

	addon := &addons.LogAddon{}
	connCtx := &proxy.ConnContext{
		ClientConn: &proxy.ClientConn{
			Conn: &mockConn{remoteAddr: mockAddr{"172.16.0.1:8080"}},
		},
		ServerConn: &proxy.ServerConn{
			Address: "cdn.example.org:80",
			Conn: &mockConn{
				remoteAddr: mockAddr{"151.101.1.195:80"},
				localAddr:  mockAddr{"172.16.0.1:44444"},
			},
		},
	}
	connCtx.FlowCount.Store(15)

	output := captureLog(func() {
		addon.ServerDisconnected(connCtx)
	})

	c.Assert(output, qt.Contains, "server disconnected")
	c.Assert(output, qt.Contains, "flowCount=15")
	c.Assert(output, qt.Contains, "172.16.0.1:8080")
	c.Assert(output, qt.Contains, "cdn.example.org:80")
}

func TestLogAddonRequestheadersWritesDebugLogWithMethodAndURL(t *testing.T) {
	c := qt.New(t)

	addon := &addons.LogAddon{}
	connCtx := &proxy.ConnContext{
		ClientConn: &proxy.ClientConn{
			Conn: &mockConn{remoteAddr: mockAddr{"192.168.100.50:33333"}},
		},
	}

	flow := types.NewFlow()
	flow.Request = &proxy.Request{
		Method: "POST",
		URL:    &url.URL{Scheme: "https", Host: "api.service.com", Path: "/v2/endpoint"},
		Header: make(map[string][]string),
	}
	flow.ConnContext = connCtx

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldLogger)

	addon.Requestheaders(flow)

	output := buf.String()
	c.Assert(output, qt.Contains, "request headers")
	c.Assert(output, qt.Contains, "POST")
	c.Assert(output, qt.Contains, "https://api.service.com/v2/endpoint")
	c.Assert(output, qt.Contains, "192.168.100.50:33333")
}

func TestLogAddonRequestheadersLogsCompletionWithStatusAndDuration(t *testing.T) {
	c := qt.New(t)

	addon := &addons.LogAddon{}
	connCtx := &proxy.ConnContext{
		ClientConn: &proxy.ClientConn{
			Conn: &mockConn{remoteAddr: mockAddr{"10.20.30.40:7777"}},
		},
	}

	flow := types.NewFlow()
	flow.Request = &proxy.Request{
		Method: "GET",
		URL:    &url.URL{Scheme: "http", Host: "download.example.net", Path: "/file.zip"},
		Header: make(map[string][]string),
	}
	flow.Response = &proxy.Response{
		StatusCode: 200,
		Header:     make(map[string][]string),
		Body:       []byte(strings.Repeat("x", 4096)),
	}
	flow.ConnContext = connCtx

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldLogger)

	done := make(chan struct{})
	go func() {
		addon.Requestheaders(flow)
		done <- struct{}{}
	}()

	<-done
	flow.Finish()
	time.Sleep(20 * time.Millisecond)

	output := buf.String()
	c.Assert(output, qt.Contains, "request completed")
	c.Assert(output, qt.Contains, "status=200")
	c.Assert(output, qt.Contains, "contentLength=4096")
	c.Assert(output, qt.Contains, "durationMs=")
	c.Assert(output, qt.Contains, "http://download.example.net/file.zip")
}

func TestLogAddonRequestheadersLogsZeroStatusWhenNoResponse(t *testing.T) {
	c := qt.New(t)

	addon := &addons.LogAddon{}
	connCtx := &proxy.ConnContext{
		ClientConn: &proxy.ClientConn{
			Conn: &mockConn{remoteAddr: mockAddr{"192.168.5.5:6666"}},
		},
	}

	flow := types.NewFlow()
	flow.Request = &proxy.Request{
		Method: "CONNECT",
		URL:    &url.URL{Scheme: "https", Host: "secure.example.com", Path: "/"},
		Header: make(map[string][]string),
	}
	flow.Response = nil
	flow.ConnContext = connCtx

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldLogger)

	addon.Requestheaders(flow)
	flow.Finish()
	time.Sleep(20 * time.Millisecond)

	output := buf.String()
	c.Assert(output, qt.Contains, "request completed")
	c.Assert(output, qt.Contains, "status=0")
	c.Assert(output, qt.Contains, "contentLength=0")
}

func TestLogAddonRequestheadersLogsZeroContentLengthWhenNoBody(t *testing.T) {
	c := qt.New(t)

	addon := &addons.LogAddon{}
	connCtx := &proxy.ConnContext{
		ClientConn: &proxy.ClientConn{
			Conn: &mockConn{remoteAddr: mockAddr{"172.31.0.99:1234"}},
		},
	}

	flow := types.NewFlow()
	flow.Request = &proxy.Request{
		Method: "DELETE",
		URL:    &url.URL{Scheme: "https", Host: "api.rest.com", Path: "/resource/123"},
		Header: make(map[string][]string),
	}
	flow.Response = &proxy.Response{
		StatusCode: 204,
		Header:     make(map[string][]string),
		Body:       nil,
	}
	flow.ConnContext = connCtx

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	oldLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(oldLogger)

	addon.Requestheaders(flow)
	flow.Finish()
	time.Sleep(20 * time.Millisecond)

	output := buf.String()
	c.Assert(output, qt.Contains, "request completed")
	c.Assert(output, qt.Contains, "status=204")
	c.Assert(output, qt.Contains, "contentLength=0")
}
