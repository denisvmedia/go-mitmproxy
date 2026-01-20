package addons_test

import (
	"io"
	"net"
	"os"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy"
	"github.com/denisvmedia/go-mitmproxy/proxy/addons"
)

func TestNewInstanceLogAddonWithFileCreatesAddon(t *testing.T) {
	c := qt.New(t)

	dir := t.TempDir()
	logFile := dir + "/instance.log"

	addon := addons.NewInstanceLogAddonWithFile(":8080", "test-instance", logFile)

	c.Assert(addon, qt.IsNotNil)

	_, err := os.Stat(logFile)
	c.Assert(err, qt.IsNil)
}

func TestInstanceLogAddonSetLoggerChangesLogger(t *testing.T) {
	c := qt.New(t)

	dir := t.TempDir()
	oldFile := dir + "/addon-old.log"
	newFile := dir + "/addon-new.log"

	addon := addons.NewInstanceLogAddonWithFile(":8080", "old", oldFile)
	client := &proxy.ClientConn{
		Conn: &stubConn{
			localAddr:  stubAddr("127.0.0.1:5000"),
			remoteAddr: stubAddr("192.168.0.10:6000"),
		},
	}

	addon.ClientConnected(client)

	newLogger := proxy.NewInstanceLoggerWithFile(":9090", "new", newFile)
	addon.SetLogger(newLogger)
	addon.ClientDisconnected(client)

	oldData, err := os.ReadFile(oldFile)
	c.Assert(err, qt.IsNil)
	newData, err := os.ReadFile(newFile)
	c.Assert(err, qt.IsNil)

	c.Assert(string(oldData), qt.Contains, `"instance_name":"old"`)
	c.Assert(string(oldData), qt.Contains, `"event":"client_connected"`)
	c.Assert(string(newData), qt.Contains, `"instance_name":"new"`)
	c.Assert(string(newData), qt.Contains, `"event":"client_disconnected"`)
}

type stubAddr string

func (stubAddr) Network() string  { return "tcp" }
func (a stubAddr) String() string { return string(a) }

type stubConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (*stubConn) Read(b []byte) (int, error)      { return 0, io.EOF }
func (*stubConn) Write(b []byte) (int, error)     { return len(b), nil }
func (*stubConn) Close() error                    { return nil }
func (c *stubConn) LocalAddr() net.Addr           { return c.localAddr }
func (c *stubConn) RemoteAddr() net.Addr          { return c.remoteAddr }
func (*stubConn) SetDeadline(time.Time) error     { return nil }
func (*stubConn) SetReadDeadline(time.Time) error { return nil }
func (*stubConn) SetWriteDeadline(time.Time) error {
	return nil
}
