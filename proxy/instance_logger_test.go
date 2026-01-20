package proxy_test

import (
	"bytes"
	"log/slog"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/denisvmedia/go-mitmproxy/proxy"
)

func TestNewInstanceLoggerExtractsPortFromAddress(t *testing.T) {
	c := qt.New(t)

	logger := proxy.NewInstanceLogger(":8080", "")

	c.Assert(logger.Port, qt.Equals, "8080")
	c.Assert(logger.InstanceName, qt.Equals, "proxy-8080")
	c.Assert(logger.InstanceID, qt.Not(qt.Equals), "")
	c.Assert(len(logger.InstanceID), qt.Equals, 8)
}

func TestNewInstanceLoggerExtractsPortFromFullAddress(t *testing.T) {
	c := qt.New(t)

	logger := proxy.NewInstanceLogger("127.0.0.1:9090", "custom-proxy")

	c.Assert(logger.Port, qt.Equals, "9090")
	c.Assert(logger.InstanceName, qt.Equals, "custom-proxy")
}

func TestNewInstanceLoggerWithFileWritesLogsToFile(t *testing.T) {
	c := qt.New(t)

	dir := t.TempDir()
	logFile := dir + "/proxy.log"

	logger := proxy.NewInstanceLoggerWithFile(":8080", "test", logFile)

	c.Assert(logger.LogFilePath, qt.Equals, logFile)

	logger.GetLogger().Info("test message", "key", "value")

	data, err := os.ReadFile(logFile)
	c.Assert(err, qt.IsNil)
	c.Assert(string(data), qt.Contains, "test message")
	c.Assert(string(data), qt.Contains, "instance_id")
	c.Assert(string(data), qt.Contains, "instance_name")
	c.Assert(string(data), qt.Contains, "test")
}

func TestInstanceLoggerWithFieldsAddsAdditionalFields(t *testing.T) {
	c := qt.New(t)

	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(orig)

	logger := proxy.NewInstanceLogger(":8080", "test")
	withFields := logger.WithFields("request_id", "abc123")

	withFields.Info("request processed")

	output := buf.String()
	c.Assert(output, qt.Contains, "request_id=abc123")
	c.Assert(output, qt.Contains, "instance_name=test")
	c.Assert(output, qt.Contains, "port=8080")
}
func TestInstanceLoggerGetLoggerWritesInstanceMetadata(t *testing.T) {
	c := qt.New(t)

	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(orig)

	logger := proxy.NewInstanceLogger(":8080", "test")
	logger.GetLogger().Info("hello world")

	output := buf.String()
	c.Assert(output, qt.Contains, "hello world")
	c.Assert(output, qt.Contains, "instance_name=test")
	c.Assert(output, qt.Contains, "port=8080")
	c.Assert(output, qt.Contains, "instance_id=")
}
