package helper

import (
	"io"
	"log/slog"
	"os"
	"sync"
)

// Wireshark HTTPS parsing configuration.
var tlsKeyLogWriter io.Writer
var tlsKeyLogOnce sync.Once

func GetTLSKeyLogWriter() io.Writer {
	tlsKeyLogOnce.Do(func() {
		logfile := os.Getenv("SSLKEYLOGFILE")
		if logfile == "" {
			return
		}

		writer, err := os.OpenFile(logfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			slog.Debug("getTlsKeyLogWriter OpenFile error", "error", err)
			return
		}

		tlsKeyLogWriter = writer
	})
	return tlsKeyLogWriter
}
