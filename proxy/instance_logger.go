package proxy

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	uuid "github.com/satori/go.uuid"
)

type InstanceLogger struct {
	InstanceID   string
	InstanceName string
	Port         string
	LogFilePath  string
	logger       *slog.Logger
}

// NewInstanceLogger creates a logger with instance identification.
func NewInstanceLogger(addr, instanceName string) *InstanceLogger {
	return NewInstanceLoggerWithFile(addr, instanceName, "")
}

// NewInstanceLoggerWithFile creates a logger with instance identification and optional file output.
func NewInstanceLoggerWithFile(addr, instanceName, logFilePath string) *InstanceLogger {
	// Extract port from address
	port := addr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		port = addr[idx+1:]
	}

	// Generate instance ID if name not provided
	if instanceName == "" {
		instanceName = fmt.Sprintf("proxy-%s", port)
	}

	il := &InstanceLogger{
		InstanceID:   uuid.NewV4().String()[:8],
		InstanceName: instanceName,
		Port:         port,
		LogFilePath:  logFilePath,
	}

	// Configure file logger if path provided
	if logFilePath != "" {
		file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			slog.Error("Failed to open log file", "file", logFilePath, "error", err)
		}
		if err == nil {
			il.logger = slog.New(slog.NewJSONHandler(file, &slog.HandlerOptions{})).With(
				"instance_id", il.InstanceID,
				"instance_name", il.InstanceName,
				"port", il.Port,
			)
			return il
		}
	}

	// Default: use global slog logger with bound fields
	il.logger = slog.Default().With(
		"instance_id", il.InstanceID,
		"instance_name", il.InstanceName,
		"port", il.Port,
	)

	return il
}

// WithFields adds additional fields to the logger.
func (il *InstanceLogger) WithFields(args ...any) *slog.Logger {
	return il.logger.With(args...)
}

// GetLogger returns the underlying slog logger.
func (il *InstanceLogger) GetLogger() *slog.Logger {
	return il.logger
}
