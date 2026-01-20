# Custom Client Factory Example

This example demonstrates how to use the `ClientFactory` interface to customize HTTP client creation in go-mitmproxy.

## Overview

The `ClientFactory` interface allows you to control how HTTP clients are created for different scenarios:

1. **Main Client** - Used for modified requests or when `UseSeparateClient` is set
2. **HTTP/2 Client** - Used for HTTP/2 connections
3. **Plain HTTP Client** - Used for non-TLS HTTP connections
4. **HTTPS Client** - Used for HTTPS connections after TLS handshake

## Use Cases

### 1. Adding Custom Headers

You can wrap the transport to add custom headers to all requests:

```go
type CustomClientFactory struct {
    *proxy.DefaultClientFactory
}

func (f *CustomClientFactory) CreateMainClient(upstreamManager proxy.UpstreamManager, insecureSkipVerify bool) *http.Client {
    // Create client with custom transport that adds headers
    return &http.Client{
        Transport: &customTransport{
            base: &http.Transport{
                Proxy:              upstreamManager.RealUpstreamProxy(),
                ForceAttemptHTTP2:  true,
                DisableCompression: true,
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: insecureSkipVerify,
                },
            },
        },
    }
}
```

### 2. Logging Client Creation

Track when and which type of clients are created:

```go
type LoggingClientFactory struct {
    *proxy.DefaultClientFactory
}

func (f *LoggingClientFactory) CreateHTTP2Client(tlsConn *tls.Conn) *http.Client {
    slog.Info("Creating HTTP/2 client")
    return f.DefaultClientFactory.CreateHTTP2Client(tlsConn)
}
```

### 3. Custom Transport Configuration

Modify transport settings like timeouts, connection pooling, etc:

```go
func (f *CustomClientFactory) CreateMainClient(upstreamManager proxy.UpstreamManager, insecureSkipVerify bool) *http.Client {
    transport := &http.Transport{
        Proxy:              upstreamManager.RealUpstreamProxy(),
        ForceAttemptHTTP2:  true,
        DisableCompression: true,
        MaxIdleConns:       100,
        IdleConnTimeout:    90 * time.Second,
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: insecureSkipVerify,
        },
    }
    return &http.Client{Transport: transport}
}
```

### 4. Testing and Mocking

Replace real HTTP clients with mock clients for testing:

```go
type MockClientFactory struct{}

func (f *MockClientFactory) CreateMainClient(upstreamManager proxy.UpstreamManager, insecureSkipVerify bool) *http.Client {
    return &http.Client{
        Transport: &mockTransport{},
    }
}
```

## How to Use

To use a custom client factory, you need to create the attacker manually:

```go
import (
    "github.com/denisvmedia/go-mitmproxy/proxy"
)

// Create your custom factory
clientFactory := NewCustomClientFactory()

// Note: To use a custom client factory with the standard proxy.NewProxy,
// you would need to create the attacker manually and pass it to a custom
// proxy constructor. For most use cases, you can extend proxy.NewProxy
// or create your own initialization function that accepts a ClientFactory.
```

## Benefits

- **Flexibility**: Customize HTTP client behavior without modifying core code
- **Testing**: Easy to inject mock clients for testing
- **Monitoring**: Add logging, metrics, or tracing to client creation
- **Patching**: Modify client behavior for specific use cases (e.g., custom certificates, proxies)
- **Protocol Control**: Force specific protocols or configurations

## Interface Definition

```go
type ClientFactory interface {
    CreateMainClient(upstreamManager *upstream.Manager, insecureSkipVerify bool) *http.Client
    CreateHTTP2Client(tlsConn *tls.Conn) *http.Client
    CreatePlainHTTPClient(conn net.Conn) *http.Client
    CreateHTTPSClient(tlsConn *tls.Conn) *http.Client
}
```

## Default Implementation

If you don't provide a `ClientFactory`, the `DefaultClientFactory` is used automatically, which provides the standard go-mitmproxy behavior.

