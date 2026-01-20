# Client Factory Pattern

## Overview

The `ClientFactory` interface provides a way to externally define and customize HTTP client creation in go-mitmproxy. This improves patching facilities and allows for flexible client configuration without modifying core code.

## Why Multiple HTTP Clients?

The proxy creates 4 different types of HTTP clients, each optimized for specific scenarios:

### 1. Main Client (Fallback/Separate)
- **When**: Request has been modified (different host/scheme) or `UseSeparateClient` is set
- **Characteristics**: Goes through upstream proxy, supports HTTP/2, creates new connections
- **Location**: Created in `attacker.New()`

### 2. HTTP/2 Client
- **When**: Negotiated protocol is "h2"
- **Characteristics**: Uses `http2.Transport`, reuses existing TLS connection
- **Location**: Created in `serveConn()` when handling HTTP/2 connections

### 3. Plain HTTP Client
- **When**: Non-TLS HTTP connections
- **Characteristics**: Disables HTTP/2, reuses existing plain connection
- **Location**: Created in `InitHTTPDialFn()` for plain HTTP

### 4. HTTPS Client
- **When**: HTTPS connections after TLS handshake
- **Characteristics**: Allows HTTP/2, reuses established TLS connection
- **Location**: Created in `serverTLSHandshake()` for HTTPS

## ClientFactory Interface

```go
type ClientFactory interface {
    CreateMainClient(upstreamManager *upstream.Manager, insecureSkipVerify bool) *http.Client
    CreateHTTP2Client(tlsConn *tls.Conn) *http.Client
    CreatePlainHTTPClient(conn net.Conn) *http.Client
    CreateHTTPSClient(tlsConn *tls.Conn) *http.Client
}
```

## Usage

### Default Behavior

If you don't provide a `ClientFactory`, the `DefaultClientFactory` is used automatically:

```go
atk, err := attacker.New(attacker.Args{
    CA:                 ca,
    UpstreamManager:    upstreamManager,
    AddonRegistry:      addonRegistry,
    StreamLargeBodies:  1024 * 1024 * 5,
    InsecureSkipVerify: false,
    // ClientFactory is nil, so DefaultClientFactory will be used
})
```

### Custom Client Factory

To use a custom client factory:

```go
// Create your custom factory
type MyClientFactory struct {
    *attacker.DefaultClientFactory
}

func (f *MyClientFactory) CreateMainClient(upstreamManager *upstream.Manager, insecureSkipVerify bool) *http.Client {
    // Custom implementation
    client := f.DefaultClientFactory.CreateMainClient(upstreamManager, insecureSkipVerify)
    // Add custom modifications
    return client
}

// Use it when creating the attacker
clientFactory := &MyClientFactory{
    DefaultClientFactory: attacker.NewDefaultClientFactory(),
}

atk, err := attacker.New(attacker.Args{
    CA:                 ca,
    UpstreamManager:    upstreamManager,
    AddonRegistry:      addonRegistry,
    StreamLargeBodies:  1024 * 1024 * 5,
    InsecureSkipVerify: false,
    ClientFactory:      clientFactory,  // Your custom factory
})
```

## Use Cases

1. **Custom Headers**: Add custom headers to all requests
2. **Logging**: Track when and which type of clients are created
3. **Custom Timeouts**: Modify transport settings like timeouts, connection pooling
4. **Testing**: Replace real HTTP clients with mock clients
5. **Metrics**: Add monitoring and tracing to client creation
6. **Protocol Control**: Force specific protocols or configurations

## Examples

See `examples/custom-client-factory/` for detailed examples including:
- Adding custom headers via transport wrapper
- Logging all client creations
- Forcing HTTP/2 for all connections
- Custom transport configurations

## Benefits

- **Flexibility**: Customize HTTP client behavior without modifying core code
- **Testing**: Easy to inject mock clients for testing
- **Monitoring**: Add logging, metrics, or tracing to client creation
- **Patching**: Modify client behavior for specific use cases
- **Backward Compatible**: Existing code continues to work without changes

## Implementation Details

The client factory is stored in the `Attacker` struct and used at 4 different points:

1. `New()` - Creates the main client
2. `serveConn()` - Creates HTTP/2 client when needed
3. `InitHTTPDialFn()` - Creates plain HTTP client
4. `serverTLSHandshake()` - Creates HTTPS client

All client creation now goes through the factory, making it easy to customize or replace the default behavior.

