package proxy

import (
	"context"
	"net"
	"net/http"
)

// AttackerService defines the interface for MITM attack functionality.
type AttackerService interface {
	// Start begins serving HTTP connections through the attacker's listener.
	Start() error

	// Attack handles an HTTP/HTTPS request through the MITM proxy.
	Attack(res http.ResponseWriter, req *http.Request)

	// InitHTTPDialFn initializes the dial function for plain HTTP connections.
	InitHTTPDialFn(req *http.Request)

	// InitHTTPSDialFn initializes the dial function for HTTPS connections.
	InitHTTPSDialFn(req *http.Request)

	// HttpsDial establishes a connection to the upstream HTTPS server.
	HTTPSDial(ctx context.Context, req *http.Request) (net.Conn, error)

	// HttpsTLSDial performs a full MITM TLS handshake for HTTPS connections.
	HTTPSTLSDial(ctx context.Context, cconn, conn net.Conn)

	// HttpsLazyAttack handles HTTPS connections with lazy TLS handshake.
	HTTPSLazyAttack(ctx context.Context, cconn net.Conn, req *http.Request)

	// ServeHTTP implements http.Handler for the attacker.
	ServeHTTP(res http.ResponseWriter, req *http.Request)
}
