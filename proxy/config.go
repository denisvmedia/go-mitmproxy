package proxy

// Config holds the proxy configuration settings.
type Config struct {
	Addr               string
	StreamLargeBodies  int64
	InsecureSkipVerify bool
	Upstream           string
	ClientFactory      ClientFactory
}
