package proxy

// Config holds the proxy configuration settings.
type Config struct {
	Addr              string
	StreamLargeBodies int64
	SslInsecure       bool
	Upstream          string
}

// NewConfig creates a new Config with the given address.
// It sets default values for other fields.
func NewConfig(addr string) *Config {
	return &Config{
		Addr:              addr,
		StreamLargeBodies: 1024 * 1024 * 5, // default: 5mb
		SslInsecure:       false,
		Upstream:          "",
	}
}

// GetStreamLargeBodies returns the threshold for switching to streaming mode.
func (c *Config) GetStreamLargeBodies() int64 {
	return c.StreamLargeBodies
}

// GetSslInsecure returns whether to skip SSL certificate verification.
func (c *Config) GetSslInsecure() bool {
	return c.SslInsecure
}
