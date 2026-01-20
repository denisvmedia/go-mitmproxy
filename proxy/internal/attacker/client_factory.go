package attacker

import (
	"github.com/denisvmedia/go-mitmproxy/proxy/internal/types"
)

// NewDefaultClientFactory creates a new DefaultClientFactory.
// This is a convenience wrapper around types.NewDefaultClientFactory.
func NewDefaultClientFactory() types.ClientFactory {
	return types.NewDefaultClientFactory()
}

