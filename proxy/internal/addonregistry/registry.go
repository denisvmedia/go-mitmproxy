package addonregistry

import (
	"sync"

	"github.com/denisvmedia/go-mitmproxy/proxy/internal/types"
)

// Registry manages a collection of addons and provides thread-safe access to them.
type Registry struct {
	addons []types.Addon
	mu     sync.RWMutex
}

// New creates a new Registry instance.
func New() *Registry {
	return &Registry{
		addons: make([]types.Addon, 0),
	}
}

// Add adds a new addon to the registry.
// This method is thread-safe.
func (r *Registry) Add(addon types.Addon) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addons = append(r.addons, addon)
}

// Get returns a copy of the current addon list.
// This method is thread-safe.
func (r *Registry) Get() []types.Addon {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// Return a copy to prevent external modification
	result := make([]types.Addon, len(r.addons))
	copy(result, r.addons)
	return result
}

