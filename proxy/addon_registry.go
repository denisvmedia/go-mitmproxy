package proxy

import "sync"

// AddonRegistry manages a collection of addons and provides thread-safe access to them.
type AddonRegistry struct {
	addons []Addon
	mu     sync.RWMutex
}

// NewAddonRegistry creates a new AddonRegistry instance.
func NewAddonRegistry() *AddonRegistry {
	return &AddonRegistry{
		addons: make([]Addon, 0),
	}
}

// Add adds a new addon to the manager.
// This method is thread-safe.
func (m *AddonRegistry) Add(addon Addon) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addons = append(m.addons, addon)
}

// Get returns a copy of the current addon list.
// This method is thread-safe.
func (m *AddonRegistry) Get() []Addon {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Return a copy to prevent external modification
	result := make([]Addon, len(m.addons))
	copy(result, m.addons)
	return result
}
