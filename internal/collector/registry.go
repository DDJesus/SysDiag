package collector

import "sync"

// Registry maintains the catalog of available diagnostic probes.
type Registry struct {
	mu     sync.RWMutex
	probes map[string]Probe
}

// NewRegistry instantiates an empty probe registry.
func NewRegistry() *Registry {
	return &Registry{
		probes: make(map[string]Probe),
	}
}

// Register adds a probe to the registry.
func (r *Registry) Register(p Probe) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.probes[p.ID()] = p
}

// Get retrieves a probe by ID.
func (r *Registry) Get(id string) (Probe, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.probes[id]
	return p, ok
}

// All returns a slice of all registered probes.
func (r *Registry) All() []Probe {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Probe, 0, len(r.probes))
	for _, p := range r.probes {
		result = append(result, p)
	}
	return result
}

// ForProfile returns probes matching the specified execution profile.
func (r *Registry) ForProfile(profile string) []Probe {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var matches []Probe
	for _, p := range r.probes {
		for _, sp := range p.SupportedProfiles() {
			if sp == profile || sp == "all" {
				matches = append(matches, p)
				break
			}
		}
	}
	return matches
}

// ForCategories returns probes matching any of the specified categories.
func (r *Registry) ForCategories(categories ...ProbeCategory) []Probe {
	r.mu.RLock()
	defer r.mu.RUnlock()
	catMap := make(map[ProbeCategory]bool)
	for _, c := range categories {
		catMap[c] = true
	}

	var matches []Probe
	for _, p := range r.probes {
		if catMap[p.Category()] {
			matches = append(matches, p)
		}
	}
	return matches
}
