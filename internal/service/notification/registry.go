package notification

import (
	"fmt"
	"sort"
	"sync"
)

type Registry struct {
	mu          sync.RWMutex
	definitions map[Kind]Definition
}

func NewRegistry(definitions ...Definition) (*Registry, error) {
	registry := &Registry{
		definitions: make(map[Kind]Definition, len(definitions)),
	}

	for i := range definitions {
		if err := registry.Register(definitions[i]); err != nil {
			return nil, err
		}
	}

	return registry, nil
}

func MustNewRegistry(definitions ...Definition) *Registry {
	registry, err := NewRegistry(definitions...)
	if err != nil {
		panic(err)
	}
	return registry
}

func (r *Registry) Register(definition Definition) error {
	if r == nil {
		return fmt.Errorf("%w", ErrRegistryNotConfigured)
	}

	normalized, err := definition.normalized()
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.definitions[normalized.Kind]; exists {
		return fmt.Errorf("%w: duplicate definition for kind %q", ErrInvalidRequest, normalized.Kind)
	}

	r.definitions[normalized.Kind] = cloneDefinition(normalized)
	return nil
}

func (r *Registry) Definition(kind Kind) (Definition, bool) {
	if r == nil {
		return Definition{}, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	definition, ok := r.definitions[kind]
	if !ok {
		return Definition{}, false
	}
	return cloneDefinition(definition), true
}

func (r *Registry) Kinds() []Kind {
	if r == nil {
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	kinds := make([]Kind, 0, len(r.definitions))
	for kind := range r.definitions {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool {
		return kinds[i] < kinds[j]
	})
	return kinds
}

func cloneDefinition(definition Definition) Definition {
	cloned := definition
	if len(definition.SupportedChannels) > 0 {
		cloned.SupportedChannels = append([]string(nil), definition.SupportedChannels...)
	}
	return cloned
}
