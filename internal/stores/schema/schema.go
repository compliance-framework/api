package schema

import (
	"fmt"
	"sync"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

var mu sync.Mutex

type NotFoundErr struct {
}

func (e NotFoundErr) Error() string {
	return "object not found"
}

type Driver interface {
	Update(id string, object schema.BaseModel) error
	Create(id string, object schema.BaseModel) error
	Get(id string, object schema.BaseModel) error
	Delete(id string) error
}

var registry = make(map[string]Driver)

func Get(name string) (Driver, error) {
	mu.Lock()
	defer mu.Unlock()
	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("driver not found")
	}
	return p, nil
}

func GetAll() map[string]Driver {
	return registry
}

func MustRegister(name string, obj Driver) {
	mu.Lock()
	defer mu.Unlock()
	registry[name] = obj
}
