package schema

import (
	"context"
	"fmt"
	"sync"
)

var mu sync.Mutex

type NotFoundErr struct {
}

func (e NotFoundErr) Error() string {
	return "object not found"
}

type Driver interface {
	Update(ctx context.Context, collection string, id string, object interface{}) error
	Create(ctx context.Context, collection, id string, object interface{}) error
	CreateMany(ctx context.Context, collection string, objects map[string]interface{}) error
	Get(ctx context.Context, collection string, id string, object interface{}) error
	Delete(ctx context.Context, collection string, id string) error
	DeleteWhere(ctx context.Context, collection string, object interface{}, conditions map[string]interface{}) error
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
