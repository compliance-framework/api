package schema

import (
	"fmt"
	"sync"

	_ "github.com/santhosh-tekuri/jsonschema/v5/httploader"
)

var mu sync.Mutex

type BaseModel interface {
	FromJSON([]byte) error
	ToJSON() ([]byte, error)
	UUID() string
	DeepCopy() BaseModel
	Validate() error
}

var registry = make(map[string]BaseModel)

func Get(name string) (BaseModel, error) {
	mu.Lock()
	defer mu.Unlock()
	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("model not found")
	}
	return p, nil
}

func GetAll() map[string]BaseModel {
	return registry
}

func MustRegister(name string, obj BaseModel) {
	mu.Lock()
	defer mu.Unlock()
	registry[name] = obj
}
