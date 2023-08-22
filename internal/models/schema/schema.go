package schema

import (
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
	_ "github.com/santhosh-tekuri/jsonschema/v5/httploader"
)

var mu sync.Mutex

type BaseModel interface {
	SchemaURL() string
}

type Object struct {
	Model BaseModel
}

func (o *Object) Validate() error {
	sch, err := jsonschema.Compile(o.Model.SchemaURL())
	if err != nil {
		return fmt.Errorf("could not load jsonschema:%w", err)
	}
	return sch.Validate(o.Model)
}

var Registry = make(map[string]Object)

func MustRegister(name string, obj Object) {
	err := obj.Validate()
	if err != nil {
		panic(err)
	}
	mu.Lock()
	defer mu.Unlock()
	Registry[name] = obj
}
