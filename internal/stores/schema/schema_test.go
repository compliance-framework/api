package schema

import (
	"testing"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
	"github.com/stretchr/testify/assert"
)

func reset() {
	registry = map[string]Driver{}
}

type FooDriver struct {
}

func (d *FooDriver) Update(id string, object schema.BaseModel) error {
	// Implement the Update method for the FooDriver
	return nil
}

func (d *FooDriver) Create(id string, object schema.BaseModel) error {
	// Implement the Create method for the FooDriver
	return nil
}

func (d *FooDriver) Get(id string, object schema.BaseModel) error {
	// Implement the Get method for the FooDriver
	return nil
}

func (d *FooDriver) Delete(id string) error {
	// Implement the Delete method for the FooDriver
	return nil
}
func TestGet(t *testing.T) {
	reset()
	MustRegister("foo", &FooDriver{})
	_, err := Get("foo")
	assert.Nil(t, err)
	_, err = Get("bar")
	assert.NotNil(t, err)
}

func TestGetAll(t *testing.T) {
	reset()
	MustRegister("foo1", &FooDriver{})
	MustRegister("bar", &FooDriver{})
	p := GetAll()
	assert.NotNil(t, p["foo1"])
	assert.NotNil(t, p["bar"])
	assert.Nil(t, p["foo"])
}
