package schema

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func reset() {
	registry = map[string]Driver{}
}

type FooDriver struct {
}

func (d *FooDriver) Update(ctx context.Context, collection, id string, object interface{}) error {
	// Implement the Update method for the FooDriver
	return nil
}

func (d *FooDriver) Create(ctx context.Context, collection, id string, object interface{}) error {
	// Implement the Create method for the FooDriver
	return nil
}

func (d *FooDriver) Get(ctx context.Context, collection, id string, object interface{}) error {
	// Implement the Get method for the FooDriver
	return nil
}

func (d *FooDriver) Delete(ctx context.Context, collection, id string) error {
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
