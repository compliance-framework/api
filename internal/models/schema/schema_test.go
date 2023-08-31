package schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func reset() {
	registry = map[string]BaseModel{}
}

type Foo struct {
}

func (f *Foo) FromJSON([]byte) error {
	return nil
}
func (f *Foo) ToJSON() ([]byte, error) {
	return nil, nil
}
func (f *Foo) UUID() string {
	return ""
}
func (f *Foo) DeepCopy() BaseModel {
	return nil
}
func (f *Foo) Validate() error {
	return nil
}
func (f *Foo) Type() string {
	return "foo"
}
func TestGet(t *testing.T) {
	reset()
	MustRegister("foo", &Foo{})
	_, err := Get("foo")
	assert.Nil(t, err)
	_, err = Get("bar")
	assert.NotNil(t, err)
}

func TestGetAll(t *testing.T) {
	reset()
	MustRegister("foo1", &Foo{})
	MustRegister("bar", &Foo{})
	p := GetAll()
	assert.NotNil(t, p["foo1"])
	assert.NotNil(t, p["bar"])
	assert.Nil(t, p["foo"])
}
