package server

import (
	"fmt"
	"strings"
	"testing"

	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
	echo "github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestRegisterRuntime(t *testing.T) {
	drv := FakeDriver{
		GetFn: func(id string, object interface{}) error {
			if strings.Contains(id, "err") {
				return fmt.Errorf("boom")
			}
			if strings.Contains(id, "123") {
				return nil
			}
			return storeschema.NotFoundErr{}
		},
	}
	s := &Server{Driver: drv}
	p := echo.New()
	err := s.RegisterRuntime(p)
	assert.Nil(t, err)
	expected := map[string]bool{
		"GET/runtime/configurations/:uuid":    false,
		"POST/runtime/configurations":         false,
		"PUT/runtime/configurations/:uuid":    false,
		"DELETE/runtime/configurations/:uuid": false,
	}
	for _, routes := range p.Routes() {
		t := fmt.Sprintf("%s%s", routes.Method, routes.Path)
		if _, ok := expected[t]; ok {
			expected[t] = true
		}
	}
	for k, v := range expected {
		assert.True(t, v, fmt.Sprintf("expected route %s not found", k))
	}
}

type TestCase struct {
	name         string
	getFn        func(id string, object interface{}) error
	updateFn     func(id string, object interface{}) error
	deleteFn     func(id string) error
	postFn       func(id string, object interface{}) error
	path         string
	params       map[string]string
	requestPath  string
	expectedCode int
}
