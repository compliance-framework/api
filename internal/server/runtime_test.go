package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	runtime "github.com/compliance-framework/configuration-service/internal/models/runtime"
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
	getAllFn     func(id string, object interface{}) ([]interface{}, error)
	path         string
	params       map[string]string
	requestPath  string
	expectedCode int
}

func TestAssignJobs(t *testing.T) {
	tc := []TestCase{
		{
			name: "success",
			getAllFn: func(id string, _ interface{}) ([]interface{}, error) {
				return nil, nil
			},
			updateFn: func(id string, object interface{}) error {
				return nil
			},
			path:         "/runtime/jobs",
			requestPath:  "/runtime/jobs",
			expectedCode: http.StatusOK,
		},
		{
			name: "server-error",
			getAllFn: func(id string, _ interface{}) ([]interface{}, error) {
				return nil, fmt.Errorf("boom")
			},
			updateFn: func(id string, object interface{}) error {
				return nil
			},
			path:         "/runtime/jobs",
			requestPath:  "/runtime/jobs",
			expectedCode: http.StatusInternalServerError,
		},
		{
			name: "not found",
			getAllFn: func(id string, _ interface{}) ([]interface{}, error) {
				return nil, storeschema.NotFoundErr{}
			},
			updateFn: func(id string, object interface{}) error {
				return nil
			},
			path:         "/runtime/jobs",
			requestPath:  "/runtime/jobs",
			expectedCode: http.StatusNotFound,
		},
		{
			name: "success",
			getAllFn: func(id string, _ interface{}) ([]interface{}, error) {
				obs := []interface{}{}
				obj := &runtime.RuntimeConfigurationJob{
					RuntimeUuid: "123",
					Uuid:        "123",
				}
				obs = append(obs, obj)
				return obs, nil
			},
			updateFn: func(id string, object interface{}) error {
				return nil
			},
			path:         "/runtime/jobs",
			requestPath:  "/runtime/jobs",
			expectedCode: http.StatusOK,
		},
	}
	for idx, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			drv := FakeDriver{GetFn: tc[idx].getFn, DeleteFn: tc[idx].deleteFn, UpdateFn: tc[idx].updateFn, CreateFn: tc[idx].postFn, GetAllFn: tc[idx].getAllFn}
			s := &Server{Driver: drv}
			e := echo.New()
			req := httptest.NewRequest(http.MethodPut, tc[idx].requestPath, nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetPath(tc[idx].path)
			for k, v := range tc[idx].params {
				c.SetParamNames(k)
				c.SetParamValues(v)
			}
			err := s.assignJobs(c)
			assert.NoError(t, err)
			assert.Equal(t, tc[idx].expectedCode, rec.Result().StatusCode)
		})
	}
}

func TestUnassignJobs(t *testing.T) {
	tc := []TestCase{
		{
			name: "success",
			getAllFn: func(id string, _ interface{}) ([]interface{}, error) {
				return nil, nil
			},
			updateFn: func(id string, object interface{}) error {
				return nil
			},
			path:         "/runtime/jobs",
			requestPath:  "/runtime/jobs",
			expectedCode: http.StatusOK,
		},
		{
			name: "server-error",
			getAllFn: func(id string, _ interface{}) ([]interface{}, error) {
				return nil, fmt.Errorf("boom")
			},
			updateFn: func(id string, object interface{}) error {
				return nil
			},
			path:         "/runtime/jobs",
			requestPath:  "/runtime/jobs",
			expectedCode: http.StatusInternalServerError,
		},
		{
			name: "not found",
			getAllFn: func(id string, _ interface{}) ([]interface{}, error) {
				return nil, storeschema.NotFoundErr{}
			},
			updateFn: func(id string, object interface{}) error {
				return nil
			},
			path:         "/runtime/jobs",
			requestPath:  "/runtime/jobs",
			expectedCode: http.StatusNotFound,
		},
		{
			name: "success",
			getAllFn: func(id string, _ interface{}) ([]interface{}, error) {
				obs := []interface{}{}
				obj := &runtime.RuntimeConfigurationJob{
					RuntimeUuid: "123",
					Uuid:        "123",
				}
				obs = append(obs, obj)
				return obs, nil
			},
			updateFn: func(id string, object interface{}) error {
				return nil
			},
			path:         "/runtime/jobs",
			requestPath:  "/runtime/jobs",
			expectedCode: http.StatusOK,
		},
	}
	for idx, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			drv := FakeDriver{GetFn: tc[idx].getFn, DeleteFn: tc[idx].deleteFn, UpdateFn: tc[idx].updateFn, CreateFn: tc[idx].postFn, GetAllFn: tc[idx].getAllFn}
			s := &Server{Driver: drv}
			e := echo.New()
			req := httptest.NewRequest(http.MethodPut, tc[idx].requestPath, nil)
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetPath(tc[idx].path)
			for k, v := range tc[idx].params {
				c.SetParamNames(k)
				c.SetParamValues(v)
			}
			err := s.unassignJobs(c)
			assert.NoError(t, err)
			assert.Equal(t, tc[idx].expectedCode, rec.Result().StatusCode)
		})
	}
}
