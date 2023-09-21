package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
	echo "github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestRegisterProcess(t *testing.T) {
	f := FakeDriver{}
	s := &Server{Driver: f}
	p := echo.New()
	err := s.RegisterProcess(p)
	assert.Nil(t, err)
	expected := map[string]bool{
		"GET/assessment-results/:uuid": false,
		"GET/assessment-results":       false,
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

func TestGetAssessmentResult(t *testing.T) {
	testCases := []struct {
		name         string
		getFn        func(id string, object interface{}) error
		path         string
		params       map[string]string
		requestPath  string
		expectedCode int
	}{
		{
			name: "get-assessment-result",
			getFn: func(id string, object interface{}) error {
				// Simulate a successful Get call here
				return nil
			},
			path:         "/assessment-results/:uuid",
			params:       map[string]string{"uuid": "1234"},
			requestPath:  "/assessment-results/1234",
			expectedCode: 200,
		},
		{
			name: "get-assessment-result-not-found",
			getFn: func(id string, object interface{}) error {
				return storeschema.NotFoundErr{}
			},
			path:         "/assessment-results/:uuid",
			params:       map[string]string{"uuid": "1236"},
			requestPath:  "/assessment-results/1234",
			expectedCode: 404,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := FakeDriver{}
			f.GetFn = tc.getFn

			s := &Server{Driver: f}

			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, tc.requestPath, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			p := c

			err := s.GetAssessmentResult(p)
			assert.Nil(t, err)
			assert.Equal(t, tc.expectedCode, p.Response().Status)
		})
	}
}

func TestGetAssessmentResults(t *testing.T) {
	testCases := []struct {
		name     string
		getAllFn func(id string, object interface{}) ([]interface{}, error)
		path     string

		requestPath  string
		expectedCode int
	}{
		{
			name: "get-assessment-results",
			getAllFn: func(id string, object interface{}) ([]interface{}, error) {
				// Simulate a successful Get call here
				return nil, nil
			},
			path: "/assessment-results",

			requestPath:  "/assessment-results",
			expectedCode: 200,
		},
		{
			name: "get-assessment-result-not-found",
			getAllFn: func(id string, object interface{}) ([]interface{}, error) {
				// Simulate a successful Get call here
				return nil, fmt.Errorf("boom")
			},
			path: "/assessment-results",

			requestPath:  "/assessment-results/1234",
			expectedCode: 500,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := FakeDriver{}
			f.GetAllFn = tc.getAllFn

			s := &Server{Driver: f}

			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, tc.requestPath, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			p := c

			err := s.GetAssessmentResults(p)
			assert.Nil(t, err)
			assert.Equal(t, tc.expectedCode, p.Response().Status)
		})
	}
}
