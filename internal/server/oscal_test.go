package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

type Foo struct {
	Foo  string `json:"foo"`
	Bar  string `json:"bar"`
	Uuid string `json:"uuid" query:"uuid"`
}

func (f *Foo) FromJSON(b []byte) error {
	return json.Unmarshal(b, f)
}
func (f *Foo) ToJSON() ([]byte, error) {
	return json.Marshal(f)
}
func (f *Foo) UUID() string {
	return ""
}
func (f *Foo) DeepCopy() schema.BaseModel {
	d := &Foo{}
	p, err := f.ToJSON()
	if err != nil {
		panic(err)
	}
	err = d.FromJSON(p)
	if err != nil {
		panic(err)
	}
	return d
}
func (f *Foo) Validate() error {
	return nil
}
func (f *Foo) Type() string {
	return "foo"
}

type FakeDriver struct {
	UpdateFn     func(id string, object interface{}) error
	CreateFn     func(id string, object interface{}) error
	CreateManyFn func(objects map[string]interface{}) error
	GetFn        func(id string, object interface{}) error
	DeleteFn     func(id string) error
}

func (f FakeDriver) Update(_ context.Context, _, id string, object interface{}) error {
	return f.UpdateFn(id, object)
}
func (f FakeDriver) Create(_ context.Context, _, id string, object interface{}) error {
	return f.CreateFn(id, object)
}

func (f FakeDriver) Get(_ context.Context, _, id string, object interface{}) error {
	return f.GetFn(id, object)
}
func (f FakeDriver) Delete(_ context.Context, _, id string) error {
	return f.DeleteFn(id)
}

func (f FakeDriver) CreateMany(_ context.Context, _ string, objects map[string]interface{}) error {
	return f.CreateManyFn(objects)
}

func (f FakeDriver) DeleteWhere(_ context.Context, _ string, _ interface{}, objects map[string]interface{}) error {
	return nil
}

func TestOSCAL(t *testing.T) {
	schema.MustRegister("foo", &Foo{})
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
	err := s.RegisterOSCAL(p)
	assert.Nil(t, err)
	expected := map[string]bool{
		"GET/foo/:uuid":    false,
		"POST/foo":         false,
		"PUT/foo/:uuid":    false,
		"DELETE/foo/:uuid": false,
	}
	for _, rt := range p.Routes() {
		t := fmt.Sprintf("%s%s", rt.Method, rt.Path)
		if _, ok := expected[t]; ok {
			expected[t] = true
		}
	}
	for k, v := range expected {
		assert.True(t, v, fmt.Sprintf("expected route %s not found", k))
	}
}
func TestGenGET(t *testing.T) {
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
	fn := s.genGET(&Foo{})
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/foo/123", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	t.Run("returns success", func(t *testing.T) {
		c := e.NewContext(req, rec)
		c.SetPath("/foo/:uuid")
		c.SetParamNames("uuid")
		c.SetParamValues("123")
		err := fn(c)
		if assert.NoError(t, err) {
			assert.Equal(t, http.StatusOK, rec.Code)
		}
	})
	t.Run("return server error if get fails", func(t *testing.T) {
		rec = httptest.NewRecorder()
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req = httptest.NewRequest(http.MethodGet, "/foo/123err", nil)
		c := e.NewContext(req, rec)
		c.SetPath("/foo/:uuid")
		c.SetParamNames("uuid")
		c.SetParamValues("123err")
		err := fn(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("return not found if Get Returns not found", func(t *testing.T) {
		rec = httptest.NewRecorder()
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req = httptest.NewRequest(http.MethodGet, "/foo/456", nil)
		c := e.NewContext(req, rec)
		c.SetPath("/foo/:uuid")
		c.SetParamNames("uuid")
		c.SetParamValues("456")
		err := fn(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)

	})
}
