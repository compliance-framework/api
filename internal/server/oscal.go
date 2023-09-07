package server

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
	echo "github.com/labstack/echo/v4"
)

type Server struct {
	Driver storeschema.Driver
}

func (s *Server) RegisterOSCAL(e *echo.Echo) error {
	models := schema.GetAll()
	for name, model := range models {
		routePref := fmt.Sprintf("/%s", name)
		route := fmt.Sprintf("/%s/:uuid", name)
		e.POST(routePref, s.genPOST(model))
		e.GET(route, s.genGET(model))
		e.DELETE(route, s.genDELETE(model))
		e.PUT(route, s.genPUT(model))
	}
	return nil
}

func (s *Server) genLIST(model schema.BaseModel) func(e echo.Context) (err error) {
	return func(c echo.Context) (err error) {
		p := model.DeepCopy()
		objs, err := s.Driver.GetAll(c.Request().Context(), p.Type(), p)
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to get object: %v", err))
		}
		return c.JSON(http.StatusOK, objs)
	}
}

func (s *Server) genGET(model schema.BaseModel) func(e echo.Context) (err error) {
	return func(c echo.Context) (err error) {
		p := model.DeepCopy()
		if err := c.Bind(p); err != nil {
			return c.String(http.StatusBadRequest, fmt.Sprintf("bad request: %v", err))
		}
		err = s.Driver.Get(c.Request().Context(), p.Type(), c.Param("uuid"), p)
		if err != nil {
			if errors.Is(err, storeschema.NotFoundErr{}) {
				return c.String(http.StatusNotFound, "object not found")
			}
			return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to get object: %v", err))
		}
		return c.JSON(http.StatusOK, p)
	}
}

// TODO Add tests for GenPOST
func (s *Server) genPOST(model schema.BaseModel) func(e echo.Context) (err error) {
	return func(c echo.Context) (err error) {
		p := model.DeepCopy()
		if err := c.Bind(p); err != nil {
			return c.String(http.StatusBadRequest, fmt.Sprintf("bad request: %v", err))
		}
		err = p.Validate()
		if err != nil {
			return c.String(http.StatusBadRequest, fmt.Sprintf("invalid payload: %v", err))
		}
		err = s.Driver.Create(c.Request().Context(), p.Type(), p.UUID(), p)
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to create object: %v", err))
		}
		return c.JSON(http.StatusCreated, p)
	}
}

// TODO Add tests for GenPUT
func (s *Server) genPUT(model schema.BaseModel) func(e echo.Context) (err error) {
	return func(c echo.Context) (err error) {
		p := model.DeepCopy()
		if err := c.Bind(p); err != nil {
			return c.String(http.StatusBadRequest, fmt.Sprintf("bad request: %v", err))
		}
		err = s.Driver.Update(c.Request().Context(), p.Type(), c.Param("uuid"), p)
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to update object: %v", err))
		}
		return c.JSON(http.StatusOK, p)
	}
}

// TODO Add tests for GenDELETE
func (s *Server) genDELETE(model schema.BaseModel) func(e echo.Context) (err error) {
	return func(c echo.Context) (err error) {
		p := model.DeepCopy()
		if err := c.Bind(p); err != nil {
			return c.String(http.StatusBadRequest, fmt.Sprintf("bad request: %v", err))
		}
		err = s.Driver.Delete(c.Request().Context(), p.Type(), c.Param("uuid"))
		if err != nil {
			if errors.Is(err, storeschema.NotFoundErr{}) {
				return c.String(http.StatusNotFound, "object not found")
			}
			return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to delete object: %v", err))
		}
		return c.JSON(http.StatusOK, p)
	}
}
