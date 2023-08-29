package server

import (
	"errors"
	"fmt"
	"net/http"

	runtime "github.com/compliance-framework/configuration-service/internal/models/runtime"
	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
	echo "github.com/labstack/echo/v4"
)

func (s *Server) RegisterRuntime(e *echo.Echo) error {
	p := e
	g := p.Group("/runtime")
	g.GET("/configurations/:uuid", s.getConfiguration)
	g.DELETE("/configurations/:uuid", s.deleteConfiguration)
	g.PUT("/configurations/:uuid", s.putConfiguration)
	g.POST("/configurations", s.postConfiguration)
	return nil
}

func (s *Server) getConfiguration(c echo.Context) (err error) {
	p := &runtime.RuntimeConfiguration{}
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

func (s *Server) deleteConfiguration(c echo.Context) error {
	p := &runtime.RuntimeConfiguration{}
	if err := c.Bind(p); err != nil {
		return c.String(http.StatusBadRequest, fmt.Sprintf("bad request: %v", err))
	}
	err := s.Driver.Delete(c.Request().Context(), p.Type(), c.Param("uuid"))
	if err != nil {
		if errors.Is(err, storeschema.NotFoundErr{}) {
			return c.JSON(http.StatusNotFound, p)
		}
		return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to delete object: %v", err))
	}
	// Add Removal of Jobs logic in here
	return c.JSON(http.StatusOK, p)
}

func (s *Server) putConfiguration(c echo.Context) error {
	p := &runtime.RuntimeConfiguration{}
	if err := c.Bind(p); err != nil {
		return c.String(http.StatusBadRequest, fmt.Sprintf("bad request: %v", err))
	}
	err := s.Driver.Update(c.Request().Context(), p.Type(), c.Param("uuid"), p)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to update object: %v", err))
	}
	// Add Job Update in Here
	return c.JSON(http.StatusOK, p)
}

func (s *Server) postConfiguration(c echo.Context) error {
	p := &runtime.RuntimeConfiguration{}
	if err := c.Bind(p); err != nil {
		return c.String(http.StatusBadRequest, fmt.Sprintf("bad request: %v", err))
	}
	err := s.Driver.Create(c.Request().Context(), p.Type(), p.UUID(), p)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to update object: %v", err))
	}
	// Add Job Creation Logic Here
	return c.JSON(http.StatusOK, p)
}

// getJob returns a single RuntimeConfigurationJob by its uuid
func (s *Server) getJob(c echo.Context) error {
	p := &runtime.RuntimeConfigurationJob{}
	if err := c.Bind(p); err != nil {
		return c.String(http.StatusBadRequest, fmt.Sprintf("bad request: %v", err))
	}
	err := s.Driver.Get(c.Request().Context(), p.Type(), c.Param("uuid"), p)
	if err != nil {
		if errors.Is(err, storeschema.NotFoundErr{}) {
			return c.String(http.StatusNotFound, "object not found")
		}
		return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to get object: %v", err))
	}
	return c.JSON(http.StatusOK, p)
}

// assignJobs returns all RuntimeConfigurationJobs with no runtime-uuid associated with them, limited to a parameter.
// When this function is called, the returned jobs will automatically be upserted with the passed runtime-uuid
func (s *Server) assignJobs(c echo.Context) error {
	return nil
}

// unassignJobs removes the runtime-uuid configured for a given set of RuntimeConfigurationJob.
// Note: RuntimeConfigurationJobs can only be created/updated/deleted via a creation/update/delete of a RuntimeConfiguration
func (s *Server) unassignJobs(c echo.Context) error {
	return nil
}
