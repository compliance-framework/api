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
	g := e.Group("/runtime")
	g.GET("/configurations/:uuid", s.getConfiguration)
	g.DELETE("/configurations/:uuid", s.deleteConfiguration)
	g.PUT("/configurations/:uuid", s.putConfiguration)
	g.POST("/configurations", s.postConfiguration)
	g.GET("jobs/:uuid", s.getJob)
	g.POST("jobs/assign", s.assignJobs)
	g.POST("jobs/unassign", s.unassignJobs)
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
	// TODO - Move to a channel dispatch
	defer func() {
		err = s.deleteJobs(c, p) // nolint
	}()
	err = c.JSON(http.StatusOK, p)
	return err
}

func (s *Server) putConfiguration(c echo.Context) error {
	p := &runtime.RuntimeConfiguration{}
	if err := c.Bind(p); err != nil {
		return c.String(http.StatusBadRequest, fmt.Sprintf("bad request: %v", err))
	}
	err := s.Driver.Update(c.Request().Context(), p.Type(), c.Param("uuid"), p)
	if err != nil {
		if errors.Is(err, storeschema.NotFoundErr{}) {
			return c.JSON(http.StatusNotFound, nil)
		}
		return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to update object: %v", err))
	}
	// TODO - Move to a channel dispatch
	defer func() {
		err = s.updateJobs(c, p)
	}()
	err = c.JSON(http.StatusOK, p)
	return err
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
	// TODO - Move to a channel dispatch
	defer func() {
		err = s.createJobs(c, p)
	}()
	err = c.JSON(http.StatusCreated, p)
	return err
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

// deleteJobs deletes RuntimeConfigurationJobs as a result of a RuntimeConfiguration deletion
func (s *Server) deleteJobs(c echo.Context, r *runtime.RuntimeConfiguration) error {
	return nil
}

// updateJobs deletes, creates, and updates RuntimeConfigurationJobs as a result of a RuntimeConfiguration update
func (s *Server) updateJobs(c echo.Context, r *runtime.RuntimeConfiguration) error {
	return nil
}

// createJobs creates RuntimeConfigurationJobs from a newly created RuntimeConfiguration
func (s *Server) createJobs(c echo.Context, r *runtime.RuntimeConfiguration) error {
	return nil
}
