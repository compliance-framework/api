package server

import (
	"errors"
	"fmt"
	"net/http"

	runtime "github.com/compliance-framework/configuration-service/internal/models/runtime"
	"github.com/compliance-framework/configuration-service/internal/pubsub"
	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
	echo "github.com/labstack/echo/v4"
)

func (s *Server) RegisterRuntime(e *echo.Echo) error {
	g := e.Group("/runtime")
	g.GET("/configurations/:uuid", s.getConfiguration)
	g.DELETE("/configurations/:uuid", s.deleteConfiguration)
	g.PUT("/configurations/:uuid", s.putConfiguration)
	g.POST("/configurations", s.postConfiguration)
	g.GET("/jobs/:uuid", s.getJob)
	g.GET("/jobs", s.getJobs)
	g.POST("/jobs/assign", s.assignJobs)
	g.POST("/jobs/unassign", s.unassignJobs)
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
	err := s.Driver.Get(c.Request().Context(), p.Type(), c.Param("uuid"), p)
	if err != nil {
		if errors.Is(err, storeschema.NotFoundErr{}) {
			return c.JSON(http.StatusOK, p)
		}
		return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to get object: %v", err))
	}
	err = s.Driver.Delete(c.Request().Context(), p.Type(), c.Param("uuid"))
	if err != nil {
		if errors.Is(err, storeschema.NotFoundErr{}) {
			return c.JSON(http.StatusNotFound, p)
		}
		return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to delete object: %v", err))
	}
	// TODO - Move to a channel dispatch
	defer func() {
		pubsub.Publish(pubsub.RuntimeConfigurationDeleted, p)
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
		pubsub.Publish(pubsub.RuntimeConfigurationUpdated, p)
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
		pubsub.Publish(pubsub.RuntimeConfigurationCreated, p)
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

// getJobs returns all RuntimeConfigurationJobs
// TODO Add tests
func (s *Server) getJobs(c echo.Context) error {
	objs, err := s.Driver.GetAll(c.Request().Context(), "jobs", &runtime.RuntimeConfigurationJob{})
	if err != nil {
		if errors.Is(err, storeschema.NotFoundErr{}) {
			return c.String(http.StatusNotFound, "object not found")
		}
		return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to get object: %v", err))
	}
	return c.JSON(http.StatusOK, objs)
}

// assignJobs returns all RuntimeConfigurationJobs with no runtime-uuid associated with them, limited to a parameter.
// When this function is called, the returned jobs will automatically be upserted with the passed runtime-uuid
// TODO Add tests
func (s *Server) assignJobs(c echo.Context) error {
	p := &runtime.RuntimeConfigurationJobRequest{}
	if err := c.Bind(p); err != nil {
		return c.String(http.StatusBadRequest, fmt.Sprintf("bad request: %v", err))
	}
	filter := map[string]interface{}{
		"runtime-uuid": "",
	}
	objs, err := s.Driver.GetAll(c.Request().Context(), "jobs", &runtime.RuntimeConfigurationJob{}, filter)
	if err != nil {
		if errors.Is(err, storeschema.NotFoundErr{}) {
			return c.String(http.StatusNotFound, "object not found")
		}
		return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to get object: %v", err))
	}
	for i, obj := range objs {
		if p.Limit > 0 && i >= p.Limit {
			break
		}
		job := obj.(*runtime.RuntimeConfigurationJob)
		job.RuntimeUuid = p.RuntimeUuid
		err = s.Driver.Update(c.Request().Context(), job.Type(), job.UUID(), job)
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to update object: %v", err))
		}
		objs[i] = job
	}
	return c.JSON(http.StatusOK, objs)

}

// unassignJobs removes the runtime-uuid configured for a given set of RuntimeConfigurationJob.
// Note: RuntimeConfigurationJobs can only be created/updated/deleted via a creation/update/delete of a RuntimeConfiguration
// TODO Add tests
func (s *Server) unassignJobs(c echo.Context) error {
	p := &runtime.RuntimeConfigurationJobRequest{}
	if err := c.Bind(p); err != nil {
		return c.String(http.StatusBadRequest, fmt.Sprintf("bad request: %v", err))
	}
	filter := map[string]interface{}{
		"runtime-uuid": p.RuntimeUuid,
	}
	objs, err := s.Driver.GetAll(c.Request().Context(), "jobs", &runtime.RuntimeConfigurationJob{}, filter)
	if err != nil {
		if errors.Is(err, storeschema.NotFoundErr{}) {
			return c.String(http.StatusNotFound, "object not found")
		}
		return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to get object: %v", err))
	}
	for i, obj := range objs {
		if p.Limit > 0 && i >= p.Limit {
			break
		}
		job := obj.(*runtime.RuntimeConfigurationJob)
		job.RuntimeUuid = ""
		err = s.Driver.Update(c.Request().Context(), job.Type(), job.UUID(), job)
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("failed to update object: %v", err))
		}
		objs[i] = job
	}
	return c.JSON(http.StatusOK, objs)

}
