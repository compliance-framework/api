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
	e.GET("/runtimes/:uuid", s.genGET(&runtime.Runtime{}))
	e.DELETE("/runtimes/:uuid", s.genDELETE(&runtime.Runtime{}))
	e.POST("/runtimes", s.genPOST(&runtime.Runtime{}))
	e.PUT("/runtimes/:uuid", s.genPUT(&runtime.Runtime{}))
	g := e.Group("/runtime")
	g.GET("/configurations/:uuid", s.genGET(&runtime.RuntimeConfiguration{}))
	g.DELETE("/configurations/:uuid", s.genDELETE(&runtime.RuntimeConfiguration{}))
	g.PUT("/configurations/:uuid", s.genPUT(&runtime.RuntimeConfiguration{}))
	g.POST("/configurations", s.genPOST(&runtime.RuntimeConfiguration{}))
	g.GET("/jobs/:uuid", s.genLIST(&runtime.RuntimeConfigurationJob{}))
	g.GET("/jobs", s.genLIST(&runtime.RuntimeConfigurationJob{}))
	g.POST("/jobs/assign", s.assignJobs)
	g.POST("/jobs/unassign", s.unassignJobs)
	g.GET("/plugins", s.genLIST(&runtime.RuntimePlugin{}))
	g.GET("/plugins/:uuid", s.genGET(&runtime.RuntimePlugin{}))
	g.DELETE("/plugins/:uuid", s.genDELETE(&runtime.RuntimePlugin{}))
	g.PUT("/plugins/:uuid", s.genPUT(&runtime.RuntimePlugin{}))
	g.POST("/plugins", s.genPOST(&runtime.RuntimePlugin{}))
	return nil
}

// assignJobs returns all RuntimeConfigurationJobs with no runtime-uuid associated with them, limited to a parameter.
// When this function is called, the returned jobs will automatically be upserted with the passed runtime-uuid
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
