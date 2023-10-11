package server

import (
	"fmt"
	"net/http"

	process "github.com/compliance-framework/configuration-service/internal/models/process"
	echo "github.com/labstack/echo/v4"
)

func (s *Server) RegisterProcess(e *echo.Echo) error {
	e.GET("/job-results/:uuid", s.GetJobResult)
	e.GET("/job-results", s.GetJobResults)
	return nil
}

func (s *Server) GetJobResult(c echo.Context) error {
	id := c.Param("uuid")
	c.Logger().Infof("Process::getJobResult::uuid: %v", id)
	jr := process.JobResult{}

	err := s.Driver.Get(c.Request().Context(), jr.Type(), id, &jr)

	c.Logger().Infof("Process::getJobResult::obj: %v", jr)
	if err != nil {
		return c.String(http.StatusNotFound, fmt.Errorf("object not found").Error())
	}

	return c.JSON(http.StatusOK, jr)
}

func (s *Server) GetJobResults(c echo.Context) error {
	jobResult := process.JobResult{}
	objs, err := s.Driver.GetAll(c.Request().Context(), jobResult.Type(), &jobResult)

	c.Logger().Infof("Process::getJobResults::objs: %v", objs)

	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Errorf("failed to get object: %v", err).Error())
	}
	return c.JSON(http.StatusOK, objs)
}
