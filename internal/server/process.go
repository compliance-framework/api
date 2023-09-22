package server

import (
	"fmt"
	"net/http"

	process "github.com/compliance-framework/configuration-service/internal/models/process"
	echo "github.com/labstack/echo/v4"
)

func (s *Server) RegisterProcess(e *echo.Echo) error {
	e.GET("/assessment-results/:uuid", s.GetAssessmentResult)
	e.GET("/assessment-results", s.GetAssessmentResults)
	return nil
}

func (s *Server) GetAssessmentResult(c echo.Context) error {
	id := c.Param("uuid")
	c.Logger().Infof("Process::getAssessmentResult::uuid: %v", id)
	assessmentResult := process.AssessmentResult{}

	err := s.Driver.Get(c.Request().Context(), assessmentResult.Type(), id, &assessmentResult)

	c.Logger().Infof("Process::getAssessmentResult::obj: %v", assessmentResult)
	if err != nil {
		return c.String(http.StatusNotFound, fmt.Errorf("object not found").Error())
	}

	return c.JSON(http.StatusOK, assessmentResult)
}

func (s *Server) GetAssessmentResults(c echo.Context) error {
	assessmentResult := process.AssessmentResult{}
	objs, err := s.Driver.GetAll(c.Request().Context(), assessmentResult.Type(), &assessmentResult)

	c.Logger().Infof("Process::getAssessmentResults::objs: %v", objs)

	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Errorf("failed to get object: %v", err).Error())
	}
	return c.JSON(http.StatusOK, objs)
}
