package server

import (
	"net/http"

	process "github.com/compliance-framework/configuration-service/internal/models/process"
	echo "github.com/labstack/echo/v4"
)

func (s *Server) RegisterProcess(e *echo.Echo) error {
	e.GET("/assessment-results/:uuid", s.getAssessmentResult)
	e.GET("/assessment-results", s.listAssessmentResult)
	return nil
}

func (s *Server) getAssessmentResult(c echo.Context) error {
	assessmentResult := process.AssessmentResult{}
	obj := s.Driver.Get(c.Request().Context(), assessmentResult.Type(), c.Param("uuid"), &assessmentResult)

	if obj == nil {
		return c.String(http.StatusNotFound, "object not found")
	}

	return c.JSON(http.StatusOK, obj)
}

func (s *Server) listAssessmentResult(c echo.Context) error {
	assessmentResult := process.AssessmentResult{}
	objs, err := s.Driver.GetAll(c.Request().Context(), assessmentResult.Type(), &assessmentResult)

	if err != nil {
		return c.String(http.StatusInternalServerError, "failed to get object")
	}
	return c.JSON(http.StatusOK, objs)
}
