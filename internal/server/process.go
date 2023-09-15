package server

import (
	"net/http"

	process "github.com/compliance-framework/configuration-service/internal/models/process"
	echo "github.com/labstack/echo/v4"
)

func (s *Server) RegisterProcess(e *echo.Echo) error {
	e.GET("/assessment-results/:uuid", s.getAssessmentResults)
	e.GET("/assessment-results", s.queryAssessmentResults)
	return nil
}

func (s *Server) getAssessmentResults(c echo.Context) error {

	return nil
}

func (s *Server) queryAssessmentResults(c echo.Context) error {
	objs, err := s.Driver.GetAll(c.Request().Context(), "AssessmentResults", &process.AssessmentResults{})

	if err != nil {
		return c.String(http.StatusInternalServerError, "failed to get object")
	}
	return c.JSON(http.StatusOK, objs)
}
