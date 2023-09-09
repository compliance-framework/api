package server

import (
	runtime "github.com/compliance-framework/configuration-service/internal/models/runtime"
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
	g.GET("/plugins", s.genLIST(&runtime.RuntimePlugin{}))
	g.GET("/plugins/:uuid", s.genGET(&runtime.RuntimePlugin{}))
	g.DELETE("/plugins/:uuid", s.genDELETE(&runtime.RuntimePlugin{}))
	g.PUT("/plugins/:uuid", s.genPUT(&runtime.RuntimePlugin{}))
	g.POST("/plugins", s.genPOST(&runtime.RuntimePlugin{}))
	return nil
}
