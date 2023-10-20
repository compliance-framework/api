package api

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Server struct {
	Echo *echo.Echo
}

// NewServer initializes the Echo server with necessary routes and configurations.
func NewServer() *Server {
	e := echo.New()
	e.Use(middleware.Logger())

	return &Server{
		Echo: e,
	}
}

// Start starts the Echo server
func (s *Server) Start(address string) error {
	return s.Echo.Start(address)
}

func (s *Server) Route(method, path string, handler echo.HandlerFunc) {
	s.Echo.Add(method, path, handler)
}
