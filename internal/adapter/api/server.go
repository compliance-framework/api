package api

import (
	"context"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Server struct {
	ctx  context.Context
	Echo *echo.Echo
}

// NewServer initializes the Echo server with necessary routes and configurations.
func NewServer(ctx context.Context) *Server {
	e := echo.New()
	e.Use(middleware.Logger())

	return &Server{
		ctx:  ctx,
		Echo: e,
	}
}

// Start starts the Echo server
func (s *Server) Start(address string) error {
	return s.Echo.Start(address)
}

func (s *Server) Stop() error {
	fmt.Println("stopping server")
	return s.Echo.Shutdown(s.ctx)
}

func (s *Server) Route(method, path string, handler echo.HandlerFunc) {
	s.Echo.Add(method, path, handler)
}
