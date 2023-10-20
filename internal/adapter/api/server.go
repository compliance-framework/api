package api

import (
	"context"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Server struct {
	ctx  context.Context
	echo *echo.Echo
}

// NewServer initializes the echo server with necessary routes and configurations.
func NewServer(ctx context.Context) *Server {
	e := echo.New()
	e.Use(middleware.Logger())

	return &Server{
		ctx:  ctx,
		echo: e,
	}
}

// Start starts the echo server
func (s *Server) Start(address string) error {
	return s.echo.Start(address)
}

func (s *Server) Stop() error {
	err := s.echo.Shutdown(s.ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) Route(method, path string, handler echo.HandlerFunc) {
	s.echo.Add(method, path, handler)
}
