package api

import (
	"context"
	mw "github.com/compliance-framework/configuration-service/api/middleware"
	_ "github.com/compliance-framework/configuration-service/docs"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echoSwagger "github.com/swaggo/echo-swagger"
)

type Server struct {
	ctx  context.Context
	echo *echo.Echo
}

// NewServer initializes the echo server with necessary routes and configurations.
func NewServer(ctx context.Context) *Server {
	e := echo.New()
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.Logger())
	e.Validator = mw.NewValidator()
	e.GET("/swagger/*", echoSwagger.WrapHandler)

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

func (s *Server) API() *echo.Group {
	return s.echo.Group("/api")
}
