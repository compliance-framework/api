package api

import (
	"context"

	"github.com/compliance-framework/configuration-service/api/binders"
	mw "github.com/compliance-framework/configuration-service/api/middleware"
	_ "github.com/compliance-framework/configuration-service/docs"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echoSwagger "github.com/swaggo/echo-swagger"
	"go.uber.org/zap"
)

type Server struct {
	ctx   context.Context
	echo  *echo.Echo
	sugar *zap.SugaredLogger
}

// NewServer initializes the echo server with necessary routes and configurations.
func NewServer(ctx context.Context, s *zap.SugaredLogger) *Server {
	e := echo.New()
	e.Binder = &binders.CustomBinder{}
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.Logger())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept},
	}))
	e.Validator = mw.NewValidator()
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	return &Server{
		ctx:   ctx,
		echo:  e,
		sugar: s,
	}
}

// Start starts the echo server
func (s *Server) Start(address string) error {
	return s.echo.Start(address)
}

func (s *Server) E() *echo.Echo {
	return s.echo
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

func (s *Server) PrintRoutes() {
	for _, route := range s.echo.Routes() {
		s.sugar.Infof("%s %s", route.Method, route.Path)
	}
}
