package api

import (
	"cmp"
	"context"
	"slices"

	"github.com/compliance-framework/api/internal/api/binders"
	mw "github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/config"

	_ "github.com/compliance-framework/api/docs"
	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echoSwagger "github.com/swaggo/echo-swagger"
	"go.uber.org/zap"
)

type Server struct {
	ctx    context.Context
	echo   *echo.Echo
	sugar  *zap.SugaredLogger
	config *config.Config
}

// NewServer initializes the echo server with necessary routes and configurations.
func NewServer(ctx context.Context, s *zap.SugaredLogger, config *config.Config, metrics *PrometheusMetrics) *Server {
	e := echo.New()
	e.Binder = &binders.CustomBinder{}
	e.HideBanner = true
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.Logger())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURI:       true,
		LogStatus:    true,
		LogMethod:    true,
		LogUserAgent: true,
		LogLatency:   true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			s.Debugw("request",
				zap.String("method", v.Method),
				zap.String("uri", v.URI),
				zap.Int("status", v.Status),
				zap.String("user_agent", v.UserAgent),
				zap.String("latency_human", v.Latency.String()),
				zap.Int64("latency_ms", v.Latency.Milliseconds()),
			)
			return nil
		},
	}))
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     config.APIAllowedOrigins,
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
		AllowCredentials: true,
	}))
	e.Use(echoprometheus.NewMiddlewareWithConfig(echoprometheus.MiddlewareConfig{
		Registerer: metrics.Registry(),
	}))
	e.Validator = mw.NewValidator()
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	return &Server{
		ctx:    ctx,
		echo:   e,
		sugar:  s,
		config: config,
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
	for _, route := range slices.SortedFunc(slices.Values(s.echo.Routes()), func(a, b *echo.Route) int {
		return cmp.Compare(a.Path, b.Path)
	}) {
		s.sugar.Infof("%s %s", route.Method, route.Path)
	}
}
