package api

import (
	"cmp"
	"context"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/compliance-framework/api/internal/api/binders"
	mw "github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/config"

	_ "github.com/compliance-framework/api/docs"
	"github.com/labstack/echo-contrib/v5/echoprometheus"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	echoSwagger "github.com/swaggo/echo-swagger/v2"
	"go.uber.org/zap"
)

type Server struct {
	ctx    context.Context
	echo   *echo.Echo
	sugar  *zap.SugaredLogger
	config *config.Config
}

// LineageGeneratedAtHeader carries when the data behind a lineage response was
// loaded (RFC 3339), so the UI can show its age and offer a refresh.
const LineageGeneratedAtHeader = "X-Lineage-Generated-At"

// NewServer initializes the echo server with necessary routes and configurations.
func NewServer(ctx context.Context, s *zap.SugaredLogger, config *config.Config, metrics *PrometheusMetrics) *Server {
	e := echo.New()
	e.Binder = &binders.CustomBinder{}
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURI:       true,
		LogStatus:    true,
		LogMethod:    true,
		LogUserAgent: true,
		LogLatency:   true,
		LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error {
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
	// A handler panic becomes a 500 (logged above) instead of a dropped connection.
	e.Use(middleware.Recover())
	allowOrigins := config.APIAllowedOrigins
	if len(allowOrigins) == 0 {
		// Any origin, as echo v4 defaulted to. Loaded configs always set at least one.
		allowOrigins = []string{"*"}
	}
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:  allowOrigins,
		AllowHeaders:  []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization, "If-Match", "If-None-Match"},
		ExposeHeaders: []string{"ETag", LineageGeneratedAtHeader},
		// Echo refuses "*" with credentials (browsers reject that pair anyway), so a
		// wildcard allows every origin without them instead of failing at startup.
		AllowCredentials: !slices.Contains(allowOrigins, "*"),
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

// Start serves until SIGINT/SIGTERM, then shuts the server down gracefully.
func (s *Server) Start(address string) error {
	ctx, stop := signal.NotifyContext(s.ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return echo.StartConfig{Address: address, HideBanner: true}.Start(ctx, s.echo)
}

func (s *Server) E() *echo.Echo {
	return s.echo
}

func (s *Server) API() *echo.Group {
	return s.echo.Group("/api")
}

func (s *Server) PrintRoutes() {
	for _, route := range slices.SortedFunc(slices.Values(s.echo.Router().Routes()), func(a, b echo.RouteInfo) int {
		return cmp.Compare(a.Path, b.Path)
	}) {
		s.sugar.Infof("%s %s", route.Method, route.Path)
	}
}
