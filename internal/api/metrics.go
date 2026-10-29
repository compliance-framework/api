package api

import (
	"context"

	"github.com/labstack/echo-contrib/v5/echoprometheus"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"go.uber.org/zap"
)

type PrometheusCounters struct {
	BadLogins   prometheus.CounterVec
	TotalLogins prometheus.Counter
}

func newPrometheusCounters(registry *prometheus.Registry) *PrometheusCounters {
	badLogins := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ccf_logins_errors_total",
			Help: "Count of failed login attempts, grouped by reason (user_not_found, invalid_password). Any other errors are marked as unknown",
		},
		[]string{"reason"},
	)

	totalLogins := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ccf_logins_total",
			Help: "Total number of logins",
		},
	)

	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		badLogins,
		totalLogins,
	)

	return &PrometheusCounters{
		BadLogins:   *badLogins,
		TotalLogins: totalLogins,
	}
}

type PrometheusMetrics struct {
	ctx      context.Context
	logger   *zap.SugaredLogger
	registry *prometheus.Registry

	Counters *PrometheusCounters
}

func NewMetricsHandler(ctx context.Context, logger *zap.SugaredLogger) *PrometheusMetrics {
	registry := prometheus.NewRegistry()
	counters := newPrometheusCounters(registry)
	return &PrometheusMetrics{
		ctx:      ctx,
		logger:   logger,
		registry: registry,

		Counters: counters,
	}
}

func (m *PrometheusMetrics) Registry() *prometheus.Registry {
	return m.registry
}

func (m *PrometheusMetrics) StartMetricsServer(port string) {
	go func() {
		metrics := echo.New()
		metrics.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
			LogURI:     true,
			LogStatus:  true,
			LogMethod:  true,
			LogLatency: true,
			LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error {
				m.logger.Debugw("metrics request",
					zap.String("method", v.Method),
					zap.String("uri", v.URI),
					zap.Int("status", v.Status),
					zap.Int64("latency_ms", v.Latency.Milliseconds()),
				)
				return nil
			},
		}))
		metrics.GET("/metrics", echoprometheus.NewHandlerWithConfig(echoprometheus.HandlerConfig{
			Gatherer: m.registry,
		}))
		// Serves until m.ctx is cancelled, then shuts down gracefully.
		if err := (echo.StartConfig{Address: port, HideBanner: true}).Start(m.ctx, metrics); err != nil {
			m.logger.Error(err)
		}
	}()
}
