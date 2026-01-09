package api

import (
	"context"

	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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
		metrics.HideBanner = true
		metrics.Use(middleware.Logger())
		metrics.GET("/metrics", echoprometheus.NewHandlerWithConfig(echoprometheus.HandlerConfig{
			Gatherer: m.registry,
		}))
		if err := metrics.Start(port); err != nil {
			m.logger.Error(err)
			return
		}
		<-m.ctx.Done()
		err := metrics.Shutdown(m.ctx)
		if err != nil {
			m.logger.Errorw("failed to shutdown metrics server", "error", err)
		}
	}()
}
