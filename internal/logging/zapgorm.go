package logging

import (
	"context"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm/logger"
)

type ZapGormLogger struct {
	zap           *zap.SugaredLogger
	logLevel      logger.LogLevel
	slowThreshold time.Duration
}

func NewZapGormLogger(zap *zap.SugaredLogger, level logger.LogLevel) logger.Interface {
	return &ZapGormLogger{
		zap:           zap,
		logLevel:      level,
		slowThreshold: 0,
	}
}

func (l *ZapGormLogger) LogMode(level logger.LogLevel) logger.Interface {
	return &ZapGormLogger{
		zap:           l.zap,
		logLevel:      level,
		slowThreshold: 0,
	}
}

func (l *ZapGormLogger) Info(ctx context.Context, msg string, data ...any) {
	if l.logLevel >= logger.Info {
		l.zap.Infof(msg, data...)
	}
}

func (l *ZapGormLogger) Warn(ctx context.Context, msg string, data ...any) {
	if l.logLevel >= logger.Warn {
		l.zap.Warnf(msg, data...)
	}
}

func (l *ZapGormLogger) Error(ctx context.Context, msg string, data ...any) {
	if l.logLevel >= logger.Error {
		l.zap.Errorf(msg, data...)
	}
}

func (l *ZapGormLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	if l.logLevel == logger.Silent {
		return
	}

	elapsed := time.Since(begin)
	sql, rows := fc()

	switch {
	case err != nil && l.logLevel >= logger.Error:
		l.zap.Errorf("[%.3fms] [rows:%v] %s | error: %v", float64(elapsed.Microseconds())/1000, rows, sql, err)
	case l.logLevel >= logger.Info:
		l.zap.Infof("[%.3fms] [rows:%v] %s", float64(elapsed.Microseconds())/1000, rows, sql)
	}
}
