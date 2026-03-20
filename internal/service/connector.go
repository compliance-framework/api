package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/logging"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func ConnectSQLDb(ctx context.Context, config *config.Config, sugar *zap.SugaredLogger) (*gorm.DB, error) {
	gormLogLevel := logger.Warn
	if config.DBDebug {
		gormLogLevel = logger.Info
	}

	//TODO: farm this out to specific function/file
	var (
		db  *gorm.DB
		err error
	)

	switch config.DBDriver {
	case "postgres":
		dialect := postgres.New(postgres.Config{
			DSN: config.DBConnectionString,
		})
		db, err = gorm.Open(dialect, &gorm.Config{
			DisableAutomaticPing:                     true,
			DisableForeignKeyConstraintWhenMigrating: true,
			Logger:                                   logging.NewZapGormLogger(sugar, gormLogLevel),
			PrepareStmt:                              true,
		})

		pdb, err := db.DB()
		if err != nil {
			return nil, err
		}

		timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*10)
		// Connection pool tuning — the defaults (MaxIdleConns=2) are far too
		// conservative and become the throughput bottleneck under load because
		// Go constantly creates/destroys TCP connections to Postgres.
		pdb.SetMaxOpenConns(50)
		pdb.SetMaxIdleConns(25)
		pdb.SetConnMaxLifetime(5 * time.Minute)
		pdb.SetConnMaxIdleTime(3 * time.Minute)
		defer cancel()

		for {
			err = pdb.Ping()
			if err == nil {
				sugar.Info("Connected to database")
				break
			}

			if strings.Contains(err.Error(), "failed to connect") {
				// The connection failed, we should see if we have timed out and return
				if errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
					sugar.Warn("Timed out trying to connect to database. Returning")
					return nil, err
				}
			} else {
				return nil, err
			}
			sugar.Warn("Failed to connect to database. Retrying in 0.5 seconds")
			time.Sleep(time.Millisecond * 500)
		}
	default:
		return nil, errors.New("unsupported DB driver: " + config.DBDriver)
	}

	if err != nil {
		return nil, err
	}
	return db, nil
}
