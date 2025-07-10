package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/compliance-framework/configuration-service/internal/config"
	"github.com/compliance-framework/configuration-service/internal/logging"
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
		})

		pdb, err := db.DB()
		if err != nil {
			return nil, err
		}

		timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*10)
		defer cancel()

		for true {
			err = pdb.Ping()
			if err == nil {
				sugar.Warn("Connected to database")
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
