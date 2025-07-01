package service

import (
	"errors"

	"github.com/compliance-framework/configuration-service/internal/config"
	"github.com/compliance-framework/configuration-service/internal/logging"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func ConnectSQLDb(config *config.Config, sugar *zap.SugaredLogger) (*gorm.DB, error) {
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
		db, err = gorm.Open(postgres.Open(config.DBConnectionString), &gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
			Logger:                                   logging.NewZapGormLogger(sugar, gormLogLevel),
		})
	default:
		return nil, errors.New("unsupported DB driver: " + config.DBDriver)
	}

	if err != nil {
		return nil, err
	}
	return db, nil
}
