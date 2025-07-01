package service

import (
	"context"
	"errors"

	"github.com/compliance-framework/configuration-service/internal/config"
	logging "github.com/compliance-framework/configuration-service/internal/logging"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

func ConnectSQLDb(config *config.Config, sugar *zap.SugaredLogger) (*gorm.DB, error) {
	gormLogLevel := gormLogger.Warn
	if config.DBDebug {
		gormLogLevel = gormLogger.Info
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

func ConnectMongo(ctx context.Context, clientOptions *options.ClientOptions, databaseName string) (*mongo.Database, error) {
	client, err := mongo.Connect(ctx, clientOptions)

	if err != nil {
		return nil, err
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, err
	}

	return client.Database(databaseName), nil
}
