package config

import (
	"slices"
	"strings"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	DriverOptions = []string{"postgres"}
)

type Config struct {
	MongoURI           string
	AppPort            string
	DBDriver           string
	DBConnectionString string
	DBDebug            bool
}

func NewConfig(logger *zap.SugaredLogger) *Config {
	// for non-default but required variables, make sure the user is aware
	if !viper.IsSet("mongo_uri") {
		logger.Fatal("MONGO_URI is not set. Please set it in the environment or .env file.")
	}

	if !viper.IsSet("db_driver") {
		logger.Fatal(
			"CCF_DB_DRIVER is not set. Please set it in the environment or .env file. Expected values: ",
			strings.Join(DriverOptions, ", "),
		)
	}

	dbDriver := stripQuotes(strings.ToLower(viper.GetString("db_driver")))

	if !slices.Contains(DriverOptions, dbDriver) {
		logger.Fatal(
			"CCF_DB_DRIVER is set to an unsupported value: ",
			viper.GetString("db_driver"),
			". Supported values are: ",
			strings.Join(DriverOptions, ", "),
		)
	}

	if !viper.IsSet("db_connection") {
		logger.Fatal("CCF_DB_CONNECTION is not set. Please set it in the environment or .env file.")
	}

	appPort := viper.GetString("app_port")
	if !strings.HasPrefix(appPort, ":") {
		appPort = ":" + appPort
	}

	return &Config{
		MongoURI:           viper.GetString("mongo_uri"),
		AppPort:            appPort,
		DBDriver:           dbDriver,
		DBConnectionString: stripQuotes(viper.GetString("db_connection")),
		DBDebug:            viper.GetBool("db_debug"),
	}

}

func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
