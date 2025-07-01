//go:build integration

package sdk_test

import (
	"context"
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/authn"
	"github.com/compliance-framework/configuration-service/internal/config"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	"github.com/compliance-framework/configuration-service/internal/tests"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	postgresContainers "github.com/testcontainers/testcontainers-go/modules/postgres"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type IntegrationBaseTestSuite struct {
	suite.Suite

	Migrator    *tests.TestMigrator
	DB          *gorm.DB
	dbcontainer *postgresContainers.PostgresContainer // We generate a unique name for each run, so we can run tests concurrently.
	Config      *config.Config

	Server *api.Server
}

func (suite *IntegrationBaseTestSuite) GetSDKTestClient() *sdk.Client {
	config := &sdk.Config{
		BaseURL: "http://" + suite.Server.E().ListenerAddr().String(),
	}
	return sdk.NewClient(http.DefaultClient, config)
}

func (suite *IntegrationBaseTestSuite) SetupSuite() {
	ctx := context.Background()

	var err error
	cfg := &config.Config{}
	privKey, pubKey, err := config.GenerateKeyPair(2048)
	suite.NoError(err, "failed to generate RSA key pair")

	cfg.JWTPrivateKey = privKey
	cfg.JWTPublicKey = pubKey
	suite.Config = cfg

	postgresContainer, err := postgresContainers.Run(ctx,
		"postgres:17.5",
		postgresContainers.WithDatabase("ccf"),
		postgresContainers.WithUsername("postgres"),
		postgresContainers.WithPassword("postgres"),
		postgresContainers.BasicWaitStrategies(),
	)
	if err != nil {
		panic(err)
	}

	// explicitly set sslmode=disable because the container is not configured to use TLS
	connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable", "application_name=ccf")
	if err != nil {
		panic(err)
	}
	suite.dbcontainer = postgresContainer

	db, err := gorm.Open(postgres.Open(connStr), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		panic("failed to connect database")
	}

	migrator := tests.NewTestMigrator(db)

	suite.DB = db
	suite.Migrator = migrator

	err = suite.Migrator.Up()
	suite.NoError(err, "failed to migrate")

	err = suite.Migrator.CreateUser()
	suite.NoError(err, "failed to create test user")

	suite.Config.APIAllowedOrigins = []string{"*"}

	// Next setup a full running echo server, so we can run tests against it.
	logger, _ := zap.NewDevelopment()
	server := api.NewServer(context.Background(), logger.Sugar(), cfg)
	handler.RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)

	suite.Server = server

	errChan := make(chan error)
	go func() {
		err := suite.Server.E().Start("localhost:")
		if err != nil {
			errChan <- err
		}
	}()
	err = waitForServerStart(suite.Server.E(), errChan, false)
}

func (suite *IntegrationBaseTestSuite) TearDownSuite() {
	err := testcontainers.TerminateContainer(suite.dbcontainer)
	if err != nil {
		suite.T().Fatal(err)
	}
}

func (suite *IntegrationBaseTestSuite) GetAuthToken() (*string, error) {
	dummyUser := relational.User{
		Email:     "dummy@example.com",
		FirstName: "Dummy",
		LastName:  "User",
	}

	return authn.GenerateJWTToken(&dummyUser, suite.Config.JWTPrivateKey)
}

func waitForServerStart(e *echo.Echo, errChan <-chan error, isTLS bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			var addr net.Addr
			if isTLS {
				addr = e.TLSListenerAddr()
			} else {
				addr = e.ListenerAddr()
			}
			if addr != nil && strings.Contains(addr.String(), ":") {
				return nil // was started
			}
		case err := <-errChan:
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		}
	}
}
