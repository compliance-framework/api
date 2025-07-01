//go:build integration

package sdk_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/config"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/docker/go-connections/nat"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

var (
	mongoPort     = "27017"
	mongoDatabase = "testdb"
	mongoUser     = "root"
	mongoPassword = "pass"
)

type IntegrationBaseTestSuite struct {
	suite.Suite

	MongoContainer testcontainers.Container
	MongoClient    *mongo.Client
	MongoDatabase  *mongo.Database

	Server *api.Server
}

func (suite *IntegrationBaseTestSuite) GetSDKTestClient() *sdk.Client {
	config := &sdk.Config{
		BaseURL: "http://" + suite.Server.E().ListenerAddr().String(),
	}
	return sdk.NewClient(http.DefaultClient, config)
}

func (suite *IntegrationBaseTestSuite) SetupSuite() {
	var err error
	ctx := context.Background()

	// Set up a MongoDB container so we can run tests against a real database
	suite.MongoContainer, suite.MongoClient, suite.MongoDatabase, err = setupIntegrationMongo(ctx)
	if err != nil {
		fmt.Println("Failed")
		suite.T().Fatal(err, "Failed to setup Mongo")
	}

	cfg := &config.Config{
		APIAllowedOrigins: []string{"*"},
	}

	// Next setup a full running echo server, so we can run tests against it.
	logger, _ := zap.NewDevelopment()
	server := api.NewServer(context.Background(), logger.Sugar(), cfg)
	handler.RegisterHandlers(server, suite.MongoDatabase, logger.Sugar())
	suite.Server = server

	errChan := make(chan error)
	go func() {
		err := suite.Server.E().Start("localhost:")
		if err != nil {
			errChan <- err
		}
	}()
	err = waitForServerStart(suite.Server.E(), errChan, false)

	assert.NoError(suite.T(), err)
}

func (suite *IntegrationBaseTestSuite) TearDownSuite() {
	_ = suite.MongoContainer.Terminate(context.Background())

	log.Println("Stopping Echo Server")
	if err := suite.Server.E().Shutdown(context.Background()); err != nil {
		suite.T().Error(err)
	}
}

func setupIntegrationMongo(ctx context.Context) (testcontainers.Container, *mongo.Client, *mongo.Database, error) {
	container, err := createMongoContainer(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	port, err := nat.NewPort("tcp", mongoPort)
	if err != nil {
		return nil, nil, nil, err
	}
	containerPort, err := container.MappedPort(ctx, port)
	if err != nil {
		return nil, nil, nil, err
	}

	uri := fmt.Sprintf("mongodb://%s:%s@localhost:%s", mongoUser, mongoPassword, containerPort.Port())

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, nil, nil, err
	}

	database := client.Database(mongoDatabase)

	return container, client, database, nil
}

func createMongoContainer(ctx context.Context) (testcontainers.Container, error) {
	var env = map[string]string{
		"MONGO_INITDB_ROOT_USERNAME": mongoUser,
		"MONGO_INITDB_ROOT_PASSWORD": mongoPassword,
		"MONGO_INITDB_DATABASE":      mongoDatabase,
	}
	var port = mongoPort + "/tcp"

	req := testcontainers.GenericContainerRequest{
		ProviderType: testcontainers.ProviderPodman,
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "mongo",
			ExposedPorts: []string{port},
			Env:          env,
		},
		Started: true,
	}
	container, err := testcontainers.GenericContainer(ctx, req)
	if err != nil {
		return container, fmt.Errorf("failed to start container: %v", err)
	}

	p, err := container.MappedPort(ctx, "27017")
	if err != nil {
		return container, fmt.Errorf("failed to get container external port: %v", err)
	}

	log.Println("mongo container ready and running at port: ", p.Port())

	return container, nil
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
