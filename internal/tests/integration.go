//go:build integration

package tests

import (
	"context"
	"fmt"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"time"
)

var (
	mongoPort     = "27017"
	mongoDatabase = "testdb"
	mongoUser     = "root"
	mongoPassword = "pass"
)

type IntegrationTestSuite struct {
	suite.Suite

	MongoContainer testcontainers.Container
	MongoClient    *mongo.Client
	MongoDatabase  *mongo.Database
}

func (suite *IntegrationTestSuite) SetupSuite() {
	var err error
	ctx := context.Background()

	// Set up a MongoDB container so we can run tests against a real database
	suite.MongoContainer, suite.MongoClient, suite.MongoDatabase, err = SetupIntegrationMongo(ctx)
	if err != nil {
		fmt.Println("Failed")
		suite.T().Fatal(err, "Failed to setup Mongo")
	}
}

func (suite *IntegrationTestSuite) TearDownSuite() {
	_ = suite.MongoContainer.Terminate(context.Background())
}

func SetupIntegrationMongo(ctx context.Context) (testcontainers.Container, *mongo.Client, *mongo.Database, error) {
	container, err := CreateMongoContainer(ctx)
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

func CreateMongoContainer(ctx context.Context) (testcontainers.Container, error) {
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
