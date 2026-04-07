//go:build integration

package tests

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	postgresContainers "github.com/testcontainers/testcontainers-go/modules/postgres"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type IntegrationTestSuite struct {
	suite.Suite

	Migrator    *TestMigrator
	DB          *gorm.DB
	dbcontainer *postgresContainers.PostgresContainer // We generate a unique name for each run, so we can run tests concurrently.
	Config      *config.Config
}

func (suite *IntegrationTestSuite) SetupSuite() {
	ctx := context.Background()
	cfg := &config.Config{}
	privKey, pubKey, err := config.GenerateKeyPair(2048)
	suite.NoError(err, "failed to generate RSA key pair")

	cfg.JWTPrivateKey = privKey
	cfg.JWTPublicKey = pubKey
	// Only testing production environment here
	cfg.Environment = "production"
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

	migrator := &TestMigrator{
		db: db,
	}

	suite.DB = db
	suite.Migrator = migrator

	err = suite.Migrator.Up()
	suite.NoError(err, "failed to migrate")

	err = suite.Migrator.CreateUser()
	suite.NoError(err, "failed to create test user")
}

func (suite *IntegrationTestSuite) TearDownSuite() {
	err := testcontainers.TerminateContainer(suite.dbcontainer)
	if err != nil {
		suite.T().Fatal(err)
	}
}

func (suite *IntegrationTestSuite) GetAuthToken() (*string, error) {
	dummyUser := relational.User{
		Email:     "dummy@example.com",
		FirstName: "Dummy",
		LastName:  "User",
	}

	return authn.GenerateJWTToken(&dummyUser, suite.Config.JWTPrivateKey)
}

func (suite *IntegrationTestSuite) CreateAgent(name string) (*relational.Agent, error) {
	agent := &relational.Agent{
		Name:     name,
		IsActive: true,
	}
	return agent, suite.DB.Create(agent).Error
}

func (suite *IntegrationTestSuite) CreateAgentKey(agent *relational.Agent, name string) (*relational.AgentServiceAccountKey, string, error) {
	secret := fmt.Sprintf("secret-%d", time.Now().UnixNano())
	key := &relational.AgentServiceAccountKey{
		AgentID:  agent.ID,
		Name:     &name,
		ClientID: fmt.Sprintf("client-%d", time.Now().UnixNano()),
	}
	if err := key.SetSecret(secret); err != nil {
		return nil, "", err
	}
	if err := suite.DB.Create(key).Error; err != nil {
		return nil, "", err
	}
	return key, secret, nil
}

func (suite *IntegrationTestSuite) GetAgentToken(agent *relational.Agent, key *relational.AgentServiceAccountKey) (*string, error) {
	return authn.GenerateAgentJWTToken(agent, key, suite.Config.JWTPrivateKey)
}
