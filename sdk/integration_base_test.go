//go:build integration

package sdk_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	authhandler "github.com/compliance-framework/api/internal/api/handler/auth"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/compliance-framework/api/internal/service/worker"
	"github.com/compliance-framework/api/internal/tests"

	"github.com/compliance-framework/api/sdk"
	"github.com/google/uuid"
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
	// httpServer serves Server's routes on a free local port.
	httpServer *httptest.Server
}

func (suite *IntegrationBaseTestSuite) GetSDKTestClient() *sdk.Client {
	config := &sdk.Config{
		BaseURL: suite.httpServer.URL,
	}
	return sdk.NewClient(http.DefaultClient, config)
}

func (suite *IntegrationBaseTestSuite) GetAuthenticatedSDKTestClient() (*sdk.Client, error) {
	return suite.GetAuthenticatedSDKTestClientWithLogger(nil)
}

// GetAuthenticatedSDKTestClientWithLogger is GetAuthenticatedSDKTestClient with the SDK's
// logger set, for tests that check what the SDK logs.
func (suite *IntegrationBaseTestSuite) GetAuthenticatedSDKTestClientWithLogger(logger *zap.SugaredLogger) (*sdk.Client, error) {
	agent := &relational.Agent{
		Name:     fmt.Sprintf("sdk-agent-%d", time.Now().UnixNano()),
		IsActive: true,
	}
	if err := suite.DB.Create(agent).Error; err != nil {
		return nil, err
	}

	clientSecret := fmt.Sprintf("sdk-secret-%d", time.Now().UnixNano())
	key := &relational.AgentServiceAccountKey{
		AgentID:  agent.ID,
		ClientID: uuid.NewString(),
	}
	if err := key.SetSecret(clientSecret); err != nil {
		return nil, err
	}
	if err := suite.DB.Create(key).Error; err != nil {
		return nil, err
	}

	return sdk.NewClient(http.DefaultClient, &sdk.Config{
		BaseURL: suite.httpServer.URL,
		Logger:  logger,
		AgentAuth: &sdk.AgentAuthConfig{
			ClientID:     key.ClientID,
			ClientSecret: clientSecret,
		},
	}), nil
}

func (suite *IntegrationBaseTestSuite) SetupSuite() {
	ctx := context.Background()

	var err error
	cfg := &config.Config{}
	privKey, pubKey, err := config.GenerateKeyPair(2048)
	suite.NoError(err, "failed to generate RSA key pair")

	cfg.JWTPrivateKey = privKey
	cfg.JWTPublicKey = pubKey
	cfg.StrictDisablePublicAgentEndpoints = true
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
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), cfg, metrics)
	// Create evidence service without a worker service (risk job enqueuing disabled in this test server)
	evidenceService := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)

	// Create services struct for API handlers
	services := &handler.APIServices{
		EvidenceService:      evidenceService,
		RiskEnqueuer:         nil,
		DigestService:        nil,
		WorkflowManager:      nil,
		NotificationEnqueuer: nil,
		DAGExecutor:          nil,
		EvidenceBatchQueue:   &syncEvidenceBatchQueue{},
	}

	handler.RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
	authhandler.RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, metrics, nil, nil)

	suite.Server = server

	suite.httpServer = httptest.NewServer(suite.Server.E())
}

// syncEvidenceBatchQueue processes each evidence batch chunk as soon as it is enqueued,
// standing in for the worker service.
type syncEvidenceBatchQueue struct {
	processor worker.EvidenceBatchProcessor
}

func (q *syncEvidenceBatchQueue) EvidenceBatchesAvailable() error { return nil }

func (q *syncEvidenceBatchQueue) SetEvidenceBatchProcessor(processor worker.EvidenceBatchProcessor) {
	q.processor = processor
}

func (q *syncEvidenceBatchQueue) EnqueueEvidenceBatchChunks(ctx context.Context, batchID uuid.UUID, chunks int) error {
	for chunk := 0; chunk < chunks; chunk++ {
		if err := q.processor.ProcessChunk(ctx, batchID, chunk, true); err != nil {
			return err
		}
	}
	return nil
}

func (suite *IntegrationBaseTestSuite) TearDownSuite() {
	suite.httpServer.Close()
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
