//go:build integration

package tests

import (
	"context"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	postgresContainers "github.com/testcontainers/testcontainers-go/modules/postgres"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const DatabaseName = "_integration_tests.db"

type IntegrationTestSuite struct {
	suite.Suite

	Migrator    *TestMigrator
	DB          *gorm.DB
	dbcontainer *postgresContainers.PostgresContainer // We generate a unique name for each run, so we can run tests concurrently.
}

type TestMigrator struct {
	db *gorm.DB
}

func (t *TestMigrator) Refresh() error {
	err := t.Down()
	if err != nil {
		return err
	}

	err = t.Up()
	if err != nil {
		return err
	}

	return nil
}

func (t *TestMigrator) Up() error {
	return t.db.AutoMigrate(
		&relational.Location{},
		&relational.Party{},
		&relational.BackMatterResource{},
		&relational.BackMatter{},
		&relational.Role{},
		&relational.Revision{},
		&relational.Control{},
		&relational.Group{},
		&relational.ResponsibleParty{},
		&relational.Action{},
		&relational.Metadata{},
		&relational.Catalog{},
		&relational.ControlStatementImplementation{},
		&relational.ImplementedRequirementControlImplementation{},
		&relational.ControlImplementationSet{},
		&relational.ComponentDefinition{},
		&relational.Capability{},
		&relational.DefinedComponent{},
		&relational.Diagram{},
		&relational.DataFlow{},
		&relational.NetworkArchitecture{},
		&relational.AuthorizationBoundary{},
		&relational.InformationType{},
		&relational.SystemInformation{},
		&relational.SystemCharacteristics{},
		&relational.AuthorizedPrivilege{},
		&relational.SystemUser{},
		&relational.LeveragedAuthorization{},
		&relational.SystemComponent{},
		&relational.ImplementedComponent{},
		&relational.InventoryItem{},
		&relational.SystemImplementation{},
		&relational.ControlImplementationResponsibility{},
		&relational.ProvidedControlImplementation{},
		&relational.SatisfiedControlImplementationResponsibility{},
		&relational.Export{},
		&relational.InheritedControlImplementation{},
		&relational.ByComponent{},
		&relational.Statement{},
		&relational.ImplementedRequirement{},
		&relational.ControlImplementation{},
		&relational.SystemSecurityPlan{},
	)
}

func (t *TestMigrator) Down() error {
	return t.db.Migrator().DropTable(
		&relational.Location{},
		&relational.Party{},
		&relational.BackMatterResource{},
		&relational.BackMatter{},
		&relational.Role{},
		&relational.Revision{},
		&relational.Control{},
		&relational.Group{},
		&relational.ResponsibleParty{},
		&relational.Action{},
		&relational.Metadata{},
		&relational.Catalog{},
		&relational.ControlStatementImplementation{},
		&relational.ImplementedRequirementControlImplementation{},
		&relational.ControlImplementationSet{},
		&relational.ComponentDefinition{},
		&relational.Capability{},
		&relational.DefinedComponent{},
		&relational.Diagram{},
		&relational.DataFlow{},
		&relational.NetworkArchitecture{},
		&relational.AuthorizationBoundary{},
		&relational.InformationType{},
		&relational.SystemInformation{},
		&relational.SystemCharacteristics{},
		&relational.AuthorizedPrivilege{},
		&relational.AuthorizationBoundary{},
		&relational.NetworkArchitecture{},
		&relational.DataFlow{},
		&relational.SystemUser{},
		&relational.LeveragedAuthorization{},
		&relational.SystemComponent{},
		&relational.ImplementedComponent{},
		&relational.InventoryItem{},
		&relational.SystemImplementation{},
		&relational.ControlImplementationResponsibility{},
		&relational.ProvidedControlImplementation{},
		&relational.SatisfiedControlImplementationResponsibility{},
		&relational.Export{},
		&relational.InheritedControlImplementation{},
		&relational.ByComponent{},
		&relational.Statement{},
		&relational.ImplementedRequirement{},
		&relational.ControlImplementation{},
		&relational.SystemSecurityPlan{},
		"metadata_responsible_parties",
		"party_locations",
		"party_member_of_organisations",
		"responsible_party_parties",
		"action_responsible_parties",
		"capability_control_implementation_sets",
		"defined_components_control_implementation_sets",
		"authorization_boundary_diagrams",
		"network_architecture_diagrams",
		"data_flow_diagrams",
		"back_matter_resources",
	)
}

func (suite *IntegrationTestSuite) SetupSuite() {
	ctx := context.Background()

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
}

func (suite *IntegrationTestSuite) TearDownSuite() {
	err := testcontainers.TerminateContainer(suite.dbcontainer)
	if err != nil {
		suite.T().Fatal(err)
	}
}
