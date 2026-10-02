//go:build integration

package service_test

import (
	"testing"

	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
)

type MigratorIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func TestMigratorIntegration(t *testing.T) {
	suite.Run(t, new(MigratorIntegrationSuite))
}

func (s *MigratorIntegrationSuite) SetupTest() {
	s.Require().NoError(s.Migrator.Refresh())
}

func (s *MigratorIntegrationSuite) primaryKeyColumns(table string) []string {
	var columns []string
	s.Require().NoError(s.DB.Raw(`
		SELECT a.attname
		FROM pg_index i
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
		WHERE i.indrelid = ?::regclass AND i.indisprimary
		ORDER BY array_position(i.indkey::int2[], a.attnum)
	`, table).Scan(&columns).Error)
	return columns
}

func (s *MigratorIntegrationSuite) TestComponentDefinitionIdentityKeyIsPerPlugin() {
	perPluginKey := []string{"entity_type", "component_definition_id", "identity_hash"}

	// A freshly migrated database gets the per-plugin key from the model.
	s.Equal(perPluginKey, s.primaryKeyColumns("component_definition_identities"))

	// An existing database still has the original (entity_type, identity_hash) key.
	s.Require().NoError(s.DB.Exec(`DROP TABLE component_definition_identities`).Error)
	s.Require().NoError(s.DB.Exec(`
		CREATE TABLE component_definition_identities (
		  entity_type text NOT NULL,
		  identity_hash char(64) NOT NULL,
		  component_definition_id uuid NOT NULL,
		  defined_component_id uuid NOT NULL,
		  PRIMARY KEY (entity_type, identity_hash)
		)
	`).Error)
	insert := `INSERT INTO component_definition_identities
		(entity_type, identity_hash, component_definition_id, defined_component_id) VALUES (?, ?, ?, ?)`
	hashA := "aa" + uuid.NewString()[:30] + uuid.NewString()[:32]
	hashB := "bb" + uuid.NewString()[:30] + uuid.NewString()[:32]
	pluginA := uuid.New()
	s.Require().NoError(s.DB.Exec(insert, "component", hashA, pluginA, uuid.New()).Error)
	s.Require().NoError(s.DB.Exec(insert, "component", hashB, pluginA, uuid.New()).Error)

	s.Require().NoError(service.MigrateComponentDefinitionIdentityKey(s.DB))

	s.Equal(perPluginKey, s.primaryKeyColumns("component_definition_identities"))
	var count int64
	s.Require().NoError(s.DB.Raw(`SELECT count(*) FROM component_definition_identities`).Scan(&count).Error)
	s.Equal(int64(2), count, "existing identities are kept")

	// A second plugin can now record the same identity.
	s.Require().NoError(s.DB.Exec(insert, "component", hashA, uuid.New(), uuid.New()).Error)

	// Running it again is a no-op.
	s.Require().NoError(service.MigrateComponentDefinitionIdentityKey(s.DB))
	s.Equal(perPluginKey, s.primaryKeyColumns("component_definition_identities"))
}
