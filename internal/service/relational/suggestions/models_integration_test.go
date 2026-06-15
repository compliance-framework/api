//go:build integration

package suggestions_test

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	suggestionrel "github.com/compliance-framework/api/internal/service/relational/suggestions"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"gorm.io/datatypes"
)

type DashboardSuggestionsIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func TestDashboardSuggestionsIntegrationSuite(t *testing.T) {
	suite.Run(t, new(DashboardSuggestionsIntegrationSuite))
}

func (suite *DashboardSuggestionsIntegrationSuite) SetupTest() {
	suite.Require().NoError(suite.Migrator.Refresh())
}

func (suite *DashboardSuggestionsIntegrationSuite) TestMigrateUpDownAndExistingFiltersStayGlobal() {
	suite.Require().NoError(suite.Migrator.Down())

	filterID := uuid.New()
	suite.Require().NoError(suite.DB.Exec(`
		CREATE TABLE filters (
			id uuid PRIMARY KEY,
			name text,
			filter jsonb
		)
	`).Error)
	suite.Require().NoError(suite.DB.Exec(
		`INSERT INTO filters (id, name, filter) VALUES (?, ?, ?::jsonb)`,
		filterID, "legacy global filter", "{}",
	).Error)

	suite.Require().NoError(service.MigrateUp(suite.DB))

	for _, table := range []string{
		"dashboard_suggestion_runs",
		"dashboard_suggestion_run_cells",
		"dashboard_suggestions",
		"dashboard_suggestion_events",
	} {
		suite.True(suite.DB.Migrator().HasTable(table), "expected table %s to exist", table)
	}
	suite.True(suite.DB.Migrator().HasColumn(&relational.Filter{}, "ssp_id"))

	var globalCount int64
	suite.Require().NoError(suite.DB.
		Table("filters").
		Where("id = ? AND ssp_id IS NULL", filterID).
		Count(&globalCount).Error)
	suite.Equal(int64(1), globalCount)

	for _, indexName := range []string{
		"idx_dashboard_suggestions_unique_pending",
		"idx_dashboard_suggestion_runs_unique_active",
	} {
		var exists bool
		suite.Require().NoError(suite.DB.
			Raw("SELECT to_regclass(?) IS NOT NULL", indexName).
			Scan(&exists).Error)
		suite.True(exists, "expected index %s to exist", indexName)
	}

	suite.Require().NoError(service.MigrateDown(suite.DB))
	for _, table := range []string{
		"dashboard_suggestion_runs",
		"dashboard_suggestion_run_cells",
		"dashboard_suggestions",
		"dashboard_suggestion_events",
	} {
		suite.False(suite.DB.Migrator().HasTable(table), "expected table %s to be dropped", table)
	}
}

func (suite *DashboardSuggestionsIntegrationSuite) TestDeletingSSPCascadesBoundFiltersOnly() {
	sspID := uuid.New()
	ssp := relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
	}
	suite.Require().NoError(suite.DB.Create(&ssp).Error)

	boundFilter := relational.Filter{
		Name:   "ssp-bound filter",
		SSPID:  &sspID,
		Filter: datatypes.NewJSONType(labelfilter.Filter{}),
	}
	globalFilter := relational.Filter{
		Name:   "global filter",
		Filter: datatypes.NewJSONType(labelfilter.Filter{}),
	}
	suite.Require().NoError(suite.DB.Create(&boundFilter).Error)
	suite.Require().NoError(suite.DB.Create(&globalFilter).Error)

	suite.Require().NoError(suite.DB.Delete(&relational.SystemSecurityPlan{}, "id = ?", sspID).Error)

	var boundCount int64
	suite.Require().NoError(suite.DB.
		Model(&relational.Filter{}).
		Where("id = ?", boundFilter.ID).
		Count(&boundCount).Error)
	suite.Zero(boundCount)

	var globalCount int64
	suite.Require().NoError(suite.DB.
		Model(&relational.Filter{}).
		Where("id = ?", globalFilter.ID).
		Count(&globalCount).Error)
	suite.Equal(int64(1), globalCount)
}

func (suite *DashboardSuggestionsIntegrationSuite) TestDeletingRunCascadesCellsAndSuggestions() {
	runID := uuid.New()
	sspID := uuid.New()
	catalogID := uuid.New()
	run := suggestionrel.DashboardSuggestionRun{
		UUIDModel:     relational.UUIDModel{ID: &runID},
		SSPID:         sspID,
		Status:        "completed",
		Model:         "test-model",
		PromptVersion: "v1",
		Scope:         datatypes.JSONMap{"controlKeys": []string{"ac-1"}, "labelSetHashes": []string{"hash"}},
		Stats:         datatypes.JSONMap{},
	}
	suite.Require().NoError(suite.DB.Create(&run).Error)
	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestionRunCell{
		RunID:          runID,
		CellIndex:      0,
		ControlKeys:    datatypes.NewJSONSlice([]string{"ac-1"}),
		LabelSetHashes: datatypes.NewJSONSlice([]string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}),
		Status:         "completed",
	}).Error)
	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestion{
		RunID:              runID,
		SSPID:              sspID,
		ControlCatalogID:   catalogID,
		ControlID:          "ac-1",
		LabelSet:           datatypes.JSONMap{"plugin": "aws"},
		LabelSetHash:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ProposedFilterName: "aws-ac-1",
		Reasoning:          "Evidence labels match the control context.",
		Confidence:         0.8,
		Status:             "pending",
	}).Error)

	suite.Require().NoError(suite.DB.Delete(&suggestionrel.DashboardSuggestionRun{}, "id = ?", runID).Error)

	var cellCount int64
	suite.Require().NoError(suite.DB.
		Model(&suggestionrel.DashboardSuggestionRunCell{}).
		Where("run_id = ?", runID).
		Count(&cellCount).Error)
	suite.Zero(cellCount)

	var suggestionCount int64
	suite.Require().NoError(suite.DB.
		Model(&suggestionrel.DashboardSuggestion{}).
		Where("run_id = ?", runID).
		Count(&suggestionCount).Error)
	suite.Zero(suggestionCount)
}

func (suite *DashboardSuggestionsIntegrationSuite) TestDashboardSuggestionEventsAreAppendOnly() {
	details := "Dashboard suggestion run started."
	event := suggestionrel.DashboardSuggestionEvent{
		EventType:  string(suggestionrel.DashboardSuggestionEventTypeRunStarted),
		OccurredAt: time.Now().UTC(),
		Details:    &details,
		Payload:    datatypes.JSONMap{"model": "test-model"},
		Snapshot:   datatypes.JSONMap{},
	}
	suite.Require().NoError(suite.DB.Create(&event).Error)

	suite.Error(suite.DB.Model(&event).Update("details", "changed").Error)
	suite.Error(suite.DB.Delete(&event).Error)
}

func (suite *DashboardSuggestionsIntegrationSuite) TestDashboardSuggestionReasoningIsRequired() {
	runID := uuid.New()
	sspID := uuid.New()
	catalogID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestionRun{
		UUIDModel:     relational.UUIDModel{ID: &runID},
		SSPID:         sspID,
		Status:        "completed",
		Model:         "test-model",
		PromptVersion: "v1",
		Scope:         datatypes.JSONMap{"controlKeys": []string{}, "labelSetHashes": []string{}},
		Stats:         datatypes.JSONMap{},
	}).Error)

	err := suite.DB.Exec(`
		INSERT INTO dashboard_suggestions (
			id,
			run_id,
			ssp_id,
			control_catalog_id,
			control_id,
			label_set,
			label_set_hash,
			proposed_filter_name,
			confidence,
			status
		) VALUES (?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?)
	`,
		uuid.New(),
		runID,
		sspID,
		catalogID,
		"ac-1",
		`{"plugin":"aws"}`,
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"aws-ac-1",
		0.8,
		"pending",
	).Error
	suite.Error(err)
}
