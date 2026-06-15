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

func (suite *DashboardSuggestionsIntegrationSuite) TestAcceptCreatesOneSSPBoundFilterAndLinksControls() {
	sspID := uuid.New()
	runID := uuid.New()
	catalogID := uuid.New()
	actorID := uuid.New()
	labels := map[string]string{"env": "prod", "repo": "payments-api"}
	hash := suggestionrel.CanonicalLabelSetHash(labels)
	suite.seedSuggestionSSPAndRun(sspID, runID)

	low := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-1", labels, hash, "low name", 0.4, nil)
	high := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-2", labels, hash, "high name", 0.9, nil)

	svc := suggestionrel.NewSuggestionService(suite.DB)
	suite.Require().NoError(svc.Accept(sspID, []uuid.UUID{*low.ID, *high.ID}, actorID))

	var filters []relational.Filter
	suite.Require().NoError(suite.DB.Where("ssp_id = ?", sspID).Find(&filters).Error)
	suite.Require().Len(filters, 1)
	suite.Equal("high name", filters[0].Name)
	filterLabels, ok := suggestionrel.CanonicalizeFilter(filters[0].Filter.Data())
	suite.True(ok)
	suite.Equal(labels, filterLabels)

	var linkCount int64
	suite.Require().NoError(suite.DB.Table("filter_controls").Where("filter_id = ?", filters[0].ID).Count(&linkCount).Error)
	suite.Equal(int64(2), linkCount)

	var accepted []suggestionrel.DashboardSuggestion
	suite.Require().NoError(suite.DB.Where("id IN ?", []uuid.UUID{*low.ID, *high.ID}).Find(&accepted).Error)
	for _, suggestion := range accepted {
		suite.Equal(suggestionrel.DashboardSuggestionStatusAccepted, suggestion.Status)
		suite.Require().NotNil(suggestion.AcceptedFilterID)
		suite.Equal(*filters[0].ID, *suggestion.AcceptedFilterID)
	}

	var eventCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionEvent{}).
		Where("event_type = ?", string(suggestionrel.DashboardSuggestionEventTypeAccepted)).
		Count(&eventCount).Error)
	suite.Equal(int64(2), eventCount)
}

func (suite *DashboardSuggestionsIntegrationSuite) TestAcceptExtendsSameSSPMatchingFilter() {
	sspID := uuid.New()
	runID := uuid.New()
	catalogID := uuid.New()
	actorID := uuid.New()
	labels := map[string]string{"env": "prod"}
	hash := suggestionrel.CanonicalLabelSetHash(labels)
	suite.seedSuggestionSSPAndRun(sspID, runID)

	filter := relational.Filter{Name: "existing", SSPID: &sspID, Filter: datatypes.NewJSONType(suggestionrel.BuildLabelFilter(labels))}
	suite.Require().NoError(suite.DB.Create(&filter).Error)
	suggestion := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-1", labels, hash, "ignored", 0.8, filter.ID)

	svc := suggestionrel.NewSuggestionService(suite.DB)
	suite.Require().NoError(svc.Accept(sspID, []uuid.UUID{*suggestion.ID}, actorID))

	var filterCount int64
	suite.Require().NoError(suite.DB.Model(&relational.Filter{}).Where("ssp_id = ?", sspID).Count(&filterCount).Error)
	suite.Equal(int64(1), filterCount)

	var linkCount int64
	suite.Require().NoError(suite.DB.Table("filter_controls").Where("filter_id = ? AND control_id = ?", filter.ID, "AC-1").Count(&linkCount).Error)
	suite.Equal(int64(1), linkCount)
}

func (suite *DashboardSuggestionsIntegrationSuite) TestInsertExcludesMatchingGlobalFilterAndDoesNotModifyIt() {
	sspID := uuid.New()
	runID := uuid.New()
	catalogID := uuid.New()
	labels := map[string]string{"env": "prod"}
	hash := suggestionrel.CanonicalLabelSetHash(labels)
	suite.seedSuggestionSSPAndRun(sspID, runID)

	global := relational.Filter{Name: "global", Filter: datatypes.NewJSONType(suggestionrel.BuildLabelFilter(labels))}
	suite.Require().NoError(suite.DB.Create(&global).Error)
	suite.Require().NoError(suite.DB.Exec(
		`INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)`,
		global.ID, catalogID, "AC-1",
	).Error)

	svc := suggestionrel.NewSuggestionService(suite.DB)
	result, err := svc.InsertValidatedMappings(runID, sspID, suggestionrel.PromptVersion, []suggestionrel.ValidatedMapping{{
		ControlKey:         suggestionrel.ControlKey(catalogID, "AC-1"),
		LabelSetHash:       hash,
		LabelSet:           labels,
		Action:             suggestionrel.MappingActionNewFilter,
		ProposedFilterName: "new",
		Confidence:         0.8,
		Reasoning:          "matches",
	}}, 10)
	suite.Require().NoError(err)
	suite.Equal(0, result.Inserted)
	suite.Equal(1, result.Excluded)

	var suggestionCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestion{}).Where("run_id = ?", runID).Count(&suggestionCount).Error)
	suite.Zero(suggestionCount)

	var reloaded relational.Filter
	suite.Require().NoError(suite.DB.First(&reloaded, "id = ?", global.ID).Error)
	suite.Nil(reloaded.SSPID)
}

func (suite *DashboardSuggestionsIntegrationSuite) TestAcceptSSPIsolationAndGlobalFiltersStayVisible() {
	sspA := uuid.New()
	sspB := uuid.New()
	runID := uuid.New()
	catalogID := uuid.New()
	actorID := uuid.New()
	labels := map[string]string{"env": "prod"}
	hash := suggestionrel.CanonicalLabelSetHash(labels)
	suite.seedSuggestionSSPAndRun(sspA, runID)
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspB}}).Error)
	global := relational.Filter{Name: "global", Filter: datatypes.NewJSONType(suggestionrel.BuildLabelFilter(map[string]string{"env": "stage"}))}
	suite.Require().NoError(suite.DB.Create(&global).Error)

	suggestion := suite.seedDashboardSuggestion(runID, sspA, catalogID, "AC-1", labels, hash, "ssp-a only", 0.8, nil)
	svc := suggestionrel.NewSuggestionService(suite.DB)
	suite.Require().NoError(svc.Accept(sspA, []uuid.UUID{*suggestion.ID}, actorID))

	var sspBFilterCount int64
	suite.Require().NoError(suite.DB.Model(&relational.Filter{}).Where("ssp_id = ?", sspB).Count(&sspBFilterCount).Error)
	suite.Zero(sspBFilterCount)

	var globalCount int64
	suite.Require().NoError(suite.DB.Model(&relational.Filter{}).Where("id = ? AND ssp_id IS NULL", global.ID).Count(&globalCount).Error)
	suite.Equal(int64(1), globalCount)
}

func (suite *DashboardSuggestionsIntegrationSuite) seedSuggestionSSPAndRun(sspID uuid.UUID, runID uuid.UUID) {
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}).Error)
	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestionRun{
		UUIDModel:       relational.UUIDModel{ID: &runID},
		SSPID:           sspID,
		Status:          "completed",
		Model:           "test-model",
		PromptVersion:   suggestionrel.PromptVersion,
		Scope:           datatypes.JSONMap{"controlKeys": []string{}, "labelSetHashes": []string{}},
		PlannedCalls:    1,
		SuggestionCount: 0,
		Stats:           datatypes.JSONMap{},
	}).Error)
}

func (suite *DashboardSuggestionsIntegrationSuite) seedDashboardSuggestion(
	runID uuid.UUID,
	sspID uuid.UUID,
	catalogID uuid.UUID,
	controlID string,
	labels map[string]string,
	hash string,
	name string,
	confidence float64,
	targetFilterID *uuid.UUID,
) suggestionrel.DashboardSuggestion {
	suggestion := suggestionrel.DashboardSuggestion{
		RunID:              runID,
		SSPID:              sspID,
		ControlCatalogID:   catalogID,
		ControlID:          controlID,
		LabelSet:           datatypes.JSONMap{},
		LabelSetHash:       hash,
		TargetFilterID:     targetFilterID,
		ProposedFilterName: name,
		Reasoning:          "Evidence satisfies the control and belongs to the system.",
		Confidence:         confidence,
		Status:             suggestionrel.DashboardSuggestionStatusPending,
	}
	for key, value := range labels {
		suggestion.LabelSet[key] = value
	}
	suite.Require().NoError(suite.DB.Create(&suggestion).Error)
	return suggestion
}
