//go:build integration

package suggestions_test

import (
	"sync"
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

func (suite *DashboardSuggestionsIntegrationSuite) TestAcceptUsesDeterministicNameTieBreak() {
	sspID := uuid.New()
	runID := uuid.New()
	catalogID := uuid.New()
	actorID := uuid.New()
	labels := map[string]string{"env": "prod"}
	hash := suggestionrel.CanonicalLabelSetHash(labels)
	suite.seedSuggestionSSPAndRun(sspID, runID)

	first := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-1", labels, hash, "z-name", 0.8, nil)
	second := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-2", labels, hash, "a-name", 0.8, nil)

	svc := suggestionrel.NewSuggestionService(suite.DB)
	suite.Require().NoError(svc.Accept(sspID, []uuid.UUID{*first.ID, *second.ID}, actorID))

	var filter relational.Filter
	suite.Require().NoError(suite.DB.First(&filter, "ssp_id = ?", sspID).Error)
	suite.Equal("a-name", filter.Name)
}

func (suite *DashboardSuggestionsIntegrationSuite) TestConcurrentAcceptsCreateOneSSPBoundFilterForSameHash() {
	sspID := uuid.New()
	runID := uuid.New()
	catalogID := uuid.New()
	actorID := uuid.New()
	labels := map[string]string{"env": "prod", "repo": "payments-api"}
	hash := suggestionrel.CanonicalLabelSetHash(labels)
	suite.seedSuggestionSSPAndRun(sspID, runID)

	first := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-1", labels, hash, "first", 0.8, nil)
	second := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-2", labels, hash, "second", 0.7, nil)

	svc := suggestionrel.NewSuggestionService(suite.DB)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for _, suggestionID := range []uuid.UUID{*first.ID, *second.ID} {
		go func(id uuid.UUID) {
			defer wg.Done()
			errs <- svc.Accept(sspID, []uuid.UUID{id}, actorID)
		}(suggestionID)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		suite.Require().NoError(err)
	}

	var filters []relational.Filter
	suite.Require().NoError(suite.DB.Where("ssp_id = ?", sspID).Find(&filters).Error)
	suite.Require().Len(filters, 1)
	filterLabels, ok := suggestionrel.CanonicalizeFilter(filters[0].Filter.Data())
	suite.True(ok)
	suite.Equal(labels, filterLabels)

	var accepted []suggestionrel.DashboardSuggestion
	suite.Require().NoError(suite.DB.Where("id IN ?", []uuid.UUID{*first.ID, *second.ID}).Find(&accepted).Error)
	suite.Require().Len(accepted, 2)
	for _, suggestion := range accepted {
		suite.Equal(suggestionrel.DashboardSuggestionStatusAccepted, suggestion.Status)
		suite.Require().NotNil(suggestion.AcceptedFilterID)
		suite.Equal(*filters[0].ID, *suggestion.AcceptedFilterID)
	}
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

func (suite *DashboardSuggestionsIntegrationSuite) TestMinimalProposedFilterDedupesAndMatchesNewRepositories() {
	sspID := uuid.New()
	runID := uuid.New()
	catalogID := uuid.New()
	actorID := uuid.New()
	suite.seedSuggestionSSPAndRun(sspID, runID)

	subset := map[string]string{
		"_policy":  "secret_scanning_push_protection",
		"provider": "github",
		"type":     "repository",
	}
	firstLabels := map[string]string{
		"_agent":       "agent-1",
		"_plugin":      "github_repos",
		"_policy":      "secret_scanning_push_protection",
		"organization": "compliance-framework",
		"provider":     "github",
		"repository":   "todo-app",
		"team":         "ccf",
		"type":         "repository",
	}
	secondLabels := map[string]string{
		"_agent":       "agent-2",
		"_plugin":      "github_repos",
		"_policy":      "secret_scanning_push_protection",
		"organization": "compliance-framework",
		"provider":     "github",
		"repository":   "payments-api",
		"team":         "ccf",
		"type":         "repository",
	}
	firstHash := suggestionrel.CanonicalLabelSetHash(firstLabels)
	secondHash := suggestionrel.CanonicalLabelSetHash(secondLabels)

	svc := suggestionrel.NewSuggestionService(suite.DB)
	result, err := svc.InsertValidatedMappings(runID, sspID, suggestionrel.PromptVersion, []suggestionrel.ValidatedMapping{
		{
			ControlKey:             suggestionrel.ControlKey(catalogID, "AC-1"),
			LabelSetHash:           firstHash,
			LabelSet:               firstLabels,
			ProposedFilterLabelSet: subset,
			Action:                 suggestionrel.MappingActionNewFilter,
			ProposedFilterName:     "GitHub push protection",
			Confidence:             0.8,
			Reasoning:              "matches",
		},
		{
			ControlKey:             suggestionrel.ControlKey(catalogID, "AC-1"),
			LabelSetHash:           secondHash,
			LabelSet:               secondLabels,
			ProposedFilterLabelSet: subset,
			Action:                 suggestionrel.MappingActionNewFilter,
			ProposedFilterName:     "GitHub push protection",
			Confidence:             0.9,
			Reasoning:              "matches another repo",
		},
	}, 10)
	suite.Require().NoError(err)
	suite.Equal(1, result.Inserted)
	suite.Equal(1, result.Excluded)

	var suggestions []suggestionrel.DashboardSuggestion
	suite.Require().NoError(suite.DB.Where("run_id = ?", runID).Find(&suggestions).Error)
	suite.Require().Len(suggestions, 1)
	suite.Equal(subset, jsonMapToStringMap(suggestions[0].ProposedFilterLabelSet))
	suite.NotEqual(suggestions[0].LabelSetHash, suggestionrel.CanonicalLabelSetHash(subset))
	suite.Contains(jsonMapToStringMap(suggestions[0].LabelSet), "repository")

	suite.Require().NoError(svc.Accept(sspID, []uuid.UUID{*suggestions[0].ID}, actorID))

	var filter relational.Filter
	suite.Require().NoError(suite.DB.First(&filter, "ssp_id = ?", sspID).Error)
	filterLabels, ok := suggestionrel.CanonicalizeFilter(filter.Filter.Data())
	suite.True(ok)
	suite.Equal(subset, filterLabels)

	var linkCount int64
	suite.Require().NoError(suite.DB.Table("filter_controls").Where("filter_id = ? AND control_id = ?", filter.ID, "AC-1").Count(&linkCount).Error)
	suite.Equal(int64(1), linkCount)
	var eventCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionEvent{}).
		Where("suggestion_id = ? AND event_type = ?", suggestions[0].ID, suggestionrel.DashboardSuggestionEventTypeAccepted).
		Count(&eventCount).Error)
	suite.Equal(int64(1), eventCount)

	now := time.Now().UTC()
	suite.insertEvidenceLabels(uuid.New(), uuid.New(), "todo-app", now, firstLabels)
	suite.insertEvidenceLabels(uuid.New(), uuid.New(), "payments-api", now, secondLabels)
	thirdLabels := map[string]string{
		"_agent":       "agent-3",
		"_plugin":      "github_repos",
		"_policy":      "secret_scanning_push_protection",
		"organization": "new-org",
		"provider":     "github",
		"repository":   "future-repo",
		"team":         "new-team",
		"type":         "repository",
	}
	suite.insertEvidenceLabels(uuid.New(), uuid.New(), "future-repo", now, thirdLabels)

	query, err := relational.GetEvidenceSearchByFilterQuery(relational.GetLatestEvidenceStreamsQuery(suite.DB), suite.DB, filter.Filter.Data())
	suite.Require().NoError(err)
	var matched []relational.Evidence
	suite.Require().NoError(query.Find(&matched).Error)
	suite.Require().Len(matched, 3)
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

func (suite *DashboardSuggestionsIntegrationSuite) TestInsertValidatedMappingsRejectsRunSSPMismatch() {
	sspA := uuid.New()
	sspB := uuid.New()
	runID := uuid.New()
	catalogID := uuid.New()
	labels := map[string]string{"env": "prod"}
	hash := suggestionrel.CanonicalLabelSetHash(labels)
	suite.seedSuggestionSSPAndRun(sspA, runID)
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspB}}).Error)

	svc := suggestionrel.NewSuggestionService(suite.DB)
	result, err := svc.InsertValidatedMappings(runID, sspB, suggestionrel.PromptVersion, []suggestionrel.ValidatedMapping{{
		ControlKey:         suggestionrel.ControlKey(catalogID, "AC-1"),
		LabelSetHash:       hash,
		LabelSet:           labels,
		Action:             suggestionrel.MappingActionNewFilter,
		ProposedFilterName: "prod",
		Confidence:         0.8,
		Reasoning:          "matches",
	}}, 10)
	suite.Error(err)
	suite.Equal(suggestionrel.InsertMappingsResult{}, result)

	var suggestionCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestion{}).
		Where("ssp_id IN ?", []uuid.UUID{sspA, sspB}).
		Count(&suggestionCount).Error)
	suite.Zero(suggestionCount)

	var run suggestionrel.DashboardSuggestionRun
	suite.Require().NoError(suite.DB.First(&run, "id = ?", runID).Error)
	suite.Zero(run.SuggestionCount)
}

func (suite *DashboardSuggestionsIntegrationSuite) TestGatherLabelSetsNormalizesAndSkipsCaseVariantDuplicates() {
	sspID := uuid.New()
	runID := uuid.New()
	suite.seedSuggestionSSPAndRun(sspID, runID)

	conflictingEvidenceID := uuid.New()
	conflictingEvidenceUUID := uuid.New()
	now := time.Now().UTC()
	for _, title := range []string{"zeta", "alpha", "gamma", "beta"} {
		suite.insertEvidenceLabels(uuid.New(), uuid.New(), title, now, map[string]string{
			"Env":  "prod",
			"env":  "prod",
			"Repo": "api",
		})
	}
	suite.insertEvidenceLabels(conflictingEvidenceID, conflictingEvidenceUUID, "conflicting", now, map[string]string{
		"Env": "prod",
		"env": "stage",
	})

	normalized := map[string]string{"env": "prod", "repo": "api"}
	hash := suggestionrel.CanonicalLabelSetHash(normalized)
	conflictingHash := suggestionrel.CanonicalLabelSetHash(map[string]string{"Env": "prod", "env": "stage"})
	svc := suggestionrel.NewSuggestionService(suite.DB)

	snapshot, err := svc.ResolveScope(sspID, suggestionrel.Scope{})
	suite.Require().NoError(err)
	suite.Contains(snapshot.LabelSetHashes, hash)
	suite.NotContains(snapshot.LabelSetHashes, conflictingHash)

	input, err := svc.GatherCellInput(sspID, suggestionrel.GridCell{LabelSetHashes: []string{hash}}, suggestionrel.GatherOptions{}, nil)
	suite.Require().NoError(err)
	suite.Require().Len(input.LabelSets, 1)
	suite.Equal(hash, input.LabelSets[0].Hash)
	suite.Equal(normalized, input.LabelSets[0].Labels)
	suite.Equal(4, input.LabelSets[0].EvidenceCount)
	suite.Equal([]string{"alpha", "beta", "gamma"}, input.LabelSets[0].SampleTitles)
}

func (suite *DashboardSuggestionsIntegrationSuite) TestGatherControlsUsesMatchingImplementationWhenSSPHasDuplicateImplementations() {
	sspID := uuid.New()
	runID := uuid.New()
	catalogID := uuid.New()
	profileID := uuid.New()
	controlID := "AC-1"
	suite.seedSuggestionSSPAndRun(sspID, runID)

	suite.Require().NoError(suite.DB.Create(&relational.Profile{UUIDModel: relational.UUIDModel{ID: &profileID}}).Error)
	suite.Require().NoError(suite.DB.Create(&relational.Control{
		CatalogID: catalogID,
		ID:        controlID,
		Title:     "Access Control Policy",
		Parts:     datatypes.NewJSONSlice([]relational.Part{}),
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		`INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)`,
		sspID,
		profileID,
	).Error)
	suite.Require().NoError(suite.DB.Exec(
		`INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)`,
		profileID,
		catalogID,
		controlID,
	).Error)

	emptyImplementationID := uuid.New()
	matchingImplementationID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.ControlImplementation{
		UUIDModel:            relational.UUIDModel{ID: &emptyImplementationID},
		SystemSecurityPlanId: sspID,
	}).Error)
	suite.Require().NoError(suite.DB.Create(&relational.ControlImplementation{
		UUIDModel:            relational.UUIDModel{ID: &matchingImplementationID},
		SystemSecurityPlanId: sspID,
	}).Error)
	suite.Require().NoError(suite.DB.Create(&relational.ImplementedRequirement{
		UUIDModel:               relational.UUIDModel{ID: ptrUUID(uuid.New())},
		ControlImplementationId: matchingImplementationID,
		ControlId:               controlID,
		Remarks:                 "implemented requirement remarks",
	}).Error)

	svc := suggestionrel.NewSuggestionService(suite.DB)
	input, err := svc.GatherCellInput(sspID, suggestionrel.GridCell{
		ControlKeys: []string{suggestionrel.ControlKey(catalogID, controlID)},
	}, suggestionrel.GatherOptions{}, nil)
	suite.Require().NoError(err)
	suite.Require().Len(input.Controls, 1)
	suite.Equal("implemented requirement remarks", input.Controls[0].ImplementationText)
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

func (suite *DashboardSuggestionsIntegrationSuite) TestEditGroupOverridesLabelsAndMembershipThenAccepts() {
	sspID := uuid.New()
	runID := uuid.New()
	catalogID := uuid.New()
	actorID := uuid.New()
	labels := map[string]string{"env": "prod", "repo": "payments-api"}
	hash := suggestionrel.CanonicalLabelSetHash(labels)
	suite.seedSuggestionSSPAndRun(sspID, runID)

	ac1 := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-1", labels, hash, "AI name", 0.8, nil)
	ac2 := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-2", labels, hash, "AI name", 0.7, nil)

	svc := suggestionrel.NewSuggestionService(suite.DB)
	// team=payments is NOT in the evidence label set — a human override.
	editedLabels := map[string]string{"env": "prod", "team": "payments"}
	newName := "Prod payments"
	addKey := suggestionrel.ControlKey(catalogID, "AC-3")
	resultIDs, err := svc.EditGroup(sspID, suggestionrel.EditGroupInput{
		IDs:                []uuid.UUID{*ac1.ID, *ac2.ID},
		ProposedFilterName: &newName,
		Labels:             &editedLabels,
		AddControlKeys:     []string{addKey},
		RemoveIDs:          []uuid.UUID{*ac2.ID},
	}, actorID)
	suite.Require().NoError(err)
	// AC-1 (kept) + AC-3 (added) remain pending; AC-2 was removed.
	suite.Require().Len(resultIDs, 2)

	var kept suggestionrel.DashboardSuggestion
	suite.Require().NoError(suite.DB.First(&kept, "id = ?", ac1.ID).Error)
	suite.True(kept.IsUserEdited)
	suite.False(kept.AddedByUser)
	suite.Require().NotNil(kept.EditedByUserID)
	suite.Equal(newName, kept.ProposedFilterName)
	suite.Equal(editedLabels, jsonMapToStringMap(kept.ProposedFilterLabelSet))
	// The AI baseline is captured for the diff.
	suite.Equal(labels, jsonMapToStringMap(kept.OriginalProposedFilterLabelSet))
	suite.Require().NotNil(kept.OriginalProposedFilterName)
	suite.Equal("AI name", *kept.OriginalProposedFilterName)
	suite.Equal([]string{"AC-2"}, []string(kept.RemovedControlIds))

	var removed suggestionrel.DashboardSuggestion
	suite.Require().NoError(suite.DB.First(&removed, "id = ?", ac2.ID).Error)
	suite.Equal(suggestionrel.DashboardSuggestionStatusRejected, removed.Status)

	var added suggestionrel.DashboardSuggestion
	suite.Require().NoError(suite.DB.First(&added, "ssp_id = ? AND control_id = ? AND status = ?", sspID, "AC-3", suggestionrel.DashboardSuggestionStatusPending).Error)
	suite.True(added.IsUserEdited)
	suite.True(added.AddedByUser)
	suite.Empty(added.OriginalProposedFilterLabelSet)
	suite.Equal([]string{"AC-2"}, []string(added.RemovedControlIds))
	suite.Equal(editedLabels, jsonMapToStringMap(added.ProposedFilterLabelSet))

	// The human-override labels survive Accept: the created filter uses them.
	suite.Require().NoError(svc.Accept(sspID, resultIDs, actorID))
	var filters []relational.Filter
	suite.Require().NoError(suite.DB.Where("ssp_id = ?", sspID).Find(&filters).Error)
	suite.Require().Len(filters, 1)
	suite.Equal(newName, filters[0].Name)
	filterLabels, ok := suggestionrel.CanonicalizeFilter(filters[0].Filter.Data())
	suite.True(ok)
	suite.Equal(editedLabels, filterLabels)

	var linkCount int64
	suite.Require().NoError(suite.DB.Table("filter_controls").Where("filter_id = ?", filters[0].ID).Count(&linkCount).Error)
	suite.Equal(int64(2), linkCount) // AC-1 and AC-3

	var editEvents int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionEvent{}).
		Where("event_type = ?", string(suggestionrel.DashboardSuggestionEventTypeEdited)).
		Count(&editEvents).Error)
	suite.Equal(int64(3), editEvents) // kept + removed + added
}

func (suite *DashboardSuggestionsIntegrationSuite) TestEditGroupRejectsMixedGroups() {
	sspID := uuid.New()
	runID := uuid.New()
	catalogID := uuid.New()
	actorID := uuid.New()
	suite.seedSuggestionSSPAndRun(sspID, runID)

	prodLabels := map[string]string{"env": "prod"}
	stageLabels := map[string]string{"env": "stage"}
	prod := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-1", prodLabels, suggestionrel.CanonicalLabelSetHash(prodLabels), "prod", 0.8, nil)
	stage := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-2", stageLabels, suggestionrel.CanonicalLabelSetHash(stageLabels), "stage", 0.8, nil)

	svc := suggestionrel.NewSuggestionService(suite.DB)
	_, err := svc.EditGroup(sspID, suggestionrel.EditGroupInput{IDs: []uuid.UUID{*prod.ID, *stage.ID}}, actorID)
	var validationErr *suggestionrel.EditValidationError
	suite.Require().ErrorAs(err, &validationErr)
}

func (suite *DashboardSuggestionsIntegrationSuite) TestGatherLabelSetsAppliesEvidenceFilter() {
	now := time.Now().UTC()
	suite.insertEvidenceLabels(uuid.New(), uuid.New(), "prod-1", now, map[string]string{"env": "prod", "provider": "aws"})
	suite.insertEvidenceLabels(uuid.New(), uuid.New(), "prod-2", now, map[string]string{"env": "prod", "provider": "gcp"})
	suite.insertEvidenceLabels(uuid.New(), uuid.New(), "stage-1", now, map[string]string{"env": "stage", "provider": "aws"})

	svc := suggestionrel.NewSuggestionService(suite.DB)

	// No filter → all three label sets.
	all, err := svc.GatherLabelSets(nil, nil)
	suite.Require().NoError(err)
	suite.Len(all, 3)

	// env=prod → only the two prod label sets.
	prodFilter := &labelfilter.Filter{Scope: &labelfilter.Scope{
		Condition: &labelfilter.Condition{Label: "env", Operator: "=", Value: "prod"},
	}}
	prod, err := svc.GatherLabelSets(nil, prodFilter)
	suite.Require().NoError(err)
	suite.Len(prod, 2)
	for _, ls := range prod {
		suite.Equal("prod", ls.Labels["env"])
	}
}

func (suite *DashboardSuggestionsIntegrationSuite) TestSearchLabelValuesMatchesSubstringServerSide() {
	now := time.Now().UTC()
	suite.insertEvidenceLabels(uuid.New(), uuid.New(), "e1", now, map[string]string{"repository": "todo-app"})
	suite.insertEvidenceLabels(uuid.New(), uuid.New(), "e2", now, map[string]string{"repository": "payments-api"})
	suite.insertEvidenceLabels(uuid.New(), uuid.New(), "e3", now, map[string]string{"repository": "todo-worker"})

	svc := suggestionrel.NewSuggestionService(suite.DB)

	// Substring search finds the value regardless of any client-side cap.
	matches, err := svc.SearchLabelValues("repository", "todo", 50)
	suite.Require().NoError(err)
	suite.ElementsMatch([]string{"todo-app", "todo-worker"}, matches)

	// Exact value is reachable, case-insensitively.
	exact, err := svc.SearchLabelValues("REPOSITORY", "todo-app", 50)
	suite.Require().NoError(err)
	suite.Equal([]string{"todo-app"}, exact)

	// Empty key returns nothing.
	none, err := svc.SearchLabelValues("", "todo", 50)
	suite.Require().NoError(err)
	suite.Empty(none)
}

func (suite *DashboardSuggestionsIntegrationSuite) TestGatherLabelKeysReturnsDistinctKeysAndValues() {
	now := time.Now().UTC()
	suite.insertEvidenceLabels(uuid.New(), uuid.New(), "e1", now, map[string]string{"env": "prod", "provider": "aws"})
	suite.insertEvidenceLabels(uuid.New(), uuid.New(), "e2", now, map[string]string{"env": "stage", "provider": "aws"})

	keys, err := suggestionrel.NewSuggestionService(suite.DB).GatherLabelKeys(0)
	suite.Require().NoError(err)

	byKey := map[string][]string{}
	for _, k := range keys {
		byKey[k.Key] = k.Values
	}
	suite.ElementsMatch([]string{"prod", "stage"}, byKey["env"])
	suite.ElementsMatch([]string{"aws"}, byKey["provider"])
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

func (suite *DashboardSuggestionsIntegrationSuite) insertEvidenceLabels(id uuid.UUID, streamUUID uuid.UUID, title string, collectedAt time.Time, labels map[string]string) {
	suite.Require().NoError(suite.DB.Exec(
		`INSERT INTO evidences (id, uuid, title, description, start, "end") VALUES (?, ?, ?, ?, ?, ?)`,
		id,
		streamUUID,
		title,
		title,
		collectedAt,
		collectedAt,
	).Error)
	for key, value := range labels {
		suite.Require().NoError(suite.DB.Exec(
			`INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, ?, ?)`,
			id,
			key,
			value,
		).Error)
	}
}

func (suite *DashboardSuggestionsIntegrationSuite) TestGeneralizeProposesMergeAndAcceptMovesControls() {
	sspID := uuid.New()
	runID := uuid.New()
	catalogID := uuid.New()
	suite.seedSuggestionSSPAndRun(sspID, runID)

	githubLabels := map[string]string{"provider": "github", "type": "repository", "_policy": "scan"}
	gitlabLabels := map[string]string{"provider": "gitlab", "type": "repository", "_policy": "scan"}
	github := relational.Filter{Name: "GitHub repos", SSPID: &sspID, Filter: datatypes.NewJSONType(suggestionrel.BuildLabelFilter(githubLabels))}
	gitlab := relational.Filter{Name: "GitLab repos", SSPID: &sspID, Filter: datatypes.NewJSONType(suggestionrel.BuildLabelFilter(gitlabLabels))}
	suite.Require().NoError(suite.DB.Create(&github).Error)
	suite.Require().NoError(suite.DB.Create(&gitlab).Error)
	for _, filterID := range []*uuid.UUID{github.ID, gitlab.ID} {
		suite.Require().NoError(suite.DB.Exec(
			`INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)`,
			filterID, catalogID, "AC-1",
		).Error)
	}

	svc := suggestionrel.NewSuggestionService(suite.DB)
	run, result, candidates, err := svc.GenerateGeneralizations(sspID, suggestionrel.GeneralizationRunInput{
		Model:                  "test-model",
		PromptVersion:          suggestionrel.PromptVersion,
		GeneralizableLabelKeys: []string{"provider"},
		MinSharedControls:      1,
	})
	suite.Require().NoError(err)
	suite.Equal(1, candidates)
	suite.Equal(1, result.Inserted)
	suite.Equal("completed", run.Status)

	var suggestions []suggestionrel.DashboardSuggestion
	suite.Require().NoError(suite.DB.Where("run_id = ? AND is_generalization = true", run.ID).Find(&suggestions).Error)
	suite.Require().Len(suggestions, 1)
	suite.Equal(map[string]string{"type": "repository", "_policy": "scan"}, jsonMapToStringMap(suggestions[0].ProposedFilterLabelSet))
	suite.Len(suggestions[0].SourceFilterIDs, 2)

	actorID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.User{UUIDModel: relational.UUIDModel{ID: &actorID}, Email: "merge@example.com"}).Error)
	suite.Require().NoError(svc.Accept(sspID, []uuid.UUID{*suggestions[0].ID}, actorID))

	// The generalized filter G now carries the control.
	generalizedLabels := map[string]string{"type": "repository", "_policy": "scan"}
	generalizedHash := suggestionrel.CanonicalLabelSetHash(generalizedLabels)
	var sspFilters []relational.Filter
	suite.Require().NoError(suite.DB.Where("ssp_id = ?", sspID).Find(&sspFilters).Error)
	var generalized *relational.Filter
	for i := range sspFilters {
		labels, ok := suggestionrel.CanonicalizeFilter(sspFilters[i].Filter.Data())
		if ok && suggestionrel.CanonicalLabelSetHash(labels) == generalizedHash {
			generalized = &sspFilters[i]
		}
	}
	suite.Require().NotNil(generalized)

	var generalizedLinks int64
	suite.Require().NoError(suite.DB.Table("filter_controls").Where("filter_id = ?", generalized.ID).Count(&generalizedLinks).Error)
	suite.Equal(int64(1), generalizedLinks)

	// The control is moved off both source filters (not double-counted).
	var sourceLinks int64
	suite.Require().NoError(suite.DB.Table("filter_controls").
		Where("filter_id IN ? AND control_id = ?", []uuid.UUID{*github.ID, *gitlab.ID}, "AC-1").
		Count(&sourceLinks).Error)
	suite.Equal(int64(0), sourceLinks)
}

func jsonMapToStringMap(values datatypes.JSONMap) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		if stringValue, ok := value.(string); ok {
			out[key] = stringValue
		}
	}
	return out
}

func ptrUUID(id uuid.UUID) *uuid.UUID {
	return &id
}
