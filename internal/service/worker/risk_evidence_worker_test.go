package worker

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newRiskEvidenceWorkerTestDB creates an in-memory SQLite database for testing
func newRiskEvidenceWorkerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Migrate all required models
	require.NoError(t, db.AutoMigrate(
		&relational.Evidence{},
		&relational.Labels{},
		&relational.AssessmentSubject{},
		&relational.SelectSubjectById{},
		&relational.SystemComponent{},
		&relational.SystemImplementation{},
		&relational.InventoryItem{},
		&relational.SystemSecurityPlan{},
		&templates.EvidenceTemplate{},
		&templates.EvidenceTemplateSelectorLabel{},
		&templates.EvidenceTemplateRiskTemplate{},
		&templates.RiskTemplate{},
		&risks.Risk{},
		&risks.RiskEvidenceLink{},
		&risks.RiskSubjectLink{},
		&risks.RiskComponentLink{},
		&risks.RiskControlLink{},
		&risks.RiskEvent{},
	))

	return db
}

// createTestRiskEvidenceWorker creates a worker instance for testing
func createTestRiskEvidenceWorker(t *testing.T) *RiskEvidenceWorker {
	t.Helper()
	db := newRiskEvidenceWorkerTestDB(t)
	logger := zap.NewNop().Sugar()
	return NewRiskEvidenceWorker(db, logger)
}

// createTestEvidence creates a test evidence record
func createTestEvidence(t *testing.T, db *gorm.DB) *relational.Evidence {
	t.Helper()
	evidenceID := uuid.New()
	evidence := &relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evidenceID},
		UUID:      evidenceID,
		Title:     "Test Evidence",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
		Labels: []relational.Labels{
			{Name: "environment", Value: "production"},
			{Name: "category", Value: "security"},
			{Name: "_policy", Value: "test-policy"},
		},
		Props: datatypes.NewJSONSlice([]relational.Prop{
			{Name: "violation_id", Value: "VIOL-001"},
		}),
	}

	require.NoError(t, db.Create(evidence).Error)
	return evidence
}

// createTestRiskTemplate creates a test risk template
func createTestRiskTemplate(t *testing.T, db *gorm.DB) *templates.RiskTemplate {
	t.Helper()
	templateID := uuid.New()
	template := &templates.RiskTemplate{
		UUIDModel:      relational.UUIDModel{ID: &templateID},
		PluginID:       "test-plugin",
		PolicyPackage:  "test-policy",
		Name:           "Test Risk Template",
		Title:          "Test Risk Template",
		Statement:      "Test risk statement",
		IsActive:       true,
		ViolationIDs:   []string{"VIOL-001"},
		LikelihoodHint: stringPtr("medium"),
		ImpactHint:     stringPtr("high"),
	}

	require.NoError(t, db.Create(template).Error)
	return template
}

// createTestSSP creates a test system security plan
func createTestSSP(t *testing.T, db *gorm.DB) *relational.SystemSecurityPlan {
	t.Helper()
	sspID := uuid.New()
	ssp := &relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
	}

	require.NoError(t, db.Create(ssp).Error)
	return ssp
}

func stringPtr(s string) *string {
	return &s
}

// createTestEvidenceWithSSP creates test evidence linked to an SSP via a component + implementation.
// Returns evidence and the SSP.
func createTestEvidenceWithSSP(t *testing.T, db *gorm.DB) (*relational.Evidence, *relational.SystemSecurityPlan) {
	t.Helper()
	ssp := createTestSSP(t, db)

	implID := uuid.New()
	impl := &relational.SystemImplementation{
		UUIDModel:            relational.UUIDModel{ID: &implID},
		SystemSecurityPlanId: *ssp.ID,
	}
	require.NoError(t, db.Create(impl).Error)

	compID := uuid.New()
	component := &relational.SystemComponent{
		UUIDModel:              relational.UUIDModel{ID: &compID},
		SystemImplementationId: *impl.ID,
	}
	require.NoError(t, db.Create(component).Error)

	evidence := createTestEvidence(t, db)
	require.NoError(t, db.Model(evidence).Association("Components").Append(component))

	// Reload to include associations (Props is a JSON column, not a relation — don't Preload it)
	var loaded relational.Evidence
	require.NoError(t, db.Preload("Labels").Preload("Subjects").Preload("Components").First(&loaded, "id = ?", evidence.ID).Error)
	return &loaded, ssp
}

func TestNewRiskEvidenceWorker(t *testing.T) {
	t.Parallel()

	db := newRiskEvidenceWorkerTestDB(t)
	logger := zap.NewNop().Sugar()

	worker := NewRiskEvidenceWorker(db, logger)

	assert.NotNil(t, worker)
	assert.Equal(t, db, worker.db)
	assert.Equal(t, logger, worker.logger)
}

func TestRiskEvidenceWorker_Work_Success(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create test data: risk template and evidence with a component linked to an SSP
	riskTemplate := createTestRiskTemplate(t, worker.db)
	evidence, ssp := createTestEvidenceWithSSP(t, worker.db)

	args := RiskProcessEvidenceFailureArgs{
		EvidenceID:  *evidence.ID,
		EvidenceEnd: "2023-01-01T00:00:00Z",
		Status:      "not-satisfied",
	}

	job := &river.Job[RiskProcessEvidenceFailureArgs]{Args: args}
	err := worker.Work(ctx, job)
	assert.NoError(t, err)

	// Verify a risk was created
	var risk risks.Risk
	require.NoError(t, worker.db.WithContext(ctx).
		Where("ssp_id = ? AND risk_template_id = ?", ssp.ID, riskTemplate.ID).
		First(&risk).Error)
	assert.Equal(t, riskTemplate.Title, risk.Title)
	assert.Equal(t, string(risks.RiskStatusOpen), risk.Status)

	// Verify the evidence link was created
	var link risks.RiskEvidenceLink
	require.NoError(t, worker.db.WithContext(ctx).
		Where("risk_id = ? AND evidence_id = ?", risk.ID, evidence.UUID).
		First(&link).Error)

	// Verify a created event was emitted
	var event risks.RiskEvent
	require.NoError(t, worker.db.WithContext(ctx).
		Where("risk_id = ? AND event_type = ?", risk.ID, string(risks.RiskEventTypeCreated)).
		First(&event).Error)
}

func TestRiskEvidenceWorker_Work_EvidenceNotFound(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create job args with non-existent evidence ID
	args := RiskProcessEvidenceFailureArgs{
		EvidenceID:  uuid.New(),
		EvidenceEnd: "2023-01-01T00:00:00Z",
		Status:      "not-satisfied",
	}

	job := &river.Job[RiskProcessEvidenceFailureArgs]{Args: args}

	// Execute the worker
	err := worker.Work(ctx, job)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load evidence")
}

func TestRiskEvidenceWorker_Work_NoMatchingTemplates(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create evidence with _policy label that won't match any risk templates
	evidence := &relational.Evidence{
		UUIDModel: relational.UUIDModel{},
		UUID:      uuid.New(),
		Title:     "Test Evidence",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
		Labels: []relational.Labels{
			{Name: "_policy", Value: "non-existent-policy"},
		},
	}

	require.NoError(t, worker.db.Create(evidence).Error)

	// Create job args
	args := RiskProcessEvidenceFailureArgs{
		EvidenceID:  *evidence.ID,
		EvidenceEnd: "2023-01-01T00:00:00Z",
		Status:      "not-satisfied",
	}

	job := &river.Job[RiskProcessEvidenceFailureArgs]{Args: args}

	// Execute the worker
	err := worker.Work(ctx, job)

	assert.NoError(t, err) // Should not error, just log and return

	// Verify no risks were created
	var riskCount int64
	require.NoError(t, worker.db.Model(&risks.Risk{}).Count(&riskCount).Error)
	assert.Equal(t, int64(0), riskCount, "no risks should be created when no templates match")

	// Verify no risk links were created
	var linkCount int64
	require.NoError(t, worker.db.Model(&risks.RiskEvidenceLink{}).Count(&linkCount).Error)
	assert.Equal(t, int64(0), linkCount, "no risk links should be created when no templates match")

	// Verify no risk events were created
	var eventCount int64
	require.NoError(t, worker.db.Model(&risks.RiskEvent{}).Count(&eventCount).Error)
	assert.Equal(t, int64(0), eventCount, "no risk events should be created when no templates match")
}

func TestRiskEvidenceWorker_Work_NoComponents_NoRisks(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create risk template
	_ = createTestRiskTemplate(t, worker.db)

	// Evidence with matching _policy label but NO components — no SSPs can be resolved
	evidence := createTestEvidence(t, worker.db)

	args := RiskProcessEvidenceFailureArgs{
		EvidenceID:  *evidence.ID,
		EvidenceEnd: "2023-01-01T00:00:00Z",
		Status:      "not-satisfied",
	}

	job := &river.Job[RiskProcessEvidenceFailureArgs]{Args: args}
	err := worker.Work(ctx, job)

	assert.NoError(t, err)

	// No risks should have been created
	var count int64
	require.NoError(t, worker.db.Model(&risks.Risk{}).Count(&count).Error)
	assert.Equal(t, int64(0), count)
}

func TestRiskEvidenceWorker_Work_PolicyLabelMatch(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create a risk template with a specific policy package
	riskTemplate := createTestRiskTemplate(t, worker.db)

	// Evidence with matching _policy label
	evidence, ssp := createTestEvidenceWithSSP(t, worker.db)

	args := RiskProcessEvidenceFailureArgs{
		EvidenceID:  *evidence.ID,
		EvidenceEnd: "2023-01-01T00:00:00Z",
		Status:      "not-satisfied",
	}

	job := &river.Job[RiskProcessEvidenceFailureArgs]{Args: args}
	err := worker.Work(ctx, job)
	assert.NoError(t, err)

	// Risk must have been created from the matching policy package
	var count int64
	require.NoError(t, worker.db.Model(&risks.Risk{}).
		Where("ssp_id = ? AND risk_template_id = ?", ssp.ID, riskTemplate.ID).
		Count(&count).Error)
	assert.Equal(t, int64(1), count, "risk template with matching policy package should have created a risk")
}

func TestRiskEvidenceWorker_loadEvidenceWithRelations(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create test evidence
	evidence := createTestEvidence(t, worker.db)

	// Load evidence
	loaded, err := worker.loadEvidenceWithRelations(ctx, *evidence.ID)

	assert.NoError(t, err)
	assert.NotNil(t, loaded)
	assert.Equal(t, evidence.ID, loaded.ID)
	assert.Equal(t, evidence.UUID, loaded.UUID)
	assert.Len(t, loaded.Labels, 3) // environment, category, _policy
}

func TestRiskEvidenceWorker_loadEvidenceWithRelations_NotFound(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Try to load non-existent evidence
	nonExistentID := uuid.New()
	_, err := worker.loadEvidenceWithRelations(ctx, nonExistentID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load evidence")
}

func TestRiskEvidenceWorker_loadRiskTemplates(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create test risk template with policy package "test-policy"
	riskTemplate := createTestRiskTemplate(t, worker.db)

	// Create evidence labels with matching _policy label
	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "test-policy"},
	}

	// Load risk templates
	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 1)
	assert.Equal(t, riskTemplate.ID, loaded[0].ID)
}

func TestRiskEvidenceWorker_loadRiskTemplates_NoPolicyLabel(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create evidence labels without _policy label
	evidenceLabels := []relational.Labels{
		{Name: "environment", Value: "production"},
	}

	// Load risk templates
	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 0)
}

func TestRiskEvidenceWorker_loadRiskTemplates_NoMatchingPolicyPackage(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create a risk template with policy package "test-policy"
	_ = createTestRiskTemplate(t, worker.db)

	// Create evidence labels with different _policy label
	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "different-policy"},
	}

	// Load risk templates
	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 0)
}

func TestRiskEvidenceWorker_loadRiskTemplates_MultipleMatchingTemplates(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create multiple risk templates with the same policy package
	template1ID := uuid.New()
	template1 := &templates.RiskTemplate{
		UUIDModel:     relational.UUIDModel{ID: &template1ID},
		PluginID:      "test-plugin",
		PolicyPackage: "shared-policy",
		Name:          "Risk Template 1",
		Title:         "Risk Template 1",
		Statement:     "Test risk statement 1",
		IsActive:      true,
		ViolationIDs:  []string{"VIOL-001"},
	}
	require.NoError(t, worker.db.Create(template1).Error)

	template2ID := uuid.New()
	template2 := &templates.RiskTemplate{
		UUIDModel:     relational.UUIDModel{ID: &template2ID},
		PluginID:      "test-plugin",
		PolicyPackage: "shared-policy",
		Name:          "Risk Template 2",
		Title:         "Risk Template 2",
		Statement:     "Test risk statement 2",
		IsActive:      true,
		ViolationIDs:  []string{"VIOL-002"},
	}
	require.NoError(t, worker.db.Create(template2).Error)

	// Create evidence labels with matching _policy label
	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "shared-policy"},
	}

	// Load risk templates
	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 2)
}

func TestRiskEvidenceWorker_loadRiskTemplates_MultiplePolicyLabels(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create two risk templates with different policy packages
	template1ID := uuid.New()
	template1 := &templates.RiskTemplate{
		UUIDModel:     relational.UUIDModel{ID: &template1ID},
		PluginID:      "test-plugin",
		PolicyPackage: "policy-one",
		Name:          "Risk Template 1",
		Title:         "Risk Template 1",
		Statement:     "Test risk statement 1",
		IsActive:      true,
		ViolationIDs:  []string{"VIOL-001"},
	}
	require.NoError(t, worker.db.Create(template1).Error)

	template2ID := uuid.New()
	template2 := &templates.RiskTemplate{
		UUIDModel:     relational.UUIDModel{ID: &template2ID},
		PluginID:      "test-plugin",
		PolicyPackage: "policy-two",
		Name:          "Risk Template 2",
		Title:         "Risk Template 2",
		Statement:     "Test risk statement 2",
		IsActive:      true,
		ViolationIDs:  []string{"VIOL-002"},
	}
	require.NoError(t, worker.db.Create(template2).Error)

	// Create evidence labels with multiple _policy labels
	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "policy-one"},
		{Name: "_policy", Value: "policy-two"},
	}

	// Load risk templates - should match both
	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 2)
}

func TestRiskEvidenceWorker_loadRiskTemplates_CaseInsensitiveLabelName(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create a risk template
	riskTemplate := createTestRiskTemplate(t, worker.db)

	// Create evidence labels with different case for _policy label name
	evidenceLabels := []relational.Labels{
		{Name: "_POLICY", Value: "test-policy"},
	}

	// Load risk templates - should match despite case difference
	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 1)
	assert.Equal(t, riskTemplate.ID, loaded[0].ID)
}

func TestRiskEvidenceWorker_loadRiskTemplates_WhitespaceTrimming(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create a risk template
	riskTemplate := createTestRiskTemplate(t, worker.db)

	// Create evidence labels with whitespace around value
	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "  test-policy  "},
	}

	// Load risk templates - should match after trimming
	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 1)
	assert.Equal(t, riskTemplate.ID, loaded[0].ID)
}

func TestRiskEvidenceWorker_loadRiskTemplates_DuplicatePolicyLabels(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create a risk template
	riskTemplate := createTestRiskTemplate(t, worker.db)

	// Create evidence labels with duplicate _policy labels (same value)
	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "test-policy"},
		{Name: "_policy", Value: "test-policy"},
		{Name: "_policy", Value: "  test-policy  "}, // With whitespace
	}

	// Load risk templates - should deduplicate and match once
	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 1)
	assert.Equal(t, riskTemplate.ID, loaded[0].ID)
}

func TestRiskEvidenceWorker_loadRiskTemplates_EmptyPolicyValue(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create evidence labels with empty _policy value
	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: ""},
		{Name: "_policy", Value: "   "}, // Only whitespace
	}

	// Load risk templates - should return empty as values are empty/whitespace
	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 0)
}

func TestRiskEvidenceWorker_loadRiskTemplates_CaseInsensitivePolicyValue(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create a risk template with policy package "test-policy"
	riskTemplate := createTestRiskTemplate(t, worker.db)

	// Create evidence labels with different case for _policy value
	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "TEST-POLICY"},
	}

	// Load risk templates - should match despite case difference in value
	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 1)
	assert.Equal(t, riskTemplate.ID, loaded[0].ID)
}

func TestRiskEvidenceWorker_loadRiskTemplates_InactiveTemplatesExcluded(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create an active risk template
	activeTemplateID := uuid.New()
	activeTemplate := &templates.RiskTemplate{
		UUIDModel:     relational.UUIDModel{ID: &activeTemplateID},
		PluginID:      "test-plugin",
		PolicyPackage: "test-policy",
		Name:          "Active Risk Template",
		Title:         "Active Risk Template",
		Statement:     "Test risk statement",
		IsActive:      true,
		ViolationIDs:  []string{"VIOL-001"},
	}
	require.NoError(t, worker.db.Create(activeTemplate).Error)

	// Create an inactive risk template with same policy package
	inactiveTemplateID := uuid.New()
	inactiveTemplate := &templates.RiskTemplate{
		UUIDModel:     relational.UUIDModel{ID: &inactiveTemplateID},
		PluginID:      "test-plugin",
		PolicyPackage: "test-policy",
		Name:          "Inactive Risk Template",
		Title:         "Inactive Risk Template",
		Statement:     "Test risk statement",
		IsActive:      false,
		ViolationIDs:  []string{"VIOL-001"},
	}
	require.NoError(t, worker.db.Create(inactiveTemplate).Error)
	// Explicitly update to ensure IsActive is set to false (SQLite may have default behavior)
	require.NoError(t, worker.db.Model(inactiveTemplate).Update("is_active", false).Error)

	// Create evidence labels with matching _policy label
	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "test-policy"},
	}

	// Load risk templates
	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 1)
	assert.Equal(t, activeTemplateID, *loaded[0].ID)
}

func TestRiskEvidenceWorker_filterRiskTemplatesByViolations(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)

	// Create risk templates
	template1 := &templates.RiskTemplate{
		UUIDModel:    relational.UUIDModel{ID: &uuid.UUID{}},
		ViolationIDs: []string{"VIOL-001"},
		IsActive:     true,
	}

	template2 := &templates.RiskTemplate{
		UUIDModel:    relational.UUIDModel{ID: &uuid.UUID{}},
		ViolationIDs: []string{"VIOL-002"},
		IsActive:     true,
	}

	template3 := &templates.RiskTemplate{
		UUIDModel:    relational.UUIDModel{ID: &uuid.UUID{}},
		ViolationIDs: []string{}, // Empty means match any violation
		IsActive:     true,
	}

	riskTemplates := []templates.RiskTemplate{*template1, *template2, *template3}

	// Create evidence props with violation ID
	evidenceProps := datatypes.NewJSONSlice([]relational.Prop{
		{Name: "violation_id", Value: "VIOL-001"},
	})

	// Filter templates
	filtered, err := worker.filterRiskTemplatesByViolations(riskTemplates, evidenceProps)

	assert.NoError(t, err)
	assert.Len(t, filtered, 2) // template1 and template3 should match
}

func TestRiskEvidenceWorker_extractViolationIDs(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)

	props := datatypes.NewJSONSlice([]relational.Prop{
		{Name: "violation_id", Value: "VIOL-001"},
		{Name: " Violation_ID ", Value: "VIOL-002"},
		{Name: " _VIOLATION_ID ", Value: "VIOL-003"},
		{Name: "other_label", Value: "value"},
		{Name: "violation_id", Value: "   "},
	})

	violationIDs := worker.extractViolationIDs(props)

	assert.Len(t, violationIDs, 3)
	assert.Contains(t, violationIDs, "VIOL-001")
	assert.Contains(t, violationIDs, "VIOL-002")
	assert.Contains(t, violationIDs, "VIOL-003")
}

func TestRiskEvidenceWorker_violationMatches(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)

	templateViolationIDs := []string{"VIOL-001", "VIOL-002"}
	evidenceViolationIDs := []string{"VIOL-001", "VIOL-003"}

	assert.True(t, worker.violationMatches(templateViolationIDs, evidenceViolationIDs))

	// Test no match
	evidenceViolationIDs = []string{"VIOL-003", "VIOL-004"}
	assert.False(t, worker.violationMatches(templateViolationIDs, evidenceViolationIDs))
}

func TestRiskEvidenceWorker_createOrUpdateRisk_CreateNew(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create test data
	ssp := createTestSSP(t, worker.db)
	riskTemplate := createTestRiskTemplate(t, worker.db)

	// Create system implementation linked to SSP
	impl := &relational.SystemImplementation{
		UUIDModel:            relational.UUIDModel{ID: &uuid.UUID{}},
		SystemSecurityPlanId: *ssp.ID,
	}
	*impl.ID = uuid.New()
	require.NoError(t, worker.db.Create(impl).Error)

	// Create component linked to implementation
	component := &relational.SystemComponent{
		UUIDModel:              relational.UUIDModel{ID: &uuid.UUID{}},
		SystemImplementationId: *impl.ID,
	}
	*component.ID = uuid.New()
	require.NoError(t, worker.db.Create(component).Error)

	evidence := createTestEvidence(t, worker.db)

	// Link component to evidence
	require.NoError(t, worker.db.Model(evidence).Association("Components").Append(component))

	// Reload evidence with associations
	var loaded relational.Evidence
	require.NoError(t, worker.db.Preload("Labels").Preload("Subjects").Preload("Components").First(&loaded, "id = ?", evidence.ID).Error)

	// Create new risk
	err := worker.createOrUpdateRisksForSSPs(ctx, *riskTemplate, &loaded)

	assert.NoError(t, err)

	// Verify risk was created with proper SSP (query by ssp+template, dedupe key no longer includes evidence.UUID)
	var risk risks.Risk
	err = worker.db.WithContext(ctx).Where("ssp_id = ? AND risk_template_id = ?", ssp.ID, riskTemplate.ID).First(&risk).Error
	assert.NoError(t, err)
	assert.Equal(t, riskTemplate.Title, risk.Title)
	assert.Equal(t, riskTemplate.Statement, risk.Description)
	assert.Equal(t, risks.RiskStatusOpen, risks.RiskStatus(risk.Status))
	assert.Equal(t, *ssp.ID, risk.SSPID)
}

func TestRiskEvidenceWorker_createOrUpdateRisk_UpdateExisting(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create test data
	ssp := createTestSSP(t, worker.db)
	riskTemplate := createTestRiskTemplate(t, worker.db)

	// Create system implementation linked to SSP
	impl := &relational.SystemImplementation{
		UUIDModel:            relational.UUIDModel{ID: &uuid.UUID{}},
		SystemSecurityPlanId: *ssp.ID,
	}
	*impl.ID = uuid.New()
	require.NoError(t, worker.db.Create(impl).Error)

	// Create component linked to implementation
	component := &relational.SystemComponent{
		UUIDModel:              relational.UUIDModel{ID: &uuid.UUID{}},
		SystemImplementationId: *impl.ID,
	}
	*component.ID = uuid.New()
	require.NoError(t, worker.db.Create(component).Error)

	evidence := createTestEvidence(t, worker.db)

	// Link component to evidence
	require.NoError(t, worker.db.Model(evidence).Association("Components").Append(component))

	// Reload evidence with associations
	var loaded relational.Evidence
	require.NoError(t, worker.db.Preload("Labels").Preload("Subjects").Preload("Components").First(&loaded, "id = ?", evidence.ID).Error)

	// Create existing risk using the new dedupe key format:
	// ssp_id:risk_template_id (no subject IDs appended anymore)
	dedupeKey := fmt.Sprintf("%s:%s", ssp.ID.String(), riskTemplate.ID.String())
	existingRisk := &risks.Risk{
		Title:          "Existing Risk",
		Description:    "Existing description",
		Status:         string(risks.RiskStatusOpen),
		SSPID:          *ssp.ID,
		RiskTemplateID: riskTemplate.ID,
		DedupeKey:      dedupeKey,
		FirstSeenAt:    time.Now().Add(-1 * time.Hour),
		LastSeenAt:     time.Now().Add(-1 * time.Hour),
	}
	require.NoError(t, worker.db.Create(existingRisk).Error)

	// Update risk (should update last_seen_at)
	err := worker.createOrUpdateRisksForSSPs(ctx, *riskTemplate, &loaded)

	assert.NoError(t, err)

	// Verify risk was updated
	var updatedRisk risks.Risk
	err = worker.db.WithContext(ctx).First(&updatedRisk, existingRisk.ID).Error
	assert.NoError(t, err)
	assert.True(t, updatedRisk.LastSeenAt.After(existingRisk.LastSeenAt))
}
func TestRiskEvidenceWorker_createRiskLinks(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create test evidence with subjects and components
	evidence := createTestEvidence(t, worker.db)

	// Create SSP and SystemImplementation for proper component linking
	sspID := uuid.New()
	ssp := &relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
	}
	require.NoError(t, worker.db.Create(ssp).Error)

	systemImplID := uuid.New()
	systemImpl := &relational.SystemImplementation{
		UUIDModel:            relational.UUIDModel{ID: &systemImplID},
		SystemSecurityPlanId: sspID,
	}
	require.NoError(t, worker.db.Create(systemImpl).Error)

	// Add subjects and components to evidence
	subject := &relational.AssessmentSubject{
		UUIDModel: relational.UUIDModel{ID: &uuid.UUID{}},
	}
	*subject.ID = uuid.New()
	require.NoError(t, worker.db.Create(subject).Error)

	componentID := uuid.New()
	component := &relational.SystemComponent{
		UUIDModel:              relational.UUIDModel{ID: &componentID},
		SystemImplementationId: systemImplID,
	}
	require.NoError(t, worker.db.Create(component).Error)

	// Update evidence with subjects and components
	require.NoError(t, worker.db.Model(evidence).Association("Subjects").Append(subject))
	require.NoError(t, worker.db.Model(evidence).Association("Components").Append(component))

	// Reload evidence with associations
	evidence, err := worker.loadEvidenceWithRelations(ctx, *evidence.ID)
	require.NoError(t, err)

	// Create a risk record so FK-backed links can be inserted.
	riskID := uuid.New()
	risk := &risks.Risk{
		UUIDModel:   relational.UUIDModel{ID: &riskID},
		SSPID:       sspID,
		Title:       "Test Risk",
		Description: "Test Description",
		Status:      "open",
		SourceType:  "manual",
		FirstSeenAt: time.Now(),
		LastSeenAt:  time.Now(),
	}
	require.NoError(t, worker.db.Create(risk).Error)

	// Create risk links
	err = worker.createRiskLinks(ctx, worker.db, riskID, sspID, evidence)

	assert.NoError(t, err)

	// Verify evidence link
	var evidenceLink risks.RiskEvidenceLink
	err = worker.db.WithContext(ctx).
		Where("risk_id = ? AND evidence_id = ?", riskID, evidence.UUID).
		First(&evidenceLink).Error
	assert.NoError(t, err)

	// Verify subject link
	var subjectLink risks.RiskSubjectLink
	err = worker.db.WithContext(ctx).
		Where("risk_id = ? AND subject_id = ?", riskID, *subject.ID).
		First(&subjectLink).Error
	assert.NoError(t, err)

	// Verify component link
	var componentLink risks.RiskComponentLink
	err = worker.db.WithContext(ctx).
		Where("risk_id = ? AND component_id = ?", riskID, *component.ID).
		First(&componentLink).Error
	assert.NoError(t, err)
}

func TestRiskEvidenceWorker_createRiskLinks_NoSubjectsOrComponents(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create test evidence without subjects or components
	evidence := createTestEvidence(t, worker.db)

	// Create a risk record so FK-backed links can be inserted.
	sspID := uuid.New()
	riskID := uuid.New()
	risk := &risks.Risk{
		UUIDModel:   relational.UUIDModel{ID: &riskID},
		SSPID:       sspID,
		Title:       "Test Risk",
		Description: "Test Description",
		Status:      "open",
		SourceType:  "manual",
		FirstSeenAt: time.Now(),
		LastSeenAt:  time.Now(),
	}
	require.NoError(t, worker.db.Create(risk).Error)

	// Create risk links
	err := worker.createRiskLinks(ctx, worker.db, riskID, sspID, evidence)

	assert.NoError(t, err)

	// Verify only evidence link was created
	var evidenceLink risks.RiskEvidenceLink
	err = worker.db.WithContext(ctx).
		Where("risk_id = ? AND evidence_id = ?", riskID, evidence.UUID).
		First(&evidenceLink).Error
	assert.NoError(t, err)

	// Verify no subject links
	var subjectLinkCount int64
	err = worker.db.WithContext(ctx).
		Model(&risks.RiskSubjectLink{}).
		Where("risk_id = ?", riskID).
		Count(&subjectLinkCount).Error
	assert.NoError(t, err)
	assert.Equal(t, int64(0), subjectLinkCount)
}

func TestRiskEvidenceWorker_createRiskLinks_MissingEvidenceStreamUUID(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	evidenceID := uuid.New()
	evidence := &relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evidenceID},
		UUID:      uuid.Nil,
		Title:     "invalid evidence",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
	}
	require.NoError(t, worker.db.Create(evidence).Error)

	riskID := uuid.New()
	err := worker.createRiskLinks(ctx, worker.db, riskID, uuid.New(), evidence)
	require.Error(t, err)
	require.ErrorContains(t, err, "missing stream uuid")

	var evidenceLinkCount int64
	require.NoError(t, worker.db.WithContext(ctx).
		Model(&risks.RiskEvidenceLink{}).
		Where("risk_id = ?", riskID).
		Count(&evidenceLinkCount).Error)
	assert.Zero(t, evidenceLinkCount)
}

func TestRiskEvidenceWorker_emitRiskEvent(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create test risk
	riskID := uuid.New()
	eventType := string(risks.RiskEventTypeCreated)
	payload := map[string]interface{}{
		"evidence_id": uuid.New(),
		"template_id": uuid.New(),
	}

	// Emit risk event
	err := worker.emitRiskEvent(ctx, worker.db, riskID, eventType, payload)

	assert.NoError(t, err)

	// Verify the event was created
	var event risks.RiskEvent
	err = worker.db.WithContext(ctx).
		Where("risk_id = ? AND event_type = ?", riskID, eventType).
		First(&event).Error
	assert.NoError(t, err)
	assert.Equal(t, riskID, event.RiskID)
	assert.Equal(t, eventType, event.EventType)
	assert.NotZero(t, event.OccurredAt)
}

func TestRiskEvidenceWorker_emitRiskEvent_DifferentEventTypes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		eventType string
		payload   map[string]interface{}
	}{
		{
			name:      "created event",
			eventType: string(risks.RiskEventTypeCreated),
			payload: map[string]interface{}{
				"evidence_id": uuid.New(),
				"template_id": uuid.New(),
			},
		},
		{
			name:      "last_seen event",
			eventType: string(risks.RiskEventTypeLastSeen),
			payload: map[string]interface{}{
				"evidence_id":        uuid.New(),
				"previous_last_seen": time.Now().Add(-1 * time.Hour),
				"new_last_seen":      time.Now(),
			},
		},
		{
			name:      "custom event",
			eventType: "custom_event",
			payload: map[string]interface{}{
				"custom_field": "custom_value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			worker := createTestRiskEvidenceWorker(t)
			ctx := context.Background()
			riskID := uuid.New()

			err := worker.emitRiskEvent(ctx, worker.db, riskID, tc.eventType, tc.payload)
			assert.NoError(t, err)

			// Verify the event was created
			var event risks.RiskEvent
			err = worker.db.WithContext(ctx).
				Where("risk_id = ? AND event_type = ?", riskID, tc.eventType).
				First(&event).Error
			assert.NoError(t, err)
			assert.Equal(t, riskID, event.RiskID)
			assert.Equal(t, tc.eventType, event.EventType)
		})
	}
}

func TestRiskEvidenceWorker_extractSSPIDsFromComponents(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create test SSP
	ssp := createTestSSP(t, worker.db)

	// Create test system implementation
	impl := &relational.SystemImplementation{
		UUIDModel:            relational.UUIDModel{ID: &uuid.UUID{}},
		SystemSecurityPlanId: *ssp.ID,
	}
	*impl.ID = uuid.New()
	require.NoError(t, worker.db.Create(impl).Error)

	// Create test components with the system implementation ID
	component1 := &relational.SystemComponent{
		UUIDModel:              relational.UUIDModel{ID: &uuid.UUID{}},
		SystemImplementationId: *impl.ID,
	}
	*component1.ID = uuid.New()

	component2 := &relational.SystemComponent{
		UUIDModel:              relational.UUIDModel{ID: &uuid.UUID{}},
		SystemImplementationId: *impl.ID, // Same implementation
	}
	*component2.ID = uuid.New()

	component3 := &relational.SystemComponent{
		UUIDModel:              relational.UUIDModel{ID: &uuid.UUID{}},
		SystemImplementationId: uuid.Nil, // No implementation
	}
	*component3.ID = uuid.New()

	require.NoError(t, worker.db.Create(component1).Error)
	require.NoError(t, worker.db.Create(component2).Error)
	require.NoError(t, worker.db.Create(component3).Error)

	components := []relational.SystemComponent{*component1, *component2, *component3}

	// Extract SSP IDs
	sspIDs, err := worker.extractSSPIDsFromComponents(ctx, components)
	require.NoError(t, err)

	// Should return only one unique SSP ID (from components 1 & 2)
	assert.Len(t, sspIDs, 1)
	assert.Equal(t, *ssp.ID, sspIDs[0])
}

func TestRiskEvidenceWorker_extractSSPIDsFromComponents_NoComponents(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Empty components list
	sspIDs, err := worker.extractSSPIDsFromComponents(ctx, []relational.SystemComponent{})
	require.NoError(t, err)
	assert.Empty(t, sspIDs)
}

func TestRiskEvidenceWorker_extractSSPIDsFromComponents_NoImplementations(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create components without system implementations
	component1 := &relational.SystemComponent{
		UUIDModel:              relational.UUIDModel{ID: &uuid.UUID{}},
		SystemImplementationId: uuid.Nil,
	}
	*component1.ID = uuid.New()

	component2 := &relational.SystemComponent{
		UUIDModel:              relational.UUIDModel{ID: &uuid.UUID{}},
		SystemImplementationId: uuid.Nil,
	}
	*component2.ID = uuid.New()

	require.NoError(t, worker.db.Create(component1).Error)
	require.NoError(t, worker.db.Create(component2).Error)

	components := []relational.SystemComponent{*component1, *component2}

	// Extract SSP IDs
	sspIDs, err := worker.extractSSPIDsFromComponents(ctx, components)
	require.NoError(t, err)
	assert.Empty(t, sspIDs)
}
