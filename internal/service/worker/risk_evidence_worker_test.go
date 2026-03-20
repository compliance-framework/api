package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/compliance-framework/api/internal/service/relational/templates"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
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
		&relational.ControlImplementation{},
		&relational.ImplementedRequirement{},
		&templates.RiskTemplate{},
		&templates.RiskTemplateThreatRef{},
		&templates.RemediationTemplate{},
		&templates.RemediationTask{},
		&risks.Risk{},
		&risks.RiskEvidenceLink{},
		&risks.RiskSubjectLink{},
		&risks.RiskComponentLink{},
		&risks.RiskControlLink{},
		&risks.RiskThreatRef{},
		&risks.RiskRemediationTemplate{},
		&risks.RiskRemediationTask{},
		&risks.RiskEvent{},
	))

	// Manually create filter-related tables (avoid full AutoMigrate of Filter model which may
	// pull in complex dependencies)
	require.NoError(t, db.Exec(`CREATE TABLE IF NOT EXISTS filters (
		id TEXT PRIMARY KEY,
		created_at DATETIME,
		updated_at DATETIME,
		deleted_at DATETIME,
		name TEXT,
		filter JSON
	)`).Error)

	require.NoError(t, db.Exec(`CREATE TABLE IF NOT EXISTS filter_controls (
		filter_id TEXT,
		control_catalog_id TEXT,
		control_id TEXT
	)`).Error)

	require.NoError(t, db.Exec(`CREATE TABLE IF NOT EXISTS profiles (
		id TEXT PRIMARY KEY,
		created_at DATETIME,
		updated_at DATETIME,
		deleted_at DATETIME
	)`).Error)

	require.NoError(t, db.Exec(`CREATE TABLE IF NOT EXISTS profile_controls (
		profile_id TEXT,
		control_catalog_id TEXT,
		control_id TEXT
	)`).Error)

	return db
}

// createTestRiskEvidenceWorker creates a worker instance for testing
func createTestRiskEvidenceWorker(t *testing.T) *RiskEvidenceWorker {
	t.Helper()
	db := newRiskEvidenceWorkerTestDB(t)
	logger := zap.NewNop().Sugar()
	return NewRiskEvidenceWorker(db, logger)
}

// createTestEvidence creates a test evidence record with not-satisfied status
func createTestEvidence(t *testing.T, db *gorm.DB) *relational.Evidence {
	t.Helper()
	evidenceID := uuid.New()
	evidence := &relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evidenceID},
		UUID:      evidenceID,
		Title:     "Test Evidence",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
		Status:    datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied"}),
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

// seedFilterForControl creates a Filter with a simple label condition and links it to a control.
// Returns the filter ID.
func seedFilterForControl(t *testing.T, db *gorm.DB, controlCatalogID uuid.UUID, controlID, labelKey, labelValue string) uuid.UUID {
	t.Helper()
	filterID := uuid.New()

	filterScope := labelfilter.Filter{
		Scope: &labelfilter.Scope{
			Condition: &labelfilter.Condition{
				Label:    labelKey,
				Operator: "=",
				Value:    labelValue,
			},
		},
	}
	filterJSON, err := json.Marshal(filterScope)
	require.NoError(t, err)

	require.NoError(t, db.Exec(
		`INSERT INTO filters (id, name, filter) VALUES (?, ?, ?)`,
		filterID.String(), "test-filter", string(filterJSON),
	).Error)

	require.NoError(t, db.Exec(
		`INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)`,
		filterID.String(), controlCatalogID.String(), controlID,
	).Error)

	return filterID
}

// createTestSSPWithControl creates an SSP with a Profile (linked via profile_controls to the
// given catalog+control), a ControlImplementation, and an ImplementedRequirement. Returns the SSP.
func createTestSSPWithControl(t *testing.T, db *gorm.DB, catalogID uuid.UUID, controlID string) *relational.SystemSecurityPlan {
	t.Helper()

	// Create a profile and link it to the control via profile_controls.
	profileID := uuid.New()
	require.NoError(t, db.Exec(
		`INSERT INTO profiles (id) VALUES (?)`, profileID.String(),
	).Error)
	require.NoError(t, db.Exec(
		`INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)`,
		profileID.String(), catalogID.String(), controlID,
	).Error)

	// Create SSP linked to the profile.
	sspID := uuid.New()
	ssp := &relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
		ProfileID: &profileID,
	}
	require.NoError(t, db.Create(ssp).Error)

	ciID := uuid.New()
	ci := &relational.ControlImplementation{
		UUIDModel:            relational.UUIDModel{ID: &ciID},
		SystemSecurityPlanId: *ssp.ID,
		Description:          "Test control implementation",
	}
	require.NoError(t, db.Create(ci).Error)

	irID := uuid.New()
	ir := &relational.ImplementedRequirement{
		UUIDModel:               relational.UUIDModel{ID: &irID},
		ControlImplementationId: ciID,
		ControlId:               controlID,
	}
	require.NoError(t, db.Create(ir).Error)

	return ssp
}

// createTestEvidenceWithFilterPath creates evidence with labels matching a filter that links to an SSP.
// Returns the evidence and SSP.
func createTestEvidenceWithFilterPath(t *testing.T, db *gorm.DB) (*relational.Evidence, *relational.SystemSecurityPlan) {
	t.Helper()

	catalogID := uuid.New()
	controlID := "AC-1"

	// Create filter matching evidence labels
	seedFilterForControl(t, db, catalogID, controlID, "environment", "production")

	// Create SSP with Profile + ControlImplementation + ImplementedRequirement for the same control
	ssp := createTestSSPWithControl(t, db, catalogID, controlID)

	// Create evidence with matching labels
	evidence := createTestEvidence(t, db)

	// Reload with relations
	var loaded relational.Evidence
	require.NoError(t, db.Preload("Labels").Preload("Subjects").First(&loaded, "id = ?", evidence.ID).Error)
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

	// Create test data: risk template, evidence with filter path to SSP
	riskTemplate := createTestRiskTemplate(t, worker.db)
	evidence, ssp := createTestEvidenceWithFilterPath(t, worker.db)

	args := RiskProcessEvidenceArgs{
		EvidenceID:  *evidence.ID,
		EvidenceEnd: "2023-01-01T00:00:00Z",
		Status:      "not-satisfied",
	}

	job := &river.Job[RiskProcessEvidenceArgs]{Args: args}
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

	// Verify control link was created
	var controlLink risks.RiskControlLink
	require.NoError(t, worker.db.WithContext(ctx).
		Where("risk_id = ?", risk.ID).
		First(&controlLink).Error)
	assert.Equal(t, "AC-1", controlLink.ControlID)

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

	args := RiskProcessEvidenceArgs{
		EvidenceID:  uuid.New(),
		EvidenceEnd: "2023-01-01T00:00:00Z",
		Status:      "not-satisfied",
	}

	job := &river.Job[RiskProcessEvidenceArgs]{Args: args}
	err := worker.Work(ctx, job)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load evidence")
}

func TestRiskEvidenceWorker_Work_NoMatchingTemplates(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create evidence with filter path but _policy label that won't match any templates
	catalogID := uuid.New()
	seedFilterForControl(t, worker.db, catalogID, "AC-1", "environment", "production")
	createTestSSPWithControl(t, worker.db, catalogID, "AC-1")

	evidence := &relational.Evidence{
		UUIDModel: relational.UUIDModel{},
		UUID:      uuid.New(),
		Title:     "Test Evidence",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
		Labels: []relational.Labels{
			{Name: "environment", Value: "production"},
			{Name: "_policy", Value: "non-existent-policy"},
		},
	}
	require.NoError(t, worker.db.Create(evidence).Error)

	args := RiskProcessEvidenceArgs{
		EvidenceID:  *evidence.ID,
		EvidenceEnd: "2023-01-01T00:00:00Z",
		Status:      "not-satisfied",
	}

	job := &river.Job[RiskProcessEvidenceArgs]{Args: args}
	err := worker.Work(ctx, job)

	assert.NoError(t, err)

	// Verify no risks were created
	var riskCount int64
	require.NoError(t, worker.db.Model(&risks.Risk{}).Count(&riskCount).Error)
	assert.Equal(t, int64(0), riskCount)
}

func TestRiskEvidenceWorker_Work_NoFiltersMatch(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create risk template
	_ = createTestRiskTemplate(t, worker.db)

	// Evidence with labels that don't match any filter — no SSPs resolved
	evidence := createTestEvidence(t, worker.db)

	args := RiskProcessEvidenceArgs{
		EvidenceID:  *evidence.ID,
		EvidenceEnd: "2023-01-01T00:00:00Z",
		Status:      "not-satisfied",
	}

	job := &river.Job[RiskProcessEvidenceArgs]{Args: args}
	err := worker.Work(ctx, job)

	assert.NoError(t, err)

	// No risks should have been created
	var count int64
	require.NoError(t, worker.db.Model(&risks.Risk{}).Count(&count).Error)
	assert.Equal(t, int64(0), count)
}

func TestRiskEvidenceWorker_Work_SatisfiedEvidence_NoRisks(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create SSP with filter path
	catalogID := uuid.New()
	seedFilterForControl(t, worker.db, catalogID, "AC-1", "environment", "production")
	createTestSSPWithControl(t, worker.db, catalogID, "AC-1")

	// Create risk template
	_ = createTestRiskTemplate(t, worker.db)

	// Create evidence with "satisfied" status
	evidenceID := uuid.New()
	evidence := &relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evidenceID},
		UUID:      evidenceID,
		Title:     "Satisfied Evidence",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
		Labels: []relational.Labels{
			{Name: "environment", Value: "production"},
			{Name: "_policy", Value: "test-policy"},
		},
	}
	require.NoError(t, worker.db.Create(evidence).Error)

	args := RiskProcessEvidenceArgs{
		EvidenceID:  evidenceID,
		EvidenceEnd: "2023-01-01T00:00:00Z",
		Status:      "satisfied",
	}

	job := &river.Job[RiskProcessEvidenceArgs]{Args: args}
	err := worker.Work(ctx, job)

	assert.NoError(t, err)

	// No risks should be created for satisfied evidence
	var count int64
	require.NoError(t, worker.db.Model(&risks.Risk{}).Count(&count).Error)
	assert.Equal(t, int64(0), count)
}

func TestRiskEvidenceWorker_Work_PolicyLabelMatch(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	riskTemplate := createTestRiskTemplate(t, worker.db)
	evidence, ssp := createTestEvidenceWithFilterPath(t, worker.db)

	args := RiskProcessEvidenceArgs{
		EvidenceID:  *evidence.ID,
		EvidenceEnd: "2023-01-01T00:00:00Z",
		Status:      "not-satisfied",
	}

	job := &river.Job[RiskProcessEvidenceArgs]{Args: args}
	err := worker.Work(ctx, job)
	assert.NoError(t, err)

	// Risk must have been created from the matching policy package
	var count int64
	require.NoError(t, worker.db.Model(&risks.Risk{}).
		Where("ssp_id = ? AND risk_template_id = ?", ssp.ID, riskTemplate.ID).
		Count(&count).Error)
	assert.Equal(t, int64(1), count)
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

	nonExistentID := uuid.New()
	_, err := worker.loadEvidenceWithRelations(ctx, nonExistentID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load evidence")
}

func TestRiskEvidenceWorker_loadRiskTemplates(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	riskTemplate := createTestRiskTemplate(t, worker.db)

	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "test-policy"},
	}

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

	evidenceLabels := []relational.Labels{
		{Name: "environment", Value: "production"},
	}

	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 0)
}

func TestRiskEvidenceWorker_loadRiskTemplates_NoMatchingPolicyPackage(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	_ = createTestRiskTemplate(t, worker.db)

	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "different-policy"},
	}

	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 0)
}

func TestRiskEvidenceWorker_loadRiskTemplates_MultipleMatchingTemplates(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

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

	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "shared-policy"},
	}

	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 2)
}

func TestRiskEvidenceWorker_loadRiskTemplates_MultiplePolicyLabels(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

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

	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "policy-one"},
		{Name: "_policy", Value: "policy-two"},
	}

	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 2)
}

func TestRiskEvidenceWorker_loadRiskTemplates_CaseInsensitiveLabelName(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	riskTemplate := createTestRiskTemplate(t, worker.db)

	evidenceLabels := []relational.Labels{
		{Name: "_POLICY", Value: "test-policy"},
	}

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

	riskTemplate := createTestRiskTemplate(t, worker.db)

	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "  test-policy  "},
	}

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

	riskTemplate := createTestRiskTemplate(t, worker.db)

	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "test-policy"},
		{Name: "_policy", Value: "test-policy"},
		{Name: "_policy", Value: "  test-policy  "},
	}

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

	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: ""},
		{Name: "_policy", Value: "   "},
	}

	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 0)
}

func TestRiskEvidenceWorker_loadRiskTemplates_CaseInsensitivePolicyValue(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	riskTemplate := createTestRiskTemplate(t, worker.db)

	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "TEST-POLICY"},
	}

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
	require.NoError(t, worker.db.Model(inactiveTemplate).Update("is_active", false).Error)

	evidenceLabels := []relational.Labels{
		{Name: "_policy", Value: "test-policy"},
	}

	evidenceID := uuid.New()
	loaded, err := worker.loadRiskTemplates(ctx, evidenceLabels, evidenceID)

	assert.NoError(t, err)
	assert.Len(t, loaded, 1)
	assert.Equal(t, activeTemplateID, *loaded[0].ID)
}

func TestRiskEvidenceWorker_filterRiskTemplatesByViolations(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)

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
		ViolationIDs: []string{},
		IsActive:     true,
	}

	riskTemplates := []templates.RiskTemplate{*template1, *template2, *template3}

	evidenceProps := datatypes.NewJSONSlice([]relational.Prop{
		{Name: "violation_id", Value: "VIOL-001"},
	})

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

	evidenceViolationIDs = []string{"VIOL-003", "VIOL-004"}
	assert.False(t, worker.violationMatches(templateViolationIDs, evidenceViolationIDs))
}

func TestRiskEvidenceWorker_createOrUpdateRisk_CreateNew(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	ssp := createTestSSP(t, worker.db)
	riskTemplate := createTestRiskTemplate(t, worker.db)
	require.NoError(t, worker.db.Create(&templates.RiskTemplateThreatRef{
		RiskTemplateID: *riskTemplate.ID,
		System:         "CWE",
		ExternalID:     "79",
		Title:          "Cross-site scripting",
	}).Error)
	remediation := templates.RemediationTemplate{
		Title:       "Fix template issue",
		Description: stringPtr("Apply secure encoding"),
	}
	require.NoError(t, worker.db.Create(&remediation).Error)
	require.NoError(t, worker.db.Create(&templates.RemediationTask{
		RemediationTemplateID: *remediation.ID,
		Title:                 "Patch code",
		OrderIndex:            1,
	}).Error)
	require.NoError(t, worker.db.Model(&templates.RiskTemplate{}).Where("id = ?", riskTemplate.ID).Update("remediation_template_id", remediation.ID).Error)
	require.NoError(t, worker.db.
		Preload("ThreatRefs").
		Preload("RemediationTemplate").
		Preload("RemediationTemplate.Tasks").
		First(riskTemplate, "id = ?", riskTemplate.ID).Error)

	evidence := createTestEvidence(t, worker.db)

	catalogID := uuid.New()
	sspInfos := []resolvedSSPInfo{
		{
			SSPID: *ssp.ID,
			ControlLinks: []controlLinkInfo{
				{CatalogID: catalogID, ControlID: "AC-1"},
			},
		},
	}

	err := worker.createOrUpdateRisksForSSPs(ctx, *riskTemplate, evidence, sspInfos)
	assert.NoError(t, err)

	// Verify risk was created
	var risk risks.Risk
	err = worker.db.WithContext(ctx).Where("ssp_id = ? AND risk_template_id = ?", ssp.ID, riskTemplate.ID).First(&risk).Error
	assert.NoError(t, err)
	assert.Equal(t, riskTemplate.Title, risk.Title)
	assert.Equal(t, riskTemplate.Statement, risk.Description)
	assert.Equal(t, risks.RiskStatusOpen, risks.RiskStatus(risk.Status))
	assert.Equal(t, *ssp.ID, risk.SSPID)

	var threatRefs []risks.RiskThreatRef
	require.NoError(t, worker.db.Where("risk_id = ?", risk.ID).Find(&threatRefs).Error)
	require.Len(t, threatRefs, 1)
	assert.Equal(t, "CWE", threatRefs[0].System)
	assert.Equal(t, "79", threatRefs[0].ExternalID)

	var remediationTemplates []risks.RiskRemediationTemplate
	require.NoError(t, worker.db.Where("risk_id = ?", risk.ID).Find(&remediationTemplates).Error)
	require.Len(t, remediationTemplates, 1)
	assert.Equal(t, "Fix template issue", remediationTemplates[0].Title)
	var remediationTasks []risks.RiskRemediationTask
	require.NotNil(t, remediationTemplates[0].ID)
	require.NoError(t, worker.db.Where("risk_remediation_template_id = ?", *remediationTemplates[0].ID).Find(&remediationTasks).Error)
	require.Len(t, remediationTasks, 1)
	assert.Equal(t, "Patch code", remediationTasks[0].Title)

	// Verify control link
	var controlLink risks.RiskControlLink
	require.NoError(t, worker.db.Where("risk_id = ?", risk.ID).First(&controlLink).Error)
	assert.Equal(t, catalogID, controlLink.CatalogID)
	assert.Equal(t, "AC-1", controlLink.ControlID)
}

func TestRiskEvidenceWorker_createOrUpdateRisk_UpdateExisting(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	ssp := createTestSSP(t, worker.db)
	riskTemplate := createTestRiskTemplate(t, worker.db)

	evidence := createTestEvidence(t, worker.db)

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

	catalogID := uuid.New()
	sspInfos := []resolvedSSPInfo{
		{
			SSPID: *ssp.ID,
			ControlLinks: []controlLinkInfo{
				{CatalogID: catalogID, ControlID: "AC-1"},
			},
		},
	}

	err := worker.createOrUpdateRisksForSSPs(ctx, *riskTemplate, evidence, sspInfos)
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

	evidence := createTestEvidence(t, worker.db)

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

	catalogID := uuid.New()
	controlLinks := []controlLinkInfo{
		{CatalogID: catalogID, ControlID: "AC-1"},
		{CatalogID: catalogID, ControlID: "AC-2"},
	}

	err := worker.createRiskLinks(ctx, worker.db, riskID, sspID, evidence, controlLinks)
	assert.NoError(t, err)

	// Verify evidence link
	var evidenceLink risks.RiskEvidenceLink
	err = worker.db.WithContext(ctx).
		Where("risk_id = ? AND evidence_id = ?", riskID, evidence.UUID).
		First(&evidenceLink).Error
	assert.NoError(t, err)

	// Verify control links
	var controlLinkRows []risks.RiskControlLink
	err = worker.db.WithContext(ctx).
		Where("risk_id = ?", riskID).
		Find(&controlLinkRows).Error
	assert.NoError(t, err)
	assert.Len(t, controlLinkRows, 2)
}

func TestRiskEvidenceWorker_createRiskLinks_NoControlLinks(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	evidence := createTestEvidence(t, worker.db)

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

	err := worker.createRiskLinks(ctx, worker.db, riskID, sspID, evidence, nil)
	assert.NoError(t, err)

	// Verify only evidence link was created
	var evidenceLink risks.RiskEvidenceLink
	err = worker.db.WithContext(ctx).
		Where("risk_id = ? AND evidence_id = ?", riskID, evidence.UUID).
		First(&evidenceLink).Error
	assert.NoError(t, err)

	// Verify no control links
	var controlLinkCount int64
	err = worker.db.WithContext(ctx).
		Model(&risks.RiskControlLink{}).
		Where("risk_id = ?", riskID).
		Count(&controlLinkCount).Error
	assert.NoError(t, err)
	assert.Equal(t, int64(0), controlLinkCount)
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
	sspID := uuid.New()
	err := worker.createRiskLinks(ctx, worker.db, riskID, sspID, evidence, nil)
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

	riskID := uuid.New()
	eventType := string(risks.RiskEventTypeCreated)
	payload := map[string]interface{}{
		"evidence_id": uuid.New(),
		"template_id": uuid.New(),
	}

	err := worker.emitRiskEvent(ctx, worker.db, riskID, eventType, payload)
	assert.NoError(t, err)

	var event risks.RiskEvent
	err = worker.db.WithContext(ctx).
		Where("risk_id = ? AND event_type = ?", riskID, eventType).
		First(&event).Error
	assert.NoError(t, err)
	assert.Equal(t, riskID, event.RiskID)
	assert.Equal(t, eventType, event.EventType)
	assert.NotZero(t, event.OccurredAt)
	assert.NotNil(t, event.Details)
	assert.NotEmpty(t, *event.Details)
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

			var event risks.RiskEvent
			err = worker.db.WithContext(ctx).
				Where("risk_id = ? AND event_type = ?", riskID, tc.eventType).
				First(&event).Error
			assert.NoError(t, err)
			assert.Equal(t, riskID, event.RiskID)
			assert.Equal(t, tc.eventType, event.EventType)
			assert.NotNil(t, event.Details)
			assert.NotEmpty(t, *event.Details)
		})
	}
}

func TestRiskEvidenceWorker_resolveSSPsViaFilters(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	catalogID := uuid.New()
	controlID := "AC-1"

	// Create filter matching "environment=production"
	seedFilterForControl(t, worker.db, catalogID, controlID, "environment", "production")

	// Create SSP with the control
	ssp := createTestSSPWithControl(t, worker.db, catalogID, controlID)

	labels := []relational.Labels{
		{Name: "environment", Value: "production"},
		{Name: "category", Value: "security"},
	}

	sspInfos, err := worker.resolveSSPsViaFilters(ctx, labels)
	require.NoError(t, err)
	require.Len(t, sspInfos, 1)
	assert.Equal(t, *ssp.ID, sspInfos[0].SSPID)
	require.Len(t, sspInfos[0].ControlLinks, 1)
	assert.Equal(t, catalogID, sspInfos[0].ControlLinks[0].CatalogID)
	assert.Equal(t, controlID, sspInfos[0].ControlLinks[0].ControlID)
}

func TestRiskEvidenceWorker_resolveSSPsViaFilters_NoMatch(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	catalogID := uuid.New()
	seedFilterForControl(t, worker.db, catalogID, "AC-1", "environment", "staging")

	labels := []relational.Labels{
		{Name: "environment", Value: "production"},
	}

	sspInfos, err := worker.resolveSSPsViaFilters(ctx, labels)
	require.NoError(t, err)
	assert.Nil(t, sspInfos)
}

func TestRiskEvidenceWorker_resolveSSPsViaFilters_NoFilters(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	labels := []relational.Labels{
		{Name: "environment", Value: "production"},
	}

	sspInfos, err := worker.resolveSSPsViaFilters(ctx, labels)
	require.NoError(t, err)
	assert.Nil(t, sspInfos)
}

func TestRiskEvidenceWorker_resolveSSPsViaFilters_MultipleSSPs(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	catalogID := uuid.New()

	// One filter matching "environment=production", linked to two different controls
	seedFilterForControl(t, worker.db, catalogID, "AC-1", "environment", "production")

	// Two SSPs each implementing a different control
	ssp1 := createTestSSPWithControl(t, worker.db, catalogID, "AC-1")

	// Create a second filter for a different control
	seedFilterForControl(t, worker.db, catalogID, "SC-7", "environment", "production")
	ssp2 := createTestSSPWithControl(t, worker.db, catalogID, "SC-7")

	labels := []relational.Labels{
		{Name: "environment", Value: "production"},
	}

	sspInfos, err := worker.resolveSSPsViaFilters(ctx, labels)
	require.NoError(t, err)
	require.Len(t, sspInfos, 2)

	sspIDs := make(map[uuid.UUID]bool)
	for _, info := range sspInfos {
		sspIDs[info.SSPID] = true
	}
	assert.True(t, sspIDs[*ssp1.ID])
	assert.True(t, sspIDs[*ssp2.ID])
}
