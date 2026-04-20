package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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
		&templates.RiskTemplateLabelSchemaField{},
		&templates.RemediationTemplate{},
		&templates.RemediationTask{},
		&risks.Risk{},
		&risks.RiskScore{},
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

	require.NoError(t, db.Exec(`CREATE TABLE IF NOT EXISTS ssp_profiles (
		system_security_plan_id TEXT,
		profile_id TEXT,
		PRIMARY KEY (system_security_plan_id, profile_id)
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

	// Also populate ssp_profiles join table for the M:M relationship.
	require.NoError(t, db.Exec(
		`INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)`,
		sspID.String(), profileID.String(),
	).Error)

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
	status := oscalTypes_1_1_3.ObjectiveStatus{
		State: "satisfied",
	}
	evidence := &relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evidenceID},
		UUID:      evidenceID,
		Title:     "Satisfied Evidence",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
		Status:    datatypes.NewJSONType(status),
		Labels: []relational.Labels{
			{Name: "environment", Value: "production"},
			{Name: "_policy", Value: "test-policy"},
		},
	}
	require.NoError(t, worker.db.Create(evidence).Error)
	require.Equal(t, "satisfied", evidence.Status.Data().State)

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

// --- Resolution flow tests ---

// createRiskWithEvidenceLink creates a risk in the given status, linked to the given evidence stream.
func createRiskWithEvidenceLink(t *testing.T, db *gorm.DB, status string, evidenceStreamID uuid.UUID, templateID *uuid.UUID) *risks.Risk {
	t.Helper()
	riskID := uuid.New()
	risk := &risks.Risk{
		UUIDModel:      relational.UUIDModel{ID: &riskID},
		Title:          "Test Risk",
		Description:    "Test Description",
		Status:         status,
		SSPID:          uuid.New(),
		RiskTemplateID: templateID,
		SourceType:     string(risks.RiskSourceTypeEvidenceAuto),
		DedupeKey:      fmt.Sprintf("dedupe-%s", riskID),
		FirstSeenAt:    time.Now().Add(-1 * time.Hour),
		LastSeenAt:     time.Now().Add(-1 * time.Hour),
	}
	require.NoError(t, db.Create(risk).Error)

	link := &risks.RiskEvidenceLink{
		RiskID:     riskID,
		EvidenceID: evidenceStreamID,
		CreatedAt:  time.Now(),
	}
	require.NoError(t, db.Create(link).Error)

	return risk
}

func TestRiskEvidenceWorker_Resolution_SatisfiedRemovesLinks(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	// Create a satisfied evidence.
	evidenceID := uuid.New()
	evidence := &relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evidenceID},
		UUID:      evidenceID,
		Title:     "Satisfied Evidence",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
		Status:    datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
	}
	require.NoError(t, worker.db.Create(evidence).Error)

	templateID := uuid.New()
	tmpl := &templates.RiskTemplate{
		UUIDModel:     relational.UUIDModel{ID: &templateID},
		PluginID:      "test-plugin",
		PolicyPackage: "test-policy",
		Name:          "Test Template",
		Title:         "Test Template",
		Statement:     "statement",
		IsActive:      true,
		ViolationIDs:  []string{"VIOL-001"},
	}
	require.NoError(t, worker.db.Create(tmpl).Error)

	// Create two risks linked to this evidence.
	risk1 := createRiskWithEvidenceLink(t, worker.db, string(risks.RiskStatusOpen), evidenceID, &templateID)
	risk2 := createRiskWithEvidenceLink(t, worker.db, string(risks.RiskStatusInvestigating), evidenceID, &templateID)

	err := worker.handleEvidenceResolution(ctx, evidence)
	require.NoError(t, err)

	// Both evidence links should be removed.
	var linkCount int64
	require.NoError(t, worker.db.Model(&risks.RiskEvidenceLink{}).Where("evidence_id = ?", evidenceID).Count(&linkCount).Error)
	assert.Equal(t, int64(0), linkCount)

	// Both risks should be remediated.
	var r1, r2 risks.Risk
	require.NoError(t, worker.db.First(&r1, "id = ?", risk1.ID).Error)
	require.NoError(t, worker.db.First(&r2, "id = ?", risk2.ID).Error)
	assert.Equal(t, string(risks.RiskStatusRemediated), r1.Status)
	assert.Equal(t, string(risks.RiskStatusRemediated), r2.Status)

	// Verify status_changed events were emitted.
	var events []risks.RiskEvent
	require.NoError(t, worker.db.Where("risk_id IN ? AND event_type = ?",
		[]uuid.UUID{*risk1.ID, *risk2.ID}, string(risks.RiskEventTypeStatusChange)).Find(&events).Error)
	assert.Len(t, events, 2)
}

func TestRiskEvidenceWorker_Resolution_ViolationsReduced(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	evidenceID := uuid.New()
	// Evidence is still not-satisfied but with reduced violations (only VIOL-002 now).
	evidence := &relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evidenceID},
		UUID:      evidenceID,
		Title:     "Reduced Violations Evidence",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
		Status:    datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied"}),
		Props: datatypes.NewJSONSlice([]relational.Prop{
			{Name: "violation_id", Value: "VIOL-002"},
		}),
	}
	require.NoError(t, worker.db.Create(evidence).Error)

	// Template 1 matches VIOL-001 — no longer in evidence → link should be removed.
	tmpl1ID := uuid.New()
	tmpl1 := &templates.RiskTemplate{
		UUIDModel:     relational.UUIDModel{ID: &tmpl1ID},
		PluginID:      "test-plugin",
		PolicyPackage: "test-policy",
		Name:          "Template VIOL-001",
		Title:         "Template VIOL-001",
		Statement:     "statement",
		IsActive:      true,
		ViolationIDs:  []string{"VIOL-001"},
	}
	require.NoError(t, worker.db.Create(tmpl1).Error)

	// Template 2 matches VIOL-002 — still in evidence → link should be kept.
	tmpl2ID := uuid.New()
	tmpl2 := &templates.RiskTemplate{
		UUIDModel:     relational.UUIDModel{ID: &tmpl2ID},
		PluginID:      "test-plugin",
		PolicyPackage: "test-policy",
		Name:          "Template VIOL-002",
		Title:         "Template VIOL-002",
		Statement:     "statement",
		IsActive:      true,
		ViolationIDs:  []string{"VIOL-002"},
	}
	require.NoError(t, worker.db.Create(tmpl2).Error)

	// Template 3 has empty ViolationIDs — matches any not-satisfied → link should be kept.
	tmpl3ID := uuid.New()
	tmpl3 := &templates.RiskTemplate{
		UUIDModel:     relational.UUIDModel{ID: &tmpl3ID},
		PluginID:      "test-plugin",
		PolicyPackage: "test-policy",
		Name:          "Template Wildcard",
		Title:         "Template Wildcard",
		Statement:     "statement",
		IsActive:      true,
		ViolationIDs:  []string{},
	}
	require.NoError(t, worker.db.Create(tmpl3).Error)

	risk1 := createRiskWithEvidenceLink(t, worker.db, string(risks.RiskStatusOpen), evidenceID, &tmpl1ID)
	risk2 := createRiskWithEvidenceLink(t, worker.db, string(risks.RiskStatusOpen), evidenceID, &tmpl2ID)
	risk3 := createRiskWithEvidenceLink(t, worker.db, string(risks.RiskStatusOpen), evidenceID, &tmpl3ID)

	err := worker.handleEvidenceResolution(ctx, evidence)
	require.NoError(t, err)

	// risk1 link removed (VIOL-001 no longer in evidence) → remediated.
	var r1 risks.Risk
	require.NoError(t, worker.db.First(&r1, "id = ?", risk1.ID).Error)
	assert.Equal(t, string(risks.RiskStatusRemediated), r1.Status)

	// risk2 link kept (VIOL-002 still present).
	var link2Count int64
	require.NoError(t, worker.db.Model(&risks.RiskEvidenceLink{}).
		Where("risk_id = ? AND evidence_id = ?", risk2.ID, evidenceID).Count(&link2Count).Error)
	assert.Equal(t, int64(1), link2Count)
	var r2 risks.Risk
	require.NoError(t, worker.db.First(&r2, "id = ?", risk2.ID).Error)
	assert.Equal(t, string(risks.RiskStatusOpen), r2.Status)

	// risk3 link kept (empty ViolationIDs = wildcard for not-satisfied).
	var link3Count int64
	require.NoError(t, worker.db.Model(&risks.RiskEvidenceLink{}).
		Where("risk_id = ? AND evidence_id = ?", risk3.ID, evidenceID).Count(&link3Count).Error)
	assert.Equal(t, int64(1), link3Count)
	var r3 risks.Risk
	require.NoError(t, worker.db.First(&r3, "id = ?", risk3.ID).Error)
	assert.Equal(t, string(risks.RiskStatusOpen), r3.Status)
}

func TestRiskEvidenceWorker_Resolution_TransitionToRemediated(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	evidenceID := uuid.New()
	evidence := &relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evidenceID},
		UUID:      evidenceID,
		Title:     "Satisfied Evidence",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
		Status:    datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
	}
	require.NoError(t, worker.db.Create(evidence).Error)

	risk := createRiskWithEvidenceLink(t, worker.db, string(risks.RiskStatusOpen), evidenceID, nil)

	err := worker.handleEvidenceResolution(ctx, evidence)
	require.NoError(t, err)

	var updated risks.Risk
	require.NoError(t, worker.db.First(&updated, "id = ?", risk.ID).Error)
	assert.Equal(t, string(risks.RiskStatusRemediated), updated.Status)

	// Verify events: evidence_unlinked + status_changed.
	var events []risks.RiskEvent
	require.NoError(t, worker.db.Where("risk_id = ?", risk.ID).Order("occurred_at asc").Find(&events).Error)
	require.Len(t, events, 2)
	assert.Equal(t, string(risks.RiskEventTypeEvidenceUnlink), events[0].EventType)
	assert.Equal(t, string(risks.RiskEventTypeStatusChange), events[1].EventType)
}

func TestRiskEvidenceWorker_Resolution_RiskAcceptedNoTransition(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	evidenceID := uuid.New()
	evidence := &relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evidenceID},
		UUID:      evidenceID,
		Title:     "Satisfied Evidence",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
		Status:    datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
	}
	require.NoError(t, worker.db.Create(evidence).Error)

	risk := createRiskWithEvidenceLink(t, worker.db, string(risks.RiskStatusRiskAccepted), evidenceID, nil)

	err := worker.handleEvidenceResolution(ctx, evidence)
	require.NoError(t, err)

	// Risk should remain risk-accepted.
	var updated risks.Risk
	require.NoError(t, worker.db.First(&updated, "id = ?", risk.ID).Error)
	assert.Equal(t, string(risks.RiskStatusRiskAccepted), updated.Status)

	// Evidence link should still be removed.
	var linkCount int64
	require.NoError(t, worker.db.Model(&risks.RiskEvidenceLink{}).
		Where("risk_id = ? AND evidence_id = ?", risk.ID, evidenceID).Count(&linkCount).Error)
	assert.Equal(t, int64(0), linkCount)

	// Verify evidence_recovered event was emitted.
	var event risks.RiskEvent
	require.NoError(t, worker.db.Where("risk_id = ? AND event_type = ?",
		risk.ID, string(risks.RiskEventTypeEvidenceRecovered)).First(&event).Error)
}

func TestRiskEvidenceWorker_Resolution_MultipleEvidencePartialResolve(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	evidenceA := uuid.New()
	evidenceB := uuid.New()

	// Create the risk with TWO evidence links.
	riskID := uuid.New()
	risk := &risks.Risk{
		UUIDModel:   relational.UUIDModel{ID: &riskID},
		Title:       "Risk with two evidence streams",
		Description: "desc",
		Status:      string(risks.RiskStatusOpen),
		SSPID:       uuid.New(),
		SourceType:  string(risks.RiskSourceTypeEvidenceAuto),
		DedupeKey:   fmt.Sprintf("dedupe-%s", riskID),
		FirstSeenAt: time.Now().Add(-1 * time.Hour),
		LastSeenAt:  time.Now().Add(-1 * time.Hour),
	}
	require.NoError(t, worker.db.Create(risk).Error)
	require.NoError(t, worker.db.Create(&risks.RiskEvidenceLink{
		RiskID: riskID, EvidenceID: evidenceA, CreatedAt: time.Now(),
	}).Error)
	require.NoError(t, worker.db.Create(&risks.RiskEvidenceLink{
		RiskID: riskID, EvidenceID: evidenceB, CreatedAt: time.Now(),
	}).Error)

	// Evidence A becomes satisfied.
	evA := &relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evidenceA},
		UUID:      evidenceA,
		Title:     "Evidence A",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
		Status:    datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
	}
	require.NoError(t, worker.db.Create(evA).Error)

	err := worker.handleEvidenceResolution(ctx, evA)
	require.NoError(t, err)

	// Risk should NOT be remediated — evidence B link still exists.
	var updated risks.Risk
	require.NoError(t, worker.db.First(&updated, "id = ?", riskID).Error)
	assert.Equal(t, string(risks.RiskStatusOpen), updated.Status)

	// Evidence A link removed, B remains.
	var remaining int64
	require.NoError(t, worker.db.Model(&risks.RiskEvidenceLink{}).
		Where("risk_id = ?", riskID).Count(&remaining).Error)
	assert.Equal(t, int64(1), remaining)
}

func TestRiskEvidenceWorker_Reopen_FromRemediated(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	ssp := createTestSSP(t, worker.db)
	riskTemplate := createTestRiskTemplate(t, worker.db)
	evidence := createTestEvidence(t, worker.db)

	dedupeKey := fmt.Sprintf("%s:%s", ssp.ID.String(), riskTemplate.ID.String())
	riskID := uuid.New()
	remediatedRisk := &risks.Risk{
		UUIDModel:      relational.UUIDModel{ID: &riskID},
		Title:          "Remediated Risk",
		Description:    "desc",
		Status:         string(risks.RiskStatusRemediated),
		SSPID:          *ssp.ID,
		RiskTemplateID: riskTemplate.ID,
		SourceType:     string(risks.RiskSourceTypeEvidenceAuto),
		DedupeKey:      dedupeKey,
		FirstSeenAt:    time.Now().Add(-1 * time.Hour),
		LastSeenAt:     time.Now().Add(-1 * time.Hour),
	}
	require.NoError(t, worker.db.Create(remediatedRisk).Error)

	catalogID := uuid.New()
	sspInfos := []resolvedSSPInfo{
		{
			SSPID:        *ssp.ID,
			ControlLinks: []controlLinkInfo{{CatalogID: catalogID, ControlID: "AC-1"}},
		},
	}

	err := worker.createOrUpdateRisksForSSPs(ctx, *riskTemplate, evidence, sspInfos)
	require.NoError(t, err)

	// Risk should be re-opened.
	var updated risks.Risk
	require.NoError(t, worker.db.First(&updated, "id = ?", riskID).Error)
	assert.Equal(t, string(risks.RiskStatusOpen), updated.Status)

	// Verify status_changed event was emitted.
	var event risks.RiskEvent
	require.NoError(t, worker.db.Where("risk_id = ? AND event_type = ?",
		riskID, string(risks.RiskEventTypeStatusChange)).First(&event).Error)
}

func TestRiskEvidenceWorker_Resolution_SkipsClosedAndRemediated(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	ctx := context.Background()

	evidenceID := uuid.New()
	evidence := &relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evidenceID},
		UUID:      evidenceID,
		Title:     "Satisfied Evidence",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
		Status:    datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
	}
	require.NoError(t, worker.db.Create(evidence).Error)

	// Create risks in closed and remediated status — should be skipped.
	closedRisk := createRiskWithEvidenceLink(t, worker.db, string(risks.RiskStatusClosed), evidenceID, nil)
	remediatedRisk := createRiskWithEvidenceLink(t, worker.db, string(risks.RiskStatusRemediated), evidenceID, nil)

	err := worker.handleEvidenceResolution(ctx, evidence)
	require.NoError(t, err)

	// Links should NOT be removed for closed/remediated risks.
	var closedLinkCount, remediatedLinkCount int64
	require.NoError(t, worker.db.Model(&risks.RiskEvidenceLink{}).
		Where("risk_id = ?", closedRisk.ID).Count(&closedLinkCount).Error)
	assert.Equal(t, int64(1), closedLinkCount)
	require.NoError(t, worker.db.Model(&risks.RiskEvidenceLink{}).
		Where("risk_id = ?", remediatedRisk.ID).Count(&remediatedLinkCount).Error)
	assert.Equal(t, int64(1), remediatedLinkCount)
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

func TestComputeDedupeKeyForSSP_WithDedupeLabelKeys(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	sspID := uuid.New()
	templateID := uuid.New()

	baseTemplate := templates.RiskTemplate{
		UUIDModel: relational.UUIDModel{ID: &templateID},
	}

	t.Run("no dedupe keys returns base key only", func(t *testing.T) {
		rt := baseTemplate
		rt.DedupeLabelKeys = nil

		key := worker.computeDedupeKeyForSSP(rt, sspID, []relational.Labels{
			{Name: "env", Value: "prod"},
		})
		require.Equal(t, fmt.Sprintf("%s:%s", sspID, templateID), key)
	})

	t.Run("dedupe keys appends sorted label values", func(t *testing.T) {
		rt := baseTemplate
		rt.DedupeLabelKeys = []string{"cve_id", "repo"}

		key := worker.computeDedupeKeyForSSP(rt, sspID, []relational.Labels{
			{Name: "repo", Value: "my-repo"},
			{Name: "cve_id", Value: "CVE-2024-1234"},
			{Name: "extra", Value: "ignored"},
		})
		expected := fmt.Sprintf("%s:%s:cve_id=CVE-2024-1234,repo=my-repo", sspID, templateID)
		require.Equal(t, expected, key)
	})

	t.Run("missing evidence labels produce empty values in key", func(t *testing.T) {
		rt := baseTemplate
		rt.DedupeLabelKeys = []string{"cve_id", "repo"}

		key := worker.computeDedupeKeyForSSP(rt, sspID, []relational.Labels{
			{Name: "cve_id", Value: "CVE-2024-5678"},
		})
		expected := fmt.Sprintf("%s:%s:cve_id=CVE-2024-5678,repo=", sspID, templateID)
		require.Equal(t, expected, key)
	})

	t.Run("dedupe key escapes delimiter characters in label values", func(t *testing.T) {
		rt := baseTemplate
		rt.DedupeLabelKeys = []string{"artifact", "repo"}

		key := worker.computeDedupeKeyForSSP(rt, sspID, []relational.Labels{
			{Name: "repo", Value: "payments:api,worker"},
			{Name: "artifact", Value: "cve=id=1,part:2"},
		})
		expected := fmt.Sprintf("%s:%s:%s", sspID, templateID, "artifact=cve%3Did%3D1%2Cpart%3A2,repo=payments%3Aapi%2Cworker")
		require.Equal(t, expected, key)
	})

	t.Run("dedupe key includes sorted unique values for duplicate label names", func(t *testing.T) {
		rt := baseTemplate
		rt.DedupeLabelKeys = []string{"repo", "team"}

		key := worker.computeDedupeKeyForSSP(rt, sspID, []relational.Labels{
			{Name: "repo", Value: "worker"},
			{Name: "repo", Value: "api"},
			{Name: "repo", Value: "api"},
			{Name: "team", Value: "platform"},
			{Name: "team", Value: "security"},
		})
		expected := fmt.Sprintf("%s:%s:%s", sspID, templateID, "repo=api&worker,team=platform&security")
		require.Equal(t, expected, key)
	})
}

func TestResolveRiskTemplateFields(t *testing.T) {
	t.Parallel()

	worker := createTestRiskEvidenceWorker(t)
	templateID := uuid.New()

	t.Run("no template fields returns static values", func(t *testing.T) {
		rt := templates.RiskTemplate{
			UUIDModel: relational.UUIDModel{ID: &templateID},
			Title:     "Static Title",
			Statement: "Static Statement",
		}

		title, statement, likelihood, impact := worker.resolveRiskTemplateFields(rt, []relational.Labels{
			{Name: "foo", Value: "bar"},
		})
		require.Equal(t, "Static Title", title)
		require.Equal(t, "Static Statement", statement)
		require.Nil(t, likelihood)
		require.Nil(t, impact)
	})

	t.Run("template fields render with evidence labels", func(t *testing.T) {
		titleTmpl := "CVE {{.cve_id}} in {{.repo}}"
		stmtTmpl := "Severity: {{.severity}}"
		rt := templates.RiskTemplate{
			UUIDModel: relational.UUIDModel{ID: &templateID},
			Title:     titleTmpl,
			Statement: stmtTmpl,
		}

		title, statement, _, _ := worker.resolveRiskTemplateFields(rt, []relational.Labels{
			{Name: "cve_id", Value: "CVE-2024-1234"},
			{Name: "repo", Value: "my-repo"},
			{Name: "severity", Value: "critical"},
		})
		require.Equal(t, "CVE CVE-2024-1234 in my-repo", title)
		require.Equal(t, "Severity: critical", statement)
	})

	t.Run("invalid template falls back to the stored field value", func(t *testing.T) {
		badTmpl := "{{.invalid template syntax"
		rt := templates.RiskTemplate{
			UUIDModel: relational.UUIDModel{ID: &templateID},
			Title:     badTmpl,
			Statement: "Static Statement",
		}

		title, statement, _, _ := worker.resolveRiskTemplateFields(rt, []relational.Labels{})
		require.Equal(t, badTmpl, title)
		require.Equal(t, "Static Statement", statement)
	})

	t.Run("missing label renders with empty string via missingkey=zero", func(t *testing.T) {
		titleTmpl := "Issue {{.cve_id}} in {{.repo}}"
		rt := templates.RiskTemplate{
			UUIDModel: relational.UUIDModel{ID: &templateID},
			Title:     titleTmpl,
			Statement: "Fallback statement",
		}

		title, _, _, _ := worker.resolveRiskTemplateFields(rt, []relational.Labels{
			{Name: "cve_id", Value: "CVE-2024-9999"},
			// "repo" label is missing
		})
		require.Equal(t, "Issue CVE-2024-9999 in ", title)
	})

	t.Run("templated risk levels are normalized before use", func(t *testing.T) {
		likelihoodTmpl := "{{.likelihood}}"
		impactTmpl := "{{.impact}}"
		rt := templates.RiskTemplate{
			UUIDModel:      relational.UUIDModel{ID: &templateID},
			LikelihoodHint: &likelihoodTmpl,
			ImpactHint:     &impactTmpl,
		}

		_, _, likelihood, impact := worker.resolveRiskTemplateFields(rt, []relational.Labels{
			{Name: "likelihood", Value: "Medium"},
			{Name: "impact", Value: " HIGH "},
		})
		require.NotNil(t, likelihood)
		require.Equal(t, "moderate", *likelihood)
		require.NotNil(t, impact)
		require.Equal(t, "high", *impact)
	})

	t.Run("template fields deterministically include all values for duplicate label names", func(t *testing.T) {
		titleTmpl := "Repos: {{.repo}}"
		stmtTmpl := "Teams: {{.team}}"
		rt := templates.RiskTemplate{
			UUIDModel: relational.UUIDModel{ID: &templateID},
			Title:     titleTmpl,
			Statement: stmtTmpl,
		}

		title, statement, _, _ := worker.resolveRiskTemplateFields(rt, []relational.Labels{
			{Name: "repo", Value: "worker"},
			{Name: "repo", Value: "api"},
			{Name: "repo", Value: "api"},
			{Name: "team", Value: "security"},
			{Name: "team", Value: "platform"},
		})
		require.Equal(t, "Repos: api, worker", title)
		require.Equal(t, "Teams: platform, security", statement)
	})

	t.Run("invalid templated risk levels fall back to nil when no static risk level exists", func(t *testing.T) {
		likelihoodTmpl := "{{.likelihood}}"
		impactTmpl := "{{.impact}}"
		rt := templates.RiskTemplate{
			UUIDModel:      relational.UUIDModel{ID: &templateID},
			LikelihoodHint: &likelihoodTmpl,
			ImpactHint:     &impactTmpl,
		}

		_, _, likelihood, impact := worker.resolveRiskTemplateFields(rt, []relational.Labels{
			{Name: "likelihood", Value: strings.Repeat("x", 32)},
			{Name: "impact", Value: "definitely-not-a-risk-level"},
		})
		require.Nil(t, likelihood)
		require.Nil(t, impact)
	})
}

func TestCreateNewRiskForSSP_WithTemplateResolution(t *testing.T) {
	t.Parallel()

	db := newRiskEvidenceWorkerTestDB(t)
	logger := zap.NewNop().Sugar()
	worker := NewRiskEvidenceWorker(db, logger)

	// Create SSP
	ssp := createTestSSP(t, db)

	// Create evidence with labels for template rendering
	evidenceID := uuid.New()
	evidence := &relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evidenceID},
		UUID:      evidenceID,
		Title:     "Test Evidence",
		Start:     time.Now().Add(-1 * time.Hour),
		End:       time.Now(),
		Status:    datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied"}),
		Labels: []relational.Labels{
			{Name: "cve_id", Value: "CVE-2024-1234"},
			{Name: "repo", Value: "my-repo"},
			{Name: "severity", Value: "critical"},
			{Name: "_policy", Value: "compliance_framework.vuln_scan"},
		},
		Props: datatypes.NewJSONSlice([]relational.Prop{
			{Name: "violation_id", Value: "vuln_detected"},
		}),
	}
	require.NoError(t, db.Create(evidence).Error)

	// Create risk template with template fields
	templateID := uuid.New()
	titleTmpl := "CVE {{.cve_id}} in {{.repo}}"
	stmtTmpl := "Severity: {{.severity}}"
	riskTemplate := templates.RiskTemplate{
		UUIDModel:       relational.UUIDModel{ID: &templateID},
		PluginID:        "vuln-scanner",
		PolicyPackage:   "compliance_framework.vuln_scan",
		Name:            "CVE template",
		Title:           titleTmpl,
		Statement:       stmtTmpl,
		LikelihoodHint:  stringPtr("high"),
		ImpactHint:      stringPtr("high"),
		IsActive:        true,
		ViolationIDs:    []string{"vuln_detected"},
		DedupeLabelKeys: []string{"cve_id"},
	}
	require.NoError(t, db.Create(&riskTemplate).Error)

	dedupeKey := worker.computeDedupeKeyForSSP(riskTemplate, *ssp.ID, evidence.Labels)

	ctx := context.Background()
	err := worker.createNewRiskForSSP(ctx, riskTemplate, evidence, *ssp.ID, dedupeKey, nil)
	require.NoError(t, err)

	// Verify the created risk has rendered template values
	var createdRisk risks.Risk
	require.NoError(t, db.Where("dedupe_key = ?", dedupeKey).First(&createdRisk).Error)

	require.Equal(t, "CVE CVE-2024-1234 in my-repo", createdRisk.Title)
	require.Equal(t, "Severity: critical", createdRisk.Description)
	require.Equal(t, *ssp.ID, createdRisk.SSPID)
	require.Equal(t, &templateID, createdRisk.RiskTemplateID)
}
