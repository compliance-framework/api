package relational

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ---------------------------------------------------------------------------
// Mock EvidenceQuerier
// ---------------------------------------------------------------------------

// mockEvidenceQuerier returns all evidences present in the test DB, bypassing
// the PostgreSQL-specific DISTINCT ON query used by the real EvidenceService.
// The actual label-matching is done by the SQL JOIN in SuggestForImplementedRequirement.
type mockEvidenceQuerier struct {
	db *gorm.DB
}

func (m *mockEvidenceQuerier) GetLatestForFilters(_ ...labelfilter.Filter) ([]Evidence, error) {
	var evidences []Evidence
	if err := m.db.Find(&evidences).Error; err != nil {
		return nil, err
	}
	return evidences, nil
}

// ---------------------------------------------------------------------------
// Test DB setup
// ---------------------------------------------------------------------------

// setupTestDB creates an in-memory SQLite database with all required tables migrated.
func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger:                                   logger.Default.LogMode(logger.Silent),
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	require.NoError(t, err)

	err = db.AutoMigrate(
		&ComponentDefinition{},
		&DefinedComponent{},
		&ControlImplementation{},
		&ImplementedRequirement{},
		&Statement{},
		&SystemImplementation{},
		&SystemSecurityPlan{},
		&SystemComponent{},
		&ByComponent{},
		&Metadata{},
		&ResponsibleRole{},
		&ControlStatementImplementation{},
	)
	require.NoError(t, err)

	// Add unique constraints needed for ON CONFLICT clauses
	// SQLite supports partial indexes with WHERE clause
	require.NoError(t, db.Exec(`
		CREATE UNIQUE INDEX IF NOT EXISTS idx_system_components_unique_impl_defined 
		ON system_components (system_implementation_id, defined_component_id)
		WHERE defined_component_id IS NOT NULL
	`).Error)

	// Manually create the tables needed for the Filter → Evidence → ComponentDefinitionLabel chain,
	// avoiding the complex dependency graph that AutoMigrate would otherwise pull in.
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

	require.NoError(t, db.Exec(`CREATE TABLE IF NOT EXISTS evidences (
		id TEXT PRIMARY KEY,
		created_at DATETIME,
		updated_at DATETIME,
		deleted_at DATETIME,
		uuid TEXT,
		title TEXT,
		description TEXT,
		start DATETIME,
		end DATETIME,
		status JSON,
		props JSON,
		links JSON,
		origins JSON
	)`).Error)

	require.NoError(t, db.Exec(`CREATE TABLE IF NOT EXISTS evidence_labels (
		evidence_id TEXT,
		labels_name TEXT,
		labels_value TEXT
	)`).Error)

	require.NoError(t, db.Exec(`CREATE TABLE IF NOT EXISTS component_definition_labels (
			defined_component_id TEXT,
			component_definition_id TEXT,
			key TEXT,
			value TEXT
		)`).Error)

	return db
}

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

// seedFilterForControl inserts a Filter record and a filter_controls row linking it
// to the given controlID string. Returns the Filter ID.
func seedFilterForControl(t *testing.T, db *gorm.DB, controlID, labelKey, labelValue string) uuid.UUID {
	t.Helper()
	filterID := uuid.New()
	lf := labelfilter.Filter{
		Scope: &labelfilter.Scope{
			Condition: &labelfilter.Condition{
				Label:    labelKey,
				Operator: "=",
				Value:    labelValue,
			},
		},
	}
	filterJSON := datatypes.NewJSONType(lf)
	filterJSONBytes, err := filterJSON.MarshalJSON()
	require.NoError(t, err)

	require.NoError(t, db.Exec(
		`INSERT INTO filters (id, name, filter) VALUES (?, ?, ?)`,
		filterID, "filter-"+controlID, string(filterJSONBytes),
	).Error)

	require.NoError(t, db.Exec(
		`INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)`,
		filterID, uuid.Nil, controlID,
	).Error)

	return filterID
}

// seedEvidenceWithLabel inserts an Evidence record and an evidence_labels row.
// Returns the Evidence ID.
func seedEvidenceWithLabel(t *testing.T, db *gorm.DB, labelKey, labelValue string) uuid.UUID {
	t.Helper()
	evidenceID := uuid.New()
	evidenceUUID := uuid.New()
	now := time.Now()

	require.NoError(t, db.Exec(
		`INSERT INTO evidences (id, uuid, title, description, start, end) VALUES (?, ?, ?, ?, ?, ?)`,
		evidenceID, evidenceUUID, "test evidence", "test", now, now,
	).Error)

	require.NoError(t, db.Exec(
		`INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, ?, ?)`,
		evidenceID, labelKey, labelValue,
	).Error)

	return evidenceID
}

// seedDefinedComponentWithLabels inserts a ComponentDefinition, a DefinedComponent linked
// to that ComponentDefinition, and a component_definition_labels row for that DefinedComponent.
// Returns the DefinedComponent.
func seedDefinedComponentWithLabels(t *testing.T, db *gorm.DB, labelKey, labelValue string) DefinedComponent {
	t.Helper()

	compDef := ComponentDefinition{}
	require.NoError(t, db.Create(&compDef).Error)

	dc := DefinedComponent{
		Type:                  "software",
		Title:                 "Test Component",
		Description:           "A test component",
		Purpose:               "testing",
		ComponentDefinitionID: compDef.ID,
	}
	require.NoError(t, db.Create(&dc).Error)

	require.NoError(t, db.Exec(
		`INSERT INTO component_definition_labels (defined_component_id, component_definition_id, key, value) VALUES (?, ?, ?, ?)`,
		dc.ID, compDef.ID, labelKey, labelValue,
	).Error)

	return dc
}

// seedSSPWithImplReq inserts a minimal SSP, SystemImplementation, ControlImplementation
// and ImplementedRequirement, then returns the SSP ID and ImplementedRequirement ID.
func seedSSPWithImplReq(t *testing.T, db *gorm.DB, controlID string) (sspID, implReqID uuid.UUID) {
	t.Helper()

	ssp := SystemSecurityPlan{}
	require.NoError(t, db.Create(&ssp).Error)

	si := SystemImplementation{SystemSecurityPlanId: *ssp.ID}
	require.NoError(t, db.Create(&si).Error)

	ci := ControlImplementation{
		Description:          "ctrl impl",
		SystemSecurityPlanId: *ssp.ID,
	}
	require.NoError(t, db.Create(&ci).Error)

	ir := ImplementedRequirement{
		ControlId:               controlID,
		ControlImplementationId: *ci.ID,
	}
	require.NoError(t, db.Create(&ir).Error)

	return *ssp.ID, *ir.ID
}

func seedStatementForImplReq(t *testing.T, db *gorm.DB, implReqID uuid.UUID, statementID string) uuid.UUID {
	t.Helper()
	stmt := Statement{
		StatementId:              statementID,
		ImplementedRequirementId: implReqID,
	}
	require.NoError(t, db.Create(&stmt).Error)
	return *stmt.ID
}

// ---------------------------------------------------------------------------
// SuggestForImplementedRequirement tests
// ---------------------------------------------------------------------------

func TestSuggestForImplementedRequirement_NoDefinedComponents(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	sspID, implReqID := seedSSPWithImplReq(t, db, "ac-1")

	suggestions, err := svc.SuggestForImplementedRequirement(sspID, implReqID)
	require.NoError(t, err)
	assert.Empty(t, suggestions)
}

func TestSuggestForImplementedRequirement_ReturnsMatchingComponent(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	const labelKey, labelValue = "plugin", "sshd"
	dc := seedDefinedComponentWithLabels(t, db, labelKey, labelValue)
	seedFilterForControl(t, db, "ac-1", labelKey, labelValue)
	seedEvidenceWithLabel(t, db, labelKey, labelValue)
	sspID, implReqID := seedSSPWithImplReq(t, db, "ac-1")

	suggestions, err := svc.SuggestForImplementedRequirement(sspID, implReqID)
	require.NoError(t, err)
	require.Len(t, suggestions, 1)
	assert.Equal(t, *dc.ID, suggestions[0].DefinedComponentID)
	assert.Equal(t, dc.Title, suggestions[0].Name)
	assert.Equal(t, dc.Type, suggestions[0].Type)
	assert.Equal(t, dc.Description, suggestions[0].Description)
}

func TestSuggestForImplementedRequirement_DoesNotReturnNonMatchingSiblingDefinedComponent(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	const labelKey = "plugin"
	const matchingValue = "sshd"
	const nonMatchingValue = "nginx"

	compDef := ComponentDefinition{}
	require.NoError(t, db.Create(&compDef).Error)

	matching := DefinedComponent{
		Type:                  "software",
		Title:                 "Matching",
		Description:           "matches label",
		Purpose:               "testing",
		ComponentDefinitionID: compDef.ID,
	}
	require.NoError(t, db.Create(&matching).Error)
	require.NoError(t, db.Exec(
		`INSERT INTO component_definition_labels (defined_component_id, component_definition_id, key, value) VALUES (?, ?, ?, ?)`,
		matching.ID, compDef.ID, labelKey, matchingValue,
	).Error)

	nonMatching := DefinedComponent{
		Type:                  "software",
		Title:                 "Non-Matching",
		Description:           "does not match label",
		Purpose:               "testing",
		ComponentDefinitionID: compDef.ID,
	}
	require.NoError(t, db.Create(&nonMatching).Error)
	require.NoError(t, db.Exec(
		`INSERT INTO component_definition_labels (defined_component_id, component_definition_id, key, value) VALUES (?, ?, ?, ?)`,
		nonMatching.ID, compDef.ID, labelKey, nonMatchingValue,
	).Error)

	seedFilterForControl(t, db, "ac-1", labelKey, matchingValue)
	seedEvidenceWithLabel(t, db, labelKey, matchingValue)
	sspID, implReqID := seedSSPWithImplReq(t, db, "ac-1")

	suggestions, err := svc.SuggestForImplementedRequirement(sspID, implReqID)
	require.NoError(t, err)
	require.Len(t, suggestions, 1)
	assert.Equal(t, *matching.ID, suggestions[0].DefinedComponentID)
}

func TestSuggestForImplementedRequirement_DifferentControlFiltered(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	const labelKey, labelValue = "plugin", "sshd"
	// Seed a component + filter for a DIFFERENT control ("si-2")
	seedDefinedComponentWithLabels(t, db, labelKey, labelValue)
	seedFilterForControl(t, db, "si-2", labelKey, labelValue)
	seedEvidenceWithLabel(t, db, labelKey, labelValue)

	// SSP uses "ac-1" — no filter exists for "ac-1", so no suggestions
	sspID, implReqID := seedSSPWithImplReq(t, db, "ac-1")

	suggestions, err := svc.SuggestForImplementedRequirement(sspID, implReqID)
	require.NoError(t, err)
	assert.Empty(t, suggestions)
}

func TestSuggestForImplementedRequirement_CaseInsensitiveControlID(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	const labelKey, labelValue = "plugin", "sshd"
	dc := seedDefinedComponentWithLabels(t, db, labelKey, labelValue)
	// Filter uses uppercase "AC-1"; ImplementedRequirement uses lowercase "ac-1"
	seedFilterForControl(t, db, "AC-1", labelKey, labelValue)
	seedEvidenceWithLabel(t, db, labelKey, labelValue)
	sspID, implReqID := seedSSPWithImplReq(t, db, "ac-1")

	suggestions, err := svc.SuggestForImplementedRequirement(sspID, implReqID)
	require.NoError(t, err)
	require.Len(t, suggestions, 1)
	assert.Equal(t, *dc.ID, suggestions[0].DefinedComponentID)
}

func TestSuggestForImplementedRequirement_AlreadyLinkedFiltered(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	const labelKey, labelValue = "plugin", "nginx"
	dc := seedDefinedComponentWithLabels(t, db, labelKey, labelValue)
	seedFilterForControl(t, db, "ac-1", labelKey, labelValue)
	seedEvidenceWithLabel(t, db, labelKey, labelValue)
	sspID, implReqID := seedSSPWithImplReq(t, db, "ac-1")

	// Get the SystemImplementation ID to create a pre-existing SystemComponent
	var systemImpl SystemImplementation
	require.NoError(t, db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error)

	// Pre-create a SystemComponent that is already linked to the DefinedComponent
	existing := SystemComponent{
		Type:                   dc.Type,
		Title:                  dc.Title,
		Description:            dc.Description,
		Status:                 datatypes.NewJSONType(SystemComponentStatus{State: "operational"}),
		SystemImplementationId: *systemImpl.ID,
		DefinedComponentID:     dc.ID,
	}
	require.NoError(t, db.Create(&existing).Error)

	suggestions, err := svc.SuggestForImplementedRequirement(sspID, implReqID)
	require.NoError(t, err)
	assert.Empty(t, suggestions, "component already linked should not appear as suggestion")
}

func TestSuggestForImplementedRequirement_MultipleComponents(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	const labelKey = "plugin"
	dc1 := seedDefinedComponentWithLabels(t, db, labelKey, "sshd")
	dc2 := seedDefinedComponentWithLabels(t, db, labelKey, "nginx")
	seedFilterForControl(t, db, "ac-2", labelKey, "sshd")
	seedFilterForControl(t, db, "ac-2", labelKey, "nginx")
	seedEvidenceWithLabel(t, db, labelKey, "sshd")
	seedEvidenceWithLabel(t, db, labelKey, "nginx")
	sspID, implReqID := seedSSPWithImplReq(t, db, "ac-2")

	suggestions, err := svc.SuggestForImplementedRequirement(sspID, implReqID)
	require.NoError(t, err)
	require.Len(t, suggestions, 2)

	ids := []uuid.UUID{suggestions[0].DefinedComponentID, suggestions[1].DefinedComponentID}
	assert.Contains(t, ids, *dc1.ID)
	assert.Contains(t, ids, *dc2.ID)
}

func TestSuggestForImplementedRequirement_NoEvidence(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	const labelKey, labelValue = "plugin", "sshd"
	seedDefinedComponentWithLabels(t, db, labelKey, labelValue)
	seedFilterForControl(t, db, "ac-1", labelKey, labelValue)
	// No evidence seeded
	sspID, implReqID := seedSSPWithImplReq(t, db, "ac-1")

	suggestions, err := svc.SuggestForImplementedRequirement(sspID, implReqID)
	require.NoError(t, err)
	assert.Empty(t, suggestions)
}

func TestSuggestForImplementedRequirement_ImplReqNotFound(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	fakeSSPID := uuid.New()
	fakeImplReqID := uuid.New()

	_, err := svc.SuggestForImplementedRequirement(fakeSSPID, fakeImplReqID)
	assert.Error(t, err)
}

func TestSuggestForStatement_ReturnsMatchingComponent(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	const labelKey, labelValue = "plugin", "sshd"
	dc := seedDefinedComponentWithLabels(t, db, labelKey, labelValue)
	seedFilterForControl(t, db, "ac-1", labelKey, labelValue)
	seedEvidenceWithLabel(t, db, labelKey, labelValue)
	sspID, implReqID := seedSSPWithImplReq(t, db, "ac-1")
	stmtID := seedStatementForImplReq(t, db, implReqID, "ac-1_smt.a")

	suggestions, err := svc.SuggestForStatement(sspID, implReqID, stmtID)
	require.NoError(t, err)
	require.Len(t, suggestions, 1)
	assert.Equal(t, *dc.ID, suggestions[0].DefinedComponentID)
}

func TestSuggestForStatement_NotFound(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	sspID, implReqID := seedSSPWithImplReq(t, db, "ac-1")
	_, err := svc.SuggestForStatement(sspID, implReqID, uuid.New())
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// ApplyForImplementedRequirement tests
// ---------------------------------------------------------------------------

func TestApplyForImplementedRequirement_CreatesComponentAndByComponent(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	const labelKey, labelValue = "plugin", "firewall"
	dc := seedDefinedComponentWithLabels(t, db, labelKey, labelValue)
	seedFilterForControl(t, db, "sc-7", labelKey, labelValue)
	seedEvidenceWithLabel(t, db, labelKey, labelValue)
	sspID, implReqID := seedSSPWithImplReq(t, db, "sc-7")

	err := svc.ApplyForImplementedRequirement(sspID, implReqID)
	require.NoError(t, err)

	// Get the SystemImplementation ID to verify the component was created
	var systemImpl SystemImplementation
	require.NoError(t, db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error)

	// Assert a SystemComponent was created
	var comp SystemComponent
	require.NoError(t, db.Where("system_implementation_id = ? AND defined_component_id = ?", systemImpl.ID, dc.ID).First(&comp).Error)
	assert.Equal(t, dc.Type, comp.Type)
	assert.Equal(t, dc.Title, comp.Title)
	assert.Equal(t, *dc.ID, *comp.DefinedComponentID)

	// Assert a ByComponent was created linking back to the ImplementedRequirement
	var bc ByComponent
	require.NoError(t, db.Where("component_uuid = ?", comp.ID).First(&bc).Error)
	assert.Equal(t, *comp.ID, bc.ComponentUUID)
	assert.Equal(t, implReqID, *bc.ParentID)
}

func TestApplyForImplementedRequirement_Idempotent(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	const labelKey, labelValue = "plugin", "firewall"
	seedDefinedComponentWithLabels(t, db, labelKey, labelValue)
	seedFilterForControl(t, db, "sc-7", labelKey, labelValue)
	seedEvidenceWithLabel(t, db, labelKey, labelValue)
	sspID, implReqID := seedSSPWithImplReq(t, db, "sc-7")

	// Apply twice
	require.NoError(t, svc.ApplyForImplementedRequirement(sspID, implReqID))
	require.NoError(t, svc.ApplyForImplementedRequirement(sspID, implReqID))

	// Get the SystemImplementation ID to verify the count
	var systemImpl SystemImplementation
	require.NoError(t, db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error)

	// Should still be exactly one SystemComponent (no duplicates)
	var count int64
	db.Model(&SystemComponent{}).Where("system_implementation_id = ?", systemImpl.ID).Count(&count)
	assert.Equal(t, int64(1), count)
}

func TestApplyForImplementedRequirement_NoSuggestions(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	sspID, implReqID := seedSSPWithImplReq(t, db, "ac-3")

	err := svc.ApplyForImplementedRequirement(sspID, implReqID)
	require.NoError(t, err)

	// Get the SystemImplementation ID to verify the count
	var systemImpl SystemImplementation
	require.NoError(t, db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error)

	var count int64
	db.Model(&SystemComponent{}).Where("system_implementation_id = ?", systemImpl.ID).Count(&count)
	assert.Equal(t, int64(0), count)
}

func TestApplyForStatement_CreatesByComponentLinkedToStatement(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	const labelKey, labelValue = "plugin", "firewall"
	dc := seedDefinedComponentWithLabels(t, db, labelKey, labelValue)
	seedFilterForControl(t, db, "sc-7", labelKey, labelValue)
	seedEvidenceWithLabel(t, db, labelKey, labelValue)
	sspID, implReqID := seedSSPWithImplReq(t, db, "sc-7")
	stmtID := seedStatementForImplReq(t, db, implReqID, "sc-7_smt.a")

	err := svc.ApplyForStatement(sspID, implReqID, stmtID)
	require.NoError(t, err)

	var systemImpl SystemImplementation
	require.NoError(t, db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error)

	var comp SystemComponent
	require.NoError(t, db.Where("system_implementation_id = ? AND defined_component_id = ?", systemImpl.ID, dc.ID).First(&comp).Error)

	var bc ByComponent
	require.NoError(t, db.Where("component_uuid = ?", comp.ID).First(&bc).Error)
	require.NotNil(t, bc.ParentID)
	require.NotNil(t, bc.ParentType)
	assert.Equal(t, stmtID, *bc.ParentID)
	assert.Equal(t, "statements", *bc.ParentType)
}

// ---------------------------------------------------------------------------
// ApplyForSSP tests
// ---------------------------------------------------------------------------

func TestApplyForSSP_ProcessesAllImplReqs(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	// Seed components + filters + evidence for two different controls
	seedDefinedComponentWithLabels(t, db, "plugin", "auditd")
	seedFilterForControl(t, db, "au-1", "plugin", "auditd")
	seedEvidenceWithLabel(t, db, "plugin", "auditd")

	seedDefinedComponentWithLabels(t, db, "plugin", "rsyslog")
	seedFilterForControl(t, db, "au-2", "plugin", "rsyslog")
	seedEvidenceWithLabel(t, db, "plugin", "rsyslog")

	// Build an SSP with two ImplementedRequirements
	ssp := SystemSecurityPlan{}
	require.NoError(t, db.Create(&ssp).Error)

	si := SystemImplementation{SystemSecurityPlanId: *ssp.ID}
	require.NoError(t, db.Create(&si).Error)

	ci := ControlImplementation{Description: "ci", SystemSecurityPlanId: *ssp.ID}
	require.NoError(t, db.Create(&ci).Error)

	ir1 := ImplementedRequirement{ControlId: "au-1", ControlImplementationId: *ci.ID}
	ir2 := ImplementedRequirement{ControlId: "au-2", ControlImplementationId: *ci.ID}
	require.NoError(t, db.Create(&ir1).Error)
	require.NoError(t, db.Create(&ir2).Error)

	err := svc.ApplyForSSP(*ssp.ID)
	require.NoError(t, err)

	var count int64
	db.Model(&SystemComponent{}).Where("system_implementation_id = ?", si.ID).Count(&count)
	assert.Equal(t, int64(2), count, "one SystemComponent should be created per ImplementedRequirement")
}

func TestApplyForSSP_SSPNotFound(t *testing.T) {
	db := setupTestDB(t)
	svc := NewSystemComponentSuggestionService(db, &mockEvidenceQuerier{db: db})

	err := svc.ApplyForSSP(uuid.New())
	assert.Error(t, err)
}
