package risks

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createAutoRisk creates a risk linked to a template (auto-generated) with the
// given status and control link. Returns the created risk.
func createAutoRisk(t *testing.T, svc *RiskService, sspID uuid.UUID, status RiskStatus, controlID string, catalogID uuid.UUID) *Risk {
	t.Helper()
	templateID := uuid.New()
	likelihood := "moderate"
	impact := "moderate"
	r, err := svc.Create(CreateRiskParams{
		Risk: Risk{
			Title:          "Test risk " + controlID,
			Description:    "auto-generated",
			Likelihood:     &likelihood,
			Impact:         &impact,
			Status:         string(status),
			SSPID:          sspID,
			RiskTemplateID: &templateID,
			SourceType:     string(RiskSourceTypeEvidenceAuto),
		},
	})
	require.NoError(t, err)
	require.NotNil(t, r)

	link := &RiskControlLink{
		RiskID:    *r.ID,
		CatalogID: catalogID,
		ControlID: controlID,
	}
	require.NoError(t, svc.db.Create(link).Error)
	return r
}

// createManualRisk creates a risk with no template (manually created).
func createManualRisk(t *testing.T, svc *RiskService, sspID uuid.UUID, status RiskStatus, controlID string, catalogID uuid.UUID) *Risk {
	t.Helper()
	likelihood := "low"
	impact := "low"
	r, err := svc.Create(CreateRiskParams{
		Risk: Risk{
			Title:       "Manual risk " + controlID,
			Description: "manual",
			Likelihood:  &likelihood,
			Impact:      &impact,
			Status:      string(status),
			SSPID:       sspID,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, r)

	if controlID != "" {
		link := &RiskControlLink{
			RiskID:    *r.ID,
			CatalogID: catalogID,
			ControlID: controlID,
		}
		require.NoError(t, svc.db.Create(link).Error)
	}
	return r
}

// TestRemediateOrphanedRisks_NoOp verifies that when all risk controls are
// still present in the new profile set, no risks are remediated.
func TestRemediateOrphanedRisks_NoOp(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	sspID := uuid.New()
	catalogID := uuid.New()

	risk := createAutoRisk(t, svc, sspID, RiskStatusOpen, "AC-1", catalogID)

	profileSet := map[ControlKey]struct{}{
		{ControlID: "AC-1"}: {},
	}

	n, err := svc.RemediateOrphanedRisks(db, sspID, profileSet)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "no risks should be remediated when controls are still present")

	var updated Risk
	require.NoError(t, db.First(&updated, "id = ?", risk.ID).Error)
	assert.Equal(t, string(RiskStatusOpen), updated.Status, "risk status should remain open")
}

// TestRemediateOrphanedRisks_PartialRemediation verifies that only risks whose
// controls are absent from the new profile set are remediated.
func TestRemediateOrphanedRisks_PartialRemediation(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	sspID := uuid.New()
	catalogID := uuid.New()

	kept := createAutoRisk(t, svc, sspID, RiskStatusOpen, "AC-1", catalogID)
	orphaned := createAutoRisk(t, svc, sspID, RiskStatusOpen, "AC-2", catalogID)

	// New profile only has AC-1; AC-2 is removed.
	profileSet := map[ControlKey]struct{}{
		{ControlID: "AC-1"}: {},
	}

	n, err := svc.RemediateOrphanedRisks(db, sspID, profileSet)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "exactly one risk should be remediated")

	var keptRisk Risk
	require.NoError(t, db.First(&keptRisk, "id = ?", kept.ID).Error)
	assert.Equal(t, string(RiskStatusOpen), keptRisk.Status, "AC-1 risk should remain open")

	var orphanedRisk Risk
	require.NoError(t, db.First(&orphanedRisk, "id = ?", orphaned.ID).Error)
	assert.Equal(t, string(RiskStatusRemediated), orphanedRisk.Status, "AC-2 risk should be remediated")
}

// TestRemediateOrphanedRisks_FullUnbind verifies that when an empty profile
// set is passed (profile unbound), all auto-generated open risks are remediated.
func TestRemediateOrphanedRisks_FullUnbind(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	sspID := uuid.New()
	catalogID := uuid.New()

	r1 := createAutoRisk(t, svc, sspID, RiskStatusOpen, "AC-1", catalogID)
	r2 := createAutoRisk(t, svc, sspID, RiskStatusOpen, "AC-2", catalogID)

	n, err := svc.RemediateOrphanedRisks(db, sspID, map[ControlKey]struct{}{})
	require.NoError(t, err)
	assert.Equal(t, 2, n, "both risks should be remediated on full unbind")

	for _, id := range []*uuid.UUID{r1.ID, r2.ID} {
		var r Risk
		require.NoError(t, db.First(&r, "id = ?", id).Error)
		assert.Equal(t, string(RiskStatusRemediated), r.Status)
	}
}

// TestRemediateOrphanedRisks_SkipsManualRisks verifies that manually created
// risks (no RiskTemplateID) are never remediated even if their control is removed.
func TestRemediateOrphanedRisks_SkipsManualRisks(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	sspID := uuid.New()
	catalogID := uuid.New()

	manual := createManualRisk(t, svc, sspID, RiskStatusOpen, "AC-1", catalogID)

	// Profile set is empty — would remediate auto risks, but not manual ones.
	n, err := svc.RemediateOrphanedRisks(db, sspID, map[ControlKey]struct{}{})
	require.NoError(t, err)
	assert.Equal(t, 0, n, "manual risks must not be remediated")

	var r Risk
	require.NoError(t, db.First(&r, "id = ?", manual.ID).Error)
	assert.Equal(t, string(RiskStatusOpen), r.Status)
}

func TestRemediateOrphanedRisks_SkipsManualRisksWithTemplate(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	sspID := uuid.New()
	catalogID := uuid.New()
	templateID := uuid.New()
	likelihood := "low"
	impact := "low"

	risk, err := svc.Create(CreateRiskParams{
		Risk: Risk{
			Title:          "Manual template-backed risk",
			Description:    "manual",
			Likelihood:     &likelihood,
			Impact:         &impact,
			Status:         string(RiskStatusOpen),
			SSPID:          sspID,
			RiskTemplateID: &templateID,
			SourceType:     string(RiskSourceTypeManual),
		},
	})
	require.NoError(t, err)
	require.NoError(t, db.Create(&RiskControlLink{
		RiskID:    *risk.ID,
		CatalogID: catalogID,
		ControlID: "AC-1",
	}).Error)

	n, err := svc.RemediateOrphanedRisks(db, sspID, map[ControlKey]struct{}{})
	require.NoError(t, err)
	assert.Equal(t, 0, n, "manual risks must not be remediated even when template-backed")

	var updated Risk
	require.NoError(t, db.First(&updated, "id = ?", risk.ID).Error)
	assert.Equal(t, string(RiskStatusOpen), updated.Status)
}

// TestRemediateOrphanedRisks_SkipsTerminalRisks verifies that risks already in
// a terminal state (remediated, closed) are not touched.
func TestRemediateOrphanedRisks_SkipsTerminalRisks(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	sspID := uuid.New()
	catalogID := uuid.New()

	alreadyRemediated := createAutoRisk(t, svc, sspID, RiskStatusRemediated, "AC-1", catalogID)
	alreadyClosed := createAutoRisk(t, svc, sspID, RiskStatusClosed, "AC-2", catalogID)

	n, err := svc.RemediateOrphanedRisks(db, sspID, map[ControlKey]struct{}{})
	require.NoError(t, err)
	assert.Equal(t, 0, n, "terminal risks must not be re-remediated")

	for _, id := range []*uuid.UUID{alreadyRemediated.ID, alreadyClosed.ID} {
		var r Risk
		require.NoError(t, db.First(&r, "id = ?", id).Error)
		// Status should be unchanged.
		assert.NotEqual(t, string(RiskStatusOpen), r.Status)
	}
}

// TestRemediateOrphanedRisks_EmitsStatusChangeEvent verifies that a
// status_changed RiskEvent is emitted for each remediated risk.
func TestRemediateOrphanedRisks_EmitsStatusChangeEvent(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	sspID := uuid.New()
	catalogID := uuid.New()

	risk := createAutoRisk(t, svc, sspID, RiskStatusOpen, "AC-1", catalogID)

	n, err := svc.RemediateOrphanedRisks(db, sspID, map[ControlKey]struct{}{})
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	var events []RiskEvent
	require.NoError(t, db.
		Where("risk_id = ? AND event_type = ?", risk.ID, string(RiskEventTypeStatusChange)).
		Find(&events).Error)
	assert.Len(t, events, 1, "one status_changed event should be emitted")
	assert.Equal(t, string(RiskEventTypeStatusChange), events[0].EventType)
	assert.NotEmpty(t, events[0].RiskSnapshot, "status_changed event should include the standard risk snapshot")
	assert.Equal(t, string(RiskStatusRemediated), events[0].RiskSnapshot["status"])
}

// TestRemediateOrphanedRisks_CatalogIDFallback verifies that a risk linked with
// a full CatalogID+ControlID key is still matched when the profile set only
// provides a bare ControlID (no CatalogID).
func TestRemediateOrphanedRisks_CatalogIDFallback(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	sspID := uuid.New()
	catalogID := uuid.New()

	// Risk is linked with a full catalog+control key.
	kept := createAutoRisk(t, svc, sspID, RiskStatusOpen, "AC-1", catalogID)

	// Profile set only has a bare control ID (no CatalogID) — as produced by
	// the profile resolution layer in AttachProfile.
	profileSet := map[ControlKey]struct{}{
		{CatalogID: "", ControlID: "AC-1"}: {},
	}

	n, err := svc.RemediateOrphanedRisks(db, sspID, profileSet)
	require.NoError(t, err)
	assert.Equal(t, 0, n, "risk should not be orphaned when matched by bare ControlID")

	var r Risk
	require.NoError(t, db.First(&r, "id = ?", kept.ID).Error)
	assert.Equal(t, string(RiskStatusOpen), r.Status)
}

// TestRemediateOrphanedRisks_IsolatedBySSP verifies that risks belonging to a
// different SSP are not affected.
func TestRemediateOrphanedRisks_IsolatedBySSP(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	sspA := uuid.New()
	sspB := uuid.New()
	catalogID := uuid.New()

	riskA := createAutoRisk(t, svc, sspA, RiskStatusOpen, "AC-1", catalogID)
	riskB := createAutoRisk(t, svc, sspB, RiskStatusOpen, "AC-1", catalogID)

	// Unbind sspA entirely.
	n, err := svc.RemediateOrphanedRisks(db, sspA, map[ControlKey]struct{}{})
	require.NoError(t, err)
	assert.Equal(t, 1, n, "only sspA risk should be remediated")

	var rA Risk
	require.NoError(t, db.First(&rA, "id = ?", riskA.ID).Error)
	assert.Equal(t, string(RiskStatusRemediated), rA.Status, "sspA risk should be remediated")

	var rB Risk
	require.NoError(t, db.First(&rB, "id = ?", riskB.ID).Error)
	assert.Equal(t, string(RiskStatusOpen), rB.Status, "sspB risk must not be touched")
}
