package worker

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newOrphanTestDB creates an in-memory SQLite database with all tables needed
// for the orphaned controls tests. It extends the base risk test DB with the
// Profile, Control (profile_controls join table), and RiskControlLink models.
func newOrphanTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&relational.SystemSecurityPlan{},
		&relational.Profile{},
		&relational.Control{},
		&riskrel.Risk{},
		&riskrel.RiskControlLink{},
		&riskrel.RiskEvent{},
	))
	return db
}

// seedOrphanScenario inserts the common objects shared across test cases:
// a catalog, a profile, an SSP bound to that profile, and a risk template ID.
func seedOrphanScenario(t *testing.T, db *gorm.DB) (catalogID, profileID, sspID, templateID uuid.UUID) {
	t.Helper()
	catalogID = uuid.New()
	profileID = uuid.New()
	sspID = uuid.New()
	templateID = uuid.New()

	profile := relational.Profile{UUIDModel: relational.UUIDModel{ID: &profileID}}
	require.NoError(t, db.Create(&profile).Error)

	ssp := relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
		ProfileID: &profileID,
	}
	require.NoError(t, db.Create(&ssp).Error)
	return
}

// seedControl inserts a control into the catalog and links it to the profile
// via the profile_controls join table.
func seedControl(t *testing.T, db *gorm.DB, catalogID, profileID uuid.UUID, controlID string) {
	t.Helper()
	ctrl := relational.Control{CatalogID: catalogID, ID: controlID, Title: controlID}
	require.NoError(t, db.Create(&ctrl).Error)

	// Insert into the profile_controls join table directly.
	require.NoError(t, db.Exec(
		"INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		profileID.String(), catalogID.String(), controlID,
	).Error)
}

// seedRiskWithControlLink inserts an open auto-generated risk and links it to a control.
func seedRiskWithControlLink(t *testing.T, db *gorm.DB, sspID, catalogID, templateID uuid.UUID, controlID string) uuid.UUID {
	t.Helper()
	riskID := uuid.New()
	r := riskrel.Risk{
		UUIDModel:      relational.UUIDModel{ID: &riskID},
		Title:          "Auto Risk",
		Description:    "auto-generated",
		Status:         string(riskrel.RiskStatusOpen),
		SSPID:          sspID,
		SourceType:     string(riskrel.RiskSourceTypeEvidenceAuto),
		RiskTemplateID: &templateID,
		FirstSeenAt:    time.Now().UTC(),
		LastSeenAt:     time.Now().UTC(),
	}
	require.NoError(t, db.Create(&r).Error)
	require.NoError(t, db.Create(&riskrel.RiskControlLink{
		RiskID:    riskID,
		CatalogID: catalogID,
		ControlID: controlID,
	}).Error)
	return riskID
}

// ---------------------------------------------------------------------------
// Unit tests for RiskOrphanedControlsWorker.Work
// ---------------------------------------------------------------------------

// TestRiskOrphanedControlsWorker_ProfileUnbound verifies that when the SSP has
// no profile (profile_id = NULL), a risk with control links is orphaned and
// transitioned to remediated.
func TestRiskOrphanedControlsWorker_ProfileUnbound(t *testing.T) {
	db := newOrphanTestDB(t)
	logger := zap.NewNop().Sugar()

	catalogID := uuid.New()
	sspID := uuid.New()
	templateID := uuid.New()

	// SSP with NO profile bound.
	ssp := relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}
	require.NoError(t, db.Create(&ssp).Error)

	riskID := seedRiskWithControlLink(t, db, sspID, catalogID, templateID, "AC-1")

	w := NewRiskOrphanedControlsWorker(db, logger)
	job := &river.Job[RiskOrphanedControlsArgs]{Args: RiskOrphanedControlsArgs{RiskID: riskID}}
	require.NoError(t, w.Work(context.Background(), job))

	var updated riskrel.Risk
	require.NoError(t, db.First(&updated, "id = ?", riskID).Error)
	assert.Equal(t, string(riskrel.RiskStatusRemediated), updated.Status,
		"risk should be remediated when SSP has no profile")

	// Verify audit event was emitted.
	var events []riskrel.RiskEvent
	require.NoError(t, db.Where("risk_id = ?", riskID).Find(&events).Error)
	assert.Len(t, events, 1)
}

// TestRiskOrphanedControlsWorker_ControlStillInProfile verifies that a risk is
// NOT transitioned when at least one of its controls still exists in the SSP's
// current profile.
func TestRiskOrphanedControlsWorker_ControlStillInProfile(t *testing.T) {
	db := newOrphanTestDB(t)
	logger := zap.NewNop().Sugar()

	catalogID, profileID, sspID, templateID := seedOrphanScenario(t, db)
	// Seed the control into the profile — risk is NOT orphaned.
	seedControl(t, db, catalogID, profileID, "AC-2")
	riskID := seedRiskWithControlLink(t, db, sspID, catalogID, templateID, "AC-2")

	w := NewRiskOrphanedControlsWorker(db, logger)
	job := &river.Job[RiskOrphanedControlsArgs]{Args: RiskOrphanedControlsArgs{RiskID: riskID}}
	require.NoError(t, w.Work(context.Background(), job))

	var updated riskrel.Risk
	require.NoError(t, db.First(&updated, "id = ?", riskID).Error)
	assert.Equal(t, string(riskrel.RiskStatusOpen), updated.Status,
		"risk should remain open when its control still exists in the profile")
}

// TestRiskOrphanedControlsWorker_ControlRemovedFromProfile verifies that a risk
// is transitioned to remediated when its control was removed from the profile
// (profile swap scenario).
func TestRiskOrphanedControlsWorker_ControlRemovedFromProfile(t *testing.T) {
	db := newOrphanTestDB(t)
	logger := zap.NewNop().Sugar()

	catalogID, profileID, sspID, templateID := seedOrphanScenario(t, db)
	// Seed a DIFFERENT control into the profile — the risk's control is absent.
	seedControl(t, db, catalogID, profileID, "SI-1")
	riskID := seedRiskWithControlLink(t, db, sspID, catalogID, templateID, "AC-3")

	w := NewRiskOrphanedControlsWorker(db, logger)
	job := &river.Job[RiskOrphanedControlsArgs]{Args: RiskOrphanedControlsArgs{RiskID: riskID}}
	require.NoError(t, w.Work(context.Background(), job))

	var updated riskrel.Risk
	require.NoError(t, db.First(&updated, "id = ?", riskID).Error)
	assert.Equal(t, string(riskrel.RiskStatusRemediated), updated.Status,
		"risk should be remediated when its control is absent from the new profile")
}

// TestRiskOrphanedControlsWorker_SkipsManualRisk verifies that manually created
// risks (RiskTemplateID == nil) are never orphaned regardless of profile state.
func TestRiskOrphanedControlsWorker_SkipsManualRisk(t *testing.T) {
	db := newOrphanTestDB(t)
	logger := zap.NewNop().Sugar()

	catalogID := uuid.New()
	sspID := uuid.New()
	ssp := relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}
	require.NoError(t, db.Create(&ssp).Error)

	riskID := uuid.New()
	r := riskrel.Risk{
		UUIDModel:      relational.UUIDModel{ID: &riskID},
		Title:          "Manual Risk",
		Description:    "manually created",
		Status:         string(riskrel.RiskStatusOpen),
		SSPID:          sspID,
		SourceType:     string(riskrel.RiskSourceTypeManual),
		RiskTemplateID: nil, // manually created — no template
		FirstSeenAt:    time.Now().UTC(),
		LastSeenAt:     time.Now().UTC(),
	}
	require.NoError(t, db.Create(&r).Error)
	require.NoError(t, db.Create(&riskrel.RiskControlLink{
		RiskID:    riskID,
		CatalogID: catalogID,
		ControlID: "AC-4",
	}).Error)

	w := NewRiskOrphanedControlsWorker(db, logger)
	job := &river.Job[RiskOrphanedControlsArgs]{Args: RiskOrphanedControlsArgs{RiskID: riskID}}
	require.NoError(t, w.Work(context.Background(), job))

	var updated riskrel.Risk
	require.NoError(t, db.First(&updated, "id = ?", riskID).Error)
	assert.Equal(t, string(riskrel.RiskStatusOpen), updated.Status,
		"manually created risk should never be orphaned")
}

// TestRiskOrphanedControlsWorker_SkipsAlreadyTerminal verifies that risks
// already in a terminal state (closed, remediated) are skipped.
func TestRiskOrphanedControlsWorker_SkipsAlreadyTerminal(t *testing.T) {
	db := newOrphanTestDB(t)
	logger := zap.NewNop().Sugar()

	catalogID := uuid.New()
	sspID := uuid.New()
	templateID := uuid.New()
	ssp := relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}
	require.NoError(t, db.Create(&ssp).Error)

	for _, status := range []riskrel.RiskStatus{riskrel.RiskStatusClosed, riskrel.RiskStatusRemediated} {
		riskID := uuid.New()
		r := riskrel.Risk{
			UUIDModel:      relational.UUIDModel{ID: &riskID},
			Title:          "Terminal Risk",
			Description:    "already terminal",
			Status:         string(status),
			SSPID:          sspID,
			SourceType:     string(riskrel.RiskSourceTypeEvidenceAuto),
			RiskTemplateID: &templateID,
			FirstSeenAt:    time.Now().UTC(),
			LastSeenAt:     time.Now().UTC(),
		}
		require.NoError(t, db.Create(&r).Error)
		require.NoError(t, db.Create(&riskrel.RiskControlLink{
			RiskID:    riskID,
			CatalogID: catalogID,
			ControlID: "AC-5",
		}).Error)

		w := NewRiskOrphanedControlsWorker(db, logger)
		job := &river.Job[RiskOrphanedControlsArgs]{Args: RiskOrphanedControlsArgs{RiskID: riskID}}
		require.NoError(t, w.Work(context.Background(), job))

		var updated riskrel.Risk
		require.NoError(t, db.First(&updated, "id = ?", riskID).Error)
		assert.Equal(t, string(status), updated.Status,
			"terminal risk should not be transitioned by orphan worker")
	}
}

// TestRiskOrphanedControlsWorker_DeletedRiskIsNoop verifies that if the risk
// was deleted between the scanner scan and the worker execution, Work returns nil.
func TestRiskOrphanedControlsWorker_DeletedRiskIsNoop(t *testing.T) {
	db := newOrphanTestDB(t)
	logger := zap.NewNop().Sugar()

	nonExistentID := uuid.New()
	w := NewRiskOrphanedControlsWorker(db, logger)
	job := &river.Job[RiskOrphanedControlsArgs]{Args: RiskOrphanedControlsArgs{RiskID: nonExistentID}}
	assert.NoError(t, w.Work(context.Background(), job),
		"worker should return nil for a risk that no longer exists")
}

// ---------------------------------------------------------------------------
// Unit tests for the reconciliation scanner Pass 2 (orphan candidate query)
// ---------------------------------------------------------------------------

// TestReconciliationScannerPass2_EnqueuesOrphanJobs verifies that the
// reconciliation scanner's Pass 2 enqueues RiskOrphanedControlsArgs jobs for
// all open auto-generated risks that have at least one control link.
func TestReconciliationScannerPass2_EnqueuesOrphanJobs(t *testing.T) {
	db := newOrphanTestDB(t)
	logger := zap.NewNop().Sugar()
	client := &stubRiverClient{}

	catalogID := uuid.New()
	sspID := uuid.New()
	templateID := uuid.New()
	ssp := relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}
	require.NoError(t, db.Create(&ssp).Error)

	// Risk 1: open, auto-generated, has a control link → should be enqueued.
	riskID1 := seedRiskWithControlLink(t, db, sspID, catalogID, templateID, "AC-6")

	// Risk 2: open but manually created (no template) → should NOT be enqueued.
	riskID2 := uuid.New()
	r2 := riskrel.Risk{
		UUIDModel:   relational.UUIDModel{ID: &riskID2},
		Title:       "Manual",
		Description: "manual",
		Status:      string(riskrel.RiskStatusOpen),
		SSPID:       sspID,
		SourceType:  string(riskrel.RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}
	require.NoError(t, db.Create(&r2).Error)

	// Risk 3: remediated auto-generated risk → should NOT be enqueued.
	riskID3 := uuid.New()
	r3 := riskrel.Risk{
		UUIDModel:      relational.UUIDModel{ID: &riskID3},
		Title:          "Remediated",
		Description:    "remediated",
		Status:         string(riskrel.RiskStatusRemediated),
		SSPID:          sspID,
		SourceType:     string(riskrel.RiskSourceTypeEvidenceAuto),
		RiskTemplateID: &templateID,
		FirstSeenAt:    time.Now().UTC(),
		LastSeenAt:     time.Now().UTC(),
	}
	require.NoError(t, db.Create(&r3).Error)
	require.NoError(t, db.Create(&riskrel.RiskControlLink{
		RiskID:    riskID3,
		CatalogID: catalogID,
		ControlID: "AC-7",
	}).Error)

	scanner := NewRiskEvidenceReconciliationScannerWorker(db, client, logger)
	job := &river.Job[RiskEvidenceReconciliationScannerArgs]{}
	require.NoError(t, scanner.Work(context.Background(), job))

	// Only riskID1 should produce an orphan job.
	var orphanJobs []river.InsertManyParams
	for _, p := range client.params {
		if _, ok := p.Args.(RiskOrphanedControlsArgs); ok {
			orphanJobs = append(orphanJobs, p)
		}
	}
	require.Len(t, orphanJobs, 1, "scanner should enqueue exactly one orphan job")
	assert.Equal(t, riskID1, orphanJobs[0].Args.(RiskOrphanedControlsArgs).RiskID)
}

// TestReconciliationScannerPass2_NoOrphans verifies that when there are no
// open auto-generated risks with control links, no orphan jobs are enqueued.
func TestReconciliationScannerPass2_NoOrphans(t *testing.T) {
	db := newOrphanTestDB(t)
	logger := zap.NewNop().Sugar()
	client := &stubRiverClient{}

	scanner := NewRiskEvidenceReconciliationScannerWorker(db, client, logger)
	job := &river.Job[RiskEvidenceReconciliationScannerArgs]{}
	require.NoError(t, scanner.Work(context.Background(), job))

	for _, p := range client.params {
		_, isOrphan := p.Args.(RiskOrphanedControlsArgs)
		assert.False(t, isOrphan, "no orphan jobs should be enqueued when DB is empty")
	}
}
