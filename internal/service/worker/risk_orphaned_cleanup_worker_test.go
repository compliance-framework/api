package worker

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type stubProfileControlResolver struct {
	controls map[uuid.UUID][]riskrel.ControlKey
	calls    []uuid.UUID
}

func (s *stubProfileControlResolver) ResolveProfileControlKeys(_ context.Context, profileID uuid.UUID) ([]riskrel.ControlKey, error) {
	s.calls = append(s.calls, profileID)
	return s.controls[profileID], nil
}

func createOrphanedCleanupRisk(t *testing.T, db *gorm.DB, sspID uuid.UUID, controlID string) uuid.UUID {
	t.Helper()

	riskID := uuid.New()
	templateID := uuid.New()
	catalogID := uuid.New()

	require.NoError(t, db.Create(&riskrel.Risk{
		UUIDModel:      relational.UUIDModel{ID: &riskID},
		Title:          "Auto-generated risk",
		Description:    "Risk created from remediation template",
		Status:         string(riskrel.RiskStatusOpen),
		SSPID:          sspID,
		RiskTemplateID: &templateID,
		SourceType:     string(riskrel.RiskSourceTypeEvidenceAuto),
	}).Error)
	require.NoError(t, db.Create(&riskrel.RiskControlLink{
		RiskID:    riskID,
		CatalogID: catalogID,
		ControlID: controlID,
	}).Error)

	return riskID
}

func TestRiskOrphanedCleanupWorker_UsesCurrentSSPProfileForStaleJob(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	sspID := uuid.New()
	staleProfileID := uuid.New()
	currentProfileID := uuid.New()

	// Create a profile row so GORM Preload("Profiles") can resolve the M:M join.
	require.NoError(t, db.Exec(
		`INSERT INTO profiles (id) VALUES (?)`, currentProfileID.String(),
	).Error)
	require.NoError(t, db.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
		ProfileID: &currentProfileID,
	}).Error)
	// Populate ssp_profiles join table for the M:M relationship.
	require.NoError(t, db.Exec(
		`INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)`,
		sspID.String(), currentProfileID.String(),
	).Error)
	riskID := createOrphanedCleanupRisk(t, db, sspID, "AC-1")

	resolver := &stubProfileControlResolver{
		controls: map[uuid.UUID][]riskrel.ControlKey{
			currentProfileID: {{ControlID: "AC-1"}},
			staleProfileID:   {{ControlID: "AC-2"}},
		},
	}
	worker := NewRiskOrphanedCleanupWorker(db, riskrel.NewRiskService(db), resolver, zap.NewNop().Sugar())

	err := worker.Work(context.Background(), makeWorkerJob(RiskOrphanedCleanupArgs{
		SSPID:        sspID,
		NewProfileID: &staleProfileID,
	}))
	require.NoError(t, err)

	assert.Equal(t, []uuid.UUID{currentProfileID}, resolver.calls)

	var risk riskrel.Risk
	require.NoError(t, db.First(&risk, "id = ?", riskID).Error)
	assert.Equal(t, string(riskrel.RiskStatusOpen), risk.Status)
}

func TestRiskOrphanedCleanupWorker_CurrentProfileUnboundRemediatesAllAutoRisks(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	sspID := uuid.New()
	staleProfileID := uuid.New()

	require.NoError(t, db.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
		ProfileID: nil,
	}).Error)
	riskID := createOrphanedCleanupRisk(t, db, sspID, "AC-1")

	resolver := &stubProfileControlResolver{
		controls: map[uuid.UUID][]riskrel.ControlKey{
			staleProfileID: {{ControlID: "AC-1"}},
		},
	}
	worker := NewRiskOrphanedCleanupWorker(db, riskrel.NewRiskService(db), resolver, zap.NewNop().Sugar())

	err := worker.Work(context.Background(), makeWorkerJob(RiskOrphanedCleanupArgs{
		SSPID:        sspID,
		NewProfileID: &staleProfileID,
	}))
	require.NoError(t, err)

	assert.Empty(t, resolver.calls)

	var risk riskrel.Risk
	require.NoError(t, db.First(&risk, "id = ?", riskID).Error)
	assert.Equal(t, string(riskrel.RiskStatusRemediated), risk.Status)

	var eventCount int64
	require.NoError(t, db.Model(&riskrel.RiskEvent{}).Where("risk_id = ?", riskID).Count(&eventCount).Error)
	assert.Equal(t, int64(1), eventCount)
}

func TestRiskOrphanedCleanupWorker_MissingSSPSkipsWithoutRetry(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	profileID := uuid.New()
	resolver := &stubProfileControlResolver{
		controls: map[uuid.UUID][]riskrel.ControlKey{
			profileID: {{ControlID: "AC-1"}},
		},
	}
	worker := NewRiskOrphanedCleanupWorker(db, riskrel.NewRiskService(db), resolver, zap.NewNop().Sugar())

	err := worker.Work(context.Background(), makeWorkerJob(RiskOrphanedCleanupArgs{
		SSPID:        uuid.New(),
		NewProfileID: &profileID,
	}))
	require.NoError(t, err)
	assert.Empty(t, resolver.calls)
}
