package oscal

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestGetControlIDsForAllProfilesFallsBackForProfilesMissingPivotRows(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`
		CREATE TABLE profile_controls (
			profile_id TEXT NOT NULL,
			control_catalog_id TEXT NOT NULL,
			control_id TEXT NOT NULL
		)
	`).Error)

	profileWithPivot := uuid.New()
	profileWithoutPivot := uuid.New()
	catalogID := uuid.New()
	require.NoError(t, db.Exec(
		"INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		profileWithPivot.String(),
		catalogID.String(),
		"ac-1",
	).Error)

	handler := NewSystemSecurityPlanHandler(zap.NewNop().Sugar(), db, nil, nil)
	handler.profileCache.Store(profileWithoutPivot, []string{"ac-2"})

	controlIDs, err := handler.getControlIDsForAllProfiles([]relational.Profile{
		{UUIDModel: relational.UUIDModel{ID: &profileWithPivot}},
		{UUIDModel: relational.UUIDModel{ID: &profileWithoutPivot}},
	})

	require.NoError(t, err)
	require.ElementsMatch(t, []string{"ac-1", "ac-2"}, controlIDs)
}
