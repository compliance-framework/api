package oscal

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newResponsibilityPostureTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&relational.Filter{},
		&relational.FilterResponsibility{},
	))
	return db
}

// TestResponsibilityPostureEmptyInput covers the case that doesn't reach the
// Postgres-only status-count query (GetLatestEvidenceStreamsQuery uses "DISTINCT ON",
// unsupported by sqlite) — the satisfied/not-satisfied cases that do reach it are
// covered by the integration suite instead, matching the existing test split for
// getStatusCountsForFilters/ComplianceProgress.
func TestResponsibilityPostureEmptyInput(t *testing.T) {
	db := newResponsibilityPostureTestDB(t)

	posture, err := ResponsibilityPosture(db, uuid.New(), nil)
	require.NoError(t, err)
	require.Empty(t, posture)
}

// TestResponsibilityPostureDefaultsToUnknownWhenNoFilterTargetsIt asserts that every
// requested responsibility uuid is always present in the returned map — defaulting to
// "unknown" — even when no filter_responsibilities row targets it at all, matching
// bulkResolveUpstreamResponsibilities's "never an absent key" convention.
func TestResponsibilityPostureDefaultsToUnknownWhenNoFilterTargetsIt(t *testing.T) {
	db := newResponsibilityPostureTestDB(t)

	downstreamSSPID := uuid.New()
	responsibilityUUID := uuid.New()

	posture, err := ResponsibilityPosture(db, downstreamSSPID, []uuid.UUID{responsibilityUUID})
	require.NoError(t, err)
	require.Equal(t, map[uuid.UUID]string{responsibilityUUID: "unknown"}, posture)
}

// TestResponsibilityPostureIgnoresRowScopedToDifferentSSP asserts that a
// filter_responsibilities row scoped to a different downstream SSP than the one asked
// about doesn't affect the result — it stays "unknown" for the requested SSP, since a
// responsibility's posture is always evaluated per-downstream-SSP (a filter targeting
// SSP A's leverage of a responsibility says nothing about SSP B's leverage of it).
func TestResponsibilityPostureIgnoresRowScopedToDifferentSSP(t *testing.T) {
	db := newResponsibilityPostureTestDB(t)

	responsibilityUUID := uuid.New()
	otherSSPID := uuid.New()
	requestedSSPID := uuid.New()

	filterID := uuid.New()
	require.NoError(t, db.Create(&relational.Filter{
		UUIDModel: relational.UUIDModel{ID: &filterID},
		Name:      "other-ssp-filter",
	}).Error)
	require.NoError(t, db.Create(&relational.FilterResponsibility{
		FilterID:           filterID,
		ResponsibilityUUID: responsibilityUUID,
		SSPID:              otherSSPID,
	}).Error)

	posture, err := ResponsibilityPosture(db, requestedSSPID, []uuid.UUID{responsibilityUUID})
	require.NoError(t, err)
	require.Equal(t, map[uuid.UUID]string{responsibilityUUID: "unknown"}, posture)
}
