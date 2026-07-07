package oscal

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func statementID(s string) *string { return &s }

// TestComputeOfferingContentHashIsOrderIndependent: the same items in a different
// slice order (as could happen depending on how they were fetched from the DB) must
// hash identically — otherwise a no-op republish would look like a content change.
func TestComputeOfferingContentHashIsOrderIndependent(t *testing.T) {
	a := relational.SSPExportOfferingItem{ControlID: "ac-1", ComponentUUID: uuid.New(), ProvidedUUID: uuid.New()}
	b := relational.SSPExportOfferingItem{ControlID: "ac-2", StatementID: statementID("ac-2_stmt.a"), ComponentUUID: uuid.New(), ProvidedUUID: uuid.New()}

	hash1 := computeOfferingContentHash("Title", "Description", []relational.SSPExportOfferingItem{a, b})
	hash2 := computeOfferingContentHash("Title", "Description", []relational.SSPExportOfferingItem{b, a})

	require.Equal(t, hash1, hash2)
}

// TestComputeOfferingContentHashChangesWithContent: any real change to title,
// description, or an item's fields must change the hash.
func TestComputeOfferingContentHashChangesWithContent(t *testing.T) {
	items := []relational.SSPExportOfferingItem{
		{ControlID: "ac-1", ComponentUUID: uuid.New(), ProvidedUUID: uuid.New()},
	}
	base := computeOfferingContentHash("Title", "Description", items)

	require.NotEqual(t, base, computeOfferingContentHash("Different Title", "Description", items))
	require.NotEqual(t, base, computeOfferingContentHash("Title", "Different Description", items))

	changedItems := []relational.SSPExportOfferingItem{
		{ControlID: "ac-2", ComponentUUID: items[0].ComponentUUID, ProvidedUUID: items[0].ProvidedUUID},
	}
	require.NotEqual(t, base, computeOfferingContentHash("Title", "Description", changedItems))
}

func newSyncExportOfferingTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SSPExportOffering{}, &relational.SSPExportOfferingItem{}))
	return db
}

// TestSyncExportOfferingBumpsVersionOnlyWhenContentChanges: calling SyncExportOffering
// on an offering whose content hasn't changed since the last sync must be a no-op (no
// version bump); it must only bump when an item was actually added.
func TestSyncExportOfferingBumpsVersionOnlyWhenContentChanges(t *testing.T) {
	db := newSyncExportOfferingTestDB(t)

	offering := relational.SSPExportOffering{SSPID: uuid.New(), Title: "Offering", Status: relational.SSPExportOfferingStatusDraft}
	require.NoError(t, db.Create(&offering).Error)
	require.NoError(t, db.Create(&relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-1", ComponentUUID: uuid.New(), ProvidedUUID: uuid.New(),
	}).Error)

	// First sync: no hash stored yet, so this must bump the version and set the hash.
	require.NoError(t, SyncExportOffering(db, *offering.ID))
	var afterFirst relational.SSPExportOffering
	require.NoError(t, db.First(&afterFirst, "id = ?", offering.ID).Error)
	require.Equal(t, 1, afterFirst.Version)
	require.NotEmpty(t, afterFirst.ContentHash)

	// Republish with no content change: must be a no-op.
	require.NoError(t, SyncExportOffering(db, *offering.ID))
	var afterSecond relational.SSPExportOffering
	require.NoError(t, db.First(&afterSecond, "id = ?", offering.ID).Error)
	require.Equal(t, 1, afterSecond.Version)
	require.Equal(t, afterFirst.ContentHash, afterSecond.ContentHash)

	// Add an item, then sync again: content changed, so this must bump the version.
	require.NoError(t, db.Create(&relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-2", ComponentUUID: uuid.New(), ProvidedUUID: uuid.New(),
	}).Error)
	require.NoError(t, SyncExportOffering(db, *offering.ID))
	var afterChange relational.SSPExportOffering
	require.NoError(t, db.First(&afterChange, "id = ?", offering.ID).Error)
	require.Equal(t, 2, afterChange.Version)
	require.NotEqual(t, afterFirst.ContentHash, afterChange.ContentHash)
}
