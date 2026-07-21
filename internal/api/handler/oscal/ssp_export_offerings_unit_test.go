package oscal

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
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

	hash1 := computeOfferingContentHash("Title", "Description", []relational.SSPExportOfferingItem{a, b}, nil)
	hash2 := computeOfferingContentHash("Title", "Description", []relational.SSPExportOfferingItem{b, a}, nil)

	require.Equal(t, hash1, hash2)
}

// TestComputeOfferingContentHashChangesWithContent: any real change to title,
// description, or an item's fields must change the hash.
func TestComputeOfferingContentHashChangesWithContent(t *testing.T) {
	items := []relational.SSPExportOfferingItem{
		{ControlID: "ac-1", ComponentUUID: uuid.New(), ProvidedUUID: uuid.New()},
	}
	base := computeOfferingContentHash("Title", "Description", items, nil)

	require.NotEqual(t, base, computeOfferingContentHash("Different Title", "Description", items, nil))
	require.NotEqual(t, base, computeOfferingContentHash("Title", "Different Description", items, nil))

	changedItems := []relational.SSPExportOfferingItem{
		{ControlID: "ac-2", ComponentUUID: items[0].ComponentUUID, ProvidedUUID: items[0].ProvidedUUID},
	}
	require.NotEqual(t, base, computeOfferingContentHash("Title", "Description", changedItems, nil))
}

func newSyncExportOfferingTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&relational.SSPExportOffering{},
		&relational.SSPExportOfferingItem{},
		&relational.ProvidedControlImplementation{},
		&relational.Export{},
		&relational.ByComponent{},
		&relational.SSPLeverageLink{},
		&relational.ControlImplementationResponsibility{},
		&relational.Profile{},
		&relational.Control{},
		&relational.SSPProfile{},
		&risks.Risk{},
		&risks.RiskEvent{},
		&risks.RiskScore{},
		&risks.RiskResponsibilityLink{},
		&risks.RiskControlLink{},
	))
	return db
}

// TestSyncExportOfferingBumpsVersionOnImplementationStatusDowngrade: a backing
// ByComponent's ImplementationStatus downgrading (implemented -> planned) is a content
// change even though none of an item's own fields (ControlID/StatementID/ComponentUUID/
// ProvidedUUID) changed — this is the "downgrading a provided status" drift trigger
// (BCH-1341), resolved live via item.ProvidedUUID -> ProvidedControlImplementation.
// ExportId -> Export.ByComponentId -> ByComponent.ImplementationStatus.
func TestSyncExportOfferingBumpsVersionOnImplementationStatusDowngrade(t *testing.T) {
	db := newSyncExportOfferingTestDB(t)

	byComponent := relational.ByComponent{
		ImplementationStatus: datatypes.NewJSONType(relational.ImplementationStatus{State: relational.ImplementationStatusImplemented}),
	}
	require.NoError(t, db.Create(&byComponent).Error)

	export := relational.Export{ByComponentId: *byComponent.ID}
	require.NoError(t, db.Create(&export).Error)

	provided := relational.ProvidedControlImplementation{ExportId: *export.ID}
	require.NoError(t, db.Create(&provided).Error)

	offering := relational.SSPExportOffering{SSPID: uuid.New(), Title: "Offering", Status: relational.SSPExportOfferingStatusDraft}
	require.NoError(t, db.Create(&offering).Error)
	require.NoError(t, db.Create(&relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-1", ComponentUUID: byComponent.ComponentUUID, ProvidedUUID: *provided.ID,
	}).Error)

	_, err := SyncExportOffering(db, *offering.ID)
	require.NoError(t, err)
	var afterFirst relational.SSPExportOffering
	require.NoError(t, db.First(&afterFirst, "id = ?", offering.ID).Error)
	require.Equal(t, 1, afterFirst.Version)

	// Re-sync with no change: no-op.
	_, err = SyncExportOffering(db, *offering.ID)
	require.NoError(t, err)
	var afterNoop relational.SSPExportOffering
	require.NoError(t, db.First(&afterNoop, "id = ?", offering.ID).Error)
	require.Equal(t, 1, afterNoop.Version)

	// Downgrade the backing component's status, then re-sync: must bump.
	require.NoError(t, db.Model(&byComponent).Update(
		"implementation_status", datatypes.NewJSONType(relational.ImplementationStatus{State: relational.ImplementationStatusPlanned}),
	).Error)
	_, err = SyncExportOffering(db, *offering.ID)
	require.NoError(t, err)
	var afterDowngrade relational.SSPExportOffering
	require.NoError(t, db.First(&afterDowngrade, "id = ?", offering.ID).Error)
	require.Equal(t, 2, afterDowngrade.Version)
	require.NotEqual(t, afterFirst.ContentHash, afterDowngrade.ContentHash)
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
	_, err := SyncExportOffering(db, *offering.ID)
	require.NoError(t, err)
	var afterFirst relational.SSPExportOffering
	require.NoError(t, db.First(&afterFirst, "id = ?", offering.ID).Error)
	require.Equal(t, 1, afterFirst.Version)
	require.NotEmpty(t, afterFirst.ContentHash)

	// Republish with no content change: must be a no-op.
	_, err = SyncExportOffering(db, *offering.ID)
	require.NoError(t, err)
	var afterSecond relational.SSPExportOffering
	require.NoError(t, db.First(&afterSecond, "id = ?", offering.ID).Error)
	require.Equal(t, 1, afterSecond.Version)
	require.Equal(t, afterFirst.ContentHash, afterSecond.ContentHash)

	// Add an item, then sync again: content changed, so this must bump the version.
	require.NoError(t, db.Create(&relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-2", ComponentUUID: uuid.New(), ProvidedUUID: uuid.New(),
	}).Error)
	_, err = SyncExportOffering(db, *offering.ID)
	require.NoError(t, err)
	var afterChange relational.SSPExportOffering
	require.NoError(t, db.First(&afterChange, "id = ?", offering.ID).Error)
	require.Equal(t, 2, afterChange.Version)
	require.NotEqual(t, afterFirst.ContentHash, afterChange.ContentHash)
}

// TestSyncExportOfferingDriftsLeverageLinksOnVersionBump: re-syncing an offering whose
// content actually changed (BCH-1341) must drift every active leverage link pointing at
// it — the version-bump trigger, exercised through the real public entrypoint rather
// than evaluateLeverageDriftForOffering directly.
func TestSyncExportOfferingDriftsLeverageLinksOnVersionBump(t *testing.T) {
	db := newSyncExportOfferingTestDB(t)

	export := relational.Export{}
	require.NoError(t, db.Create(&export).Error)
	provided := relational.ProvidedControlImplementation{ExportId: *export.ID}
	require.NoError(t, db.Create(&provided).Error)

	offering := relational.SSPExportOffering{SSPID: uuid.New(), Title: "Offering", Status: relational.SSPExportOfferingStatusDraft}
	require.NoError(t, db.Create(&offering).Error)
	require.NoError(t, db.Create(&relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-1", ComponentUUID: uuid.New(), ProvidedUUID: *provided.ID,
	}).Error)

	// First sync sets Version=1; subscribe snapshots that as the link's OfferingVersion.
	_, err := SyncExportOffering(db, *offering.ID)
	require.NoError(t, err)

	link := relational.SSPLeverageLink{
		DownstreamSSPID: uuid.New(), UpstreamSSPID: offering.SSPID, OfferingID: *offering.ID, OfferingVersion: 1,
		ControlID: "ac-1", ProvidedUUID: *provided.ID, InheritedUUID: uuid.New(),
		Satisfaction: relational.SSPLeverageSatisfactionFull, Status: relational.SSPLeverageStatusActive,
	}
	require.NoError(t, db.Create(&link).Error)

	// Change content, then re-sync: Version bumps to 2, link is now behind.
	require.NoError(t, db.Create(&relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-2", ComponentUUID: uuid.New(), ProvidedUUID: uuid.New(),
	}).Error)
	driftedLinks, err := SyncExportOffering(db, *offering.ID)
	require.NoError(t, err)
	require.Len(t, driftedLinks, 1)
	require.Equal(t, *link.ID, driftedLinks[0].LinkID)

	var reloadedLink relational.SSPLeverageLink
	require.NoError(t, db.First(&reloadedLink, "id = ?", link.ID).Error)
	require.Equal(t, relational.SSPLeverageStatusDrifted, reloadedLink.Status)

	var riskCount int64
	require.NoError(t, db.Model(&risks.Risk{}).Where("source_type = ?", string(risks.RiskSourceTypeInheritedRevoked)).Count(&riskCount).Error)
	require.Equal(t, int64(1), riskCount)
}

// TestSyncExportOfferingAbortsOnConcurrentModification: SyncExportOffering reads the
// offering once to snapshot UpdatedAt before recomputing the hash, then again inside its
// write transaction. If another write lands in between those two reads, it must abort
// rather than commit a hash computed from data that's already stale. A query callback
// deterministically injects that concurrent write right after the first read completes
// and before the transactional re-read runs, rather than relying on goroutine timing.
func TestSyncExportOfferingAbortsOnConcurrentModification(t *testing.T) {
	db := newSyncExportOfferingTestDB(t)

	offering := relational.SSPExportOffering{SSPID: uuid.New(), Title: "Offering", Status: relational.SSPExportOfferingStatusDraft}
	require.NoError(t, db.Create(&offering).Error)

	var queryCount int
	require.NoError(t, db.Callback().Query().After("gorm:query").
		Register("test:simulate-concurrent-write", func(*gorm.DB) {
			queryCount++
			if queryCount == 1 {
				require.NoError(t, db.Exec(
					"UPDATE ssp_export_offerings SET updated_at = ? WHERE id = ?",
					time.Now().Add(time.Hour), offering.ID.String(),
				).Error)
			}
		}))
	t.Cleanup(func() { _ = db.Callback().Query().Remove("test:simulate-concurrent-write") })

	_, err := SyncExportOffering(db, *offering.ID)
	require.Error(t, err)

	var reloaded relational.SSPExportOffering
	require.NoError(t, db.First(&reloaded, "id = ?", offering.ID).Error)
	require.Equal(t, 0, reloaded.Version)
	require.Empty(t, reloaded.ContentHash)
}
