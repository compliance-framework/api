//go:build integration

package oscal

import (
	"sync"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

// SubtreeLockConcurrencySuite drives the race lockByComponentSubtreeWrite exists to prevent,
// against real Postgres.
//
// TestEveryLeverageSatisfactionWriterTakesTheSubtreeLock pins the invariant structurally, which is
// necessary but not sufficient: the lock is a Postgres advisory lock and a no-op under the sqlite
// unit driver, so every unit test in this package would stay green if the lock's body were replaced
// with `return nil`. Nothing else exercises two concurrent writers against one by-component. This
// suite closes that gap — it is the test that would actually go red.
type SubtreeLockConcurrencySuite struct {
	tests.IntegrationTestSuite
}

func TestSubtreeLockConcurrencySuite(t *testing.T) {
	suite.Run(t, new(SubtreeLockConcurrencySuite))
}

func (suite *SubtreeLockConcurrencySuite) SetupTest() {
	suite.Require().NoError(suite.Migrator.Refresh())
}

// TestConcurrentSatisfiedWritesConvergeOnProjection: two goroutines each add a satisfied row
// covering a different responsibility of the same inherited capability, concurrently. Whoever
// commits second must observe the first's row, so the stored Satisfaction must end up `full` —
// matching what the live projection derives.
//
// Without the lock this is a lost update: both transactions read the satisfied set before either
// inserts, both derive `partial` from their own single row, and the second write clobbers the
// first's — leaving `partial` stored while both responsibilities are in fact satisfied. The drift
// detector and the notification path consume that stored value.
func (suite *SubtreeLockConcurrencySuite) TestConcurrentSatisfiedWritesConvergeOnProjection() {
	// Repeated over a fresh fixture each iteration: a single lucky interleaving must not be able
	// to carry the suite.
	for iter := 0; iter < 20; iter++ {
		fx := suite.seedTwoResponsibilityFixture()

		// Both writers target the same by-component, each satisfying one of the two responsibilities.
		var wg sync.WaitGroup
		errs := make([]error, 2)
		responsibilities := []uuid.UUID{fx.respAID, fx.respBID}

		// Rendezvous: both transactions must have inserted their satisfied row and still be open
		// when either one derives satisfaction. Without it, goroutine 1 routinely runs its whole
		// BEGIN → INSERT → resync → COMMIT before goroutine 2 opens a transaction, and the `full`
		// assertion below holds even with the lock removed — green for the wrong reason.
		//
		// The barrier sits AFTER the INSERT and BEFORE resyncLeverageSatisfaction, which is what
		// takes the advisory lock. It must never be crossed while holding that lock: if both
		// goroutines waited here with one of them holding it, the other could never arrive and the
		// test would deadlock rather than race.
		started := make(chan struct{}, 2)
		release := make(chan struct{})

		wg.Add(len(responsibilities))
		for i, respID := range responsibilities {
			go func(i int, respID uuid.UUID) {
				defer wg.Done()
				errs[i] = suite.DB.Transaction(func(tx *gorm.DB) error {
					satisfied := relational.SatisfiedControlImplementationResponsibility{
						ByComponentId:      fx.byComponentID,
						ResponsibilityUuid: respID,
						Description:        "satisfied concurrently",
					}
					if err := tx.Create(&satisfied).Error; err != nil {
						return err
					}
					started <- struct{}{}
					<-release
					// Takes lockByComponentSubtreeWrite itself; this is the read-modify-write the
					// lock exists to serialize.
					return resyncLeverageSatisfaction(tx, fx.downstreamSSPID, fx.byComponentID)
				})
			}(i, respID)
		}
		<-started
		<-started
		close(release)
		wg.Wait()

		for i, err := range errs {
			suite.Require().NoErrorf(err, "iteration %d: concurrent satisfied write %d failed", iter, i)
		}

		var satisfiedCount int64
		suite.Require().NoError(suite.DB.Model(&relational.SatisfiedControlImplementationResponsibility{}).
			Where("by_component_id = ?", fx.byComponentID).Count(&satisfiedCount).Error)
		suite.Require().Equalf(int64(2), satisfiedCount, "iteration %d: both satisfied rows must persist", iter)

		var link relational.SSPLeverageLink
		suite.Require().NoError(suite.DB.First(&link, "id = ?", fx.linkID).Error)
		suite.Require().Equalf(relational.SSPLeverageSatisfactionFull, link.Satisfaction,
			"iteration %d: both responsibilities are satisfied, so the stored satisfaction must be "+
				"full — `partial` means one writer's derivation overwrote the other's with a stale value", iter)
	}
}

// TestConcurrentSatisfiedWriteAndInheritedDeleteDoNotDangle: a satisfied create over one inherited
// row racing the DELETE of a SIBLING inherited row on the same by-component.
//
// The sibling deliberately has no leverage link (a hand-authored inherited entry), so
// assertInheritedNotSubscribed permits its delete — meaning the delete genuinely runs and the two
// transactions genuinely contend. Racing the delete of the LINKED row instead would prove nothing:
// assertInheritedNotSubscribed refuses it in every possible interleaving, so both assertions would
// hold with the lock deleted, run sequentially, or with the satisfied writer removed entirely.
//
// Both orderings are legal, so this asserts COHERENCE, not a winner: both transactions succeed, the
// unlinked row is gone, and the surviving link's stored Satisfaction equals what a fresh derivation
// over the final satisfied set produces — no stale value survived, and no satisfied row points at a
// deleted inherited row.
//
// SCOPE, stated so this is not over-trusted: this test is non-vacuous (the delete genuinely runs and
// the coherence assertions can fail on a dangling satisfied row or a stale satisfaction), but it is
// NOT lock-discriminating — it was verified to still pass with lockByComponentSubtreeWrite neutered.
// The lock-discriminating test in this suite is TestConcurrentSatisfiedWritesConvergeOnProjection,
// which was verified to go red ("full" -> "partial", a genuine lost update) without the lock. Do not
// treat a green run here as evidence the lock is present or working.
func (suite *SubtreeLockConcurrencySuite) TestConcurrentSatisfiedWriteAndInheritedDeleteDoNotDangle() {
	fx := suite.seedTwoResponsibilityFixture()

	var wg sync.WaitGroup
	errs := make([]error, 2)
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	wg.Add(2)

	// Satisfies BOTH responsibilities, so the derived satisfaction moves off the seeded `partial`
	// and a stale stored value is distinguishable from a freshly derived one.
	go func() {
		defer wg.Done()
		errs[0] = suite.DB.Transaction(func(tx *gorm.DB) error {
			for _, respID := range []uuid.UUID{fx.respAID, fx.respBID} {
				satisfied := relational.SatisfiedControlImplementationResponsibility{
					ByComponentId:      fx.byComponentID,
					ResponsibilityUuid: respID,
					Description:        "satisfied during delete",
				}
				if err := tx.Create(&satisfied).Error; err != nil {
					return err
				}
			}
			// Rendezvous before the advisory lock is taken — see the note in the lost-update test.
			started <- struct{}{}
			<-release
			return resyncLeverageSatisfaction(tx, fx.downstreamSSPID, fx.byComponentID)
		})
	}()

	go func() {
		defer wg.Done()
		errs[1] = suite.DB.Transaction(func(tx *gorm.DB) error {
			started <- struct{}{}
			<-release
			if err := lockByComponentSubtreeWrite(tx, fx.byComponentID); err != nil {
				return err
			}
			if err := assertInheritedNotSubscribed(tx, []uuid.UUID{fx.unlinkedInheritedID}); err != nil {
				return err
			}
			return tx.Delete(&relational.InheritedControlImplementation{}, "id = ?", fx.unlinkedInheritedID).Error
		})
	}()

	<-started
	<-started
	close(release)
	wg.Wait()

	suite.Require().NoError(errs[0], "the satisfied write must succeed")
	// The target row carries no leverage link, so the guard permits it in every interleaving.
	suite.Require().NoError(errs[1], "deleting the unsubscribed inherited row must succeed")

	// The satisfied write actually happened — without this the test could pass having exercised
	// nothing.
	var satisfiedCount int64
	suite.Require().NoError(suite.DB.Model(&relational.SatisfiedControlImplementationResponsibility{}).
		Where("by_component_id = ?", fx.byComponentID).Count(&satisfiedCount).Error)
	suite.Require().Equal(int64(2), satisfiedCount, "both satisfied rows must persist")

	var unlinkedCount int64
	suite.Require().NoError(suite.DB.Model(&relational.InheritedControlImplementation{}).
		Where("id = ?", fx.unlinkedInheritedID).Count(&unlinkedCount).Error)
	suite.Equal(int64(0), unlinkedCount, "the unsubscribed inherited row must be gone")

	// The linked row is untouched, so the link still resolves.
	var link relational.SSPLeverageLink
	suite.Require().NoError(suite.DB.First(&link, "id = ?", fx.linkID).Error)
	suite.Require().Equal(fx.inheritedID, link.InheritedUUID, "link.InheritedUUID must still resolve")

	var inheritedCount int64
	suite.Require().NoError(suite.DB.Model(&relational.InheritedControlImplementation{}).
		Where("id = ?", fx.inheritedID).Count(&inheritedCount).Error)
	suite.Require().Equal(int64(1), inheritedCount, "the subscribed inherited row must survive")

	// Coherence: whatever order the two transactions serialized in, the stored value must equal
	// what a fresh derivation over the FINAL satisfied set produces.
	suite.Require().Equal(relational.SSPLeverageSatisfactionFull, link.Satisfaction,
		"both responsibilities are satisfied, so the stored satisfaction must be full")
	settled := link.Satisfaction
	suite.Require().NoError(suite.DB.Transaction(func(tx *gorm.DB) error {
		return resyncLeverageSatisfaction(tx, fx.downstreamSSPID, fx.byComponentID)
	}))
	suite.Require().NoError(suite.DB.First(&link, "id = ?", fx.linkID).Error)
	suite.Equal(settled, link.Satisfaction,
		"a fresh resync must be a no-op — a change means the racing writers left a stale value")
}

type subtreeLockFixture struct {
	downstreamSSPID uuid.UUID
	byComponentID   uuid.UUID
	inheritedID     uuid.UUID
	// unlinkedInheritedID is a sibling inherited row on the same by-component that no
	// SSPLeverageLink references — the hand-authored shape resyncLeverageSatisfaction documents as
	// "no link, skipped silently". It is what makes a delete racing the satisfied write actually
	// reachable: assertInheritedNotSubscribed refuses the linked row unconditionally.
	unlinkedInheritedID uuid.UUID
	linkID              uuid.UUID
	respAID             uuid.UUID
	respBID             uuid.UUID
}

// seedTwoResponsibilityFixture builds an upstream capability carrying TWO responsibilities, a
// downstream by-component inheriting it, and the leverage link — the minimum shape where
// satisfaction is genuinely derived (partial vs full) rather than trivially constant.
func (suite *SubtreeLockConcurrencySuite) seedTwoResponsibilityFixture() subtreeLockFixture {
	db := suite.DB

	upstreamSSP := relational.SystemSecurityPlan{}
	suite.Require().NoError(db.Create(&upstreamSSP).Error)
	upstreamImpl := relational.ControlImplementation{SystemSecurityPlanId: *upstreamSSP.ID}
	suite.Require().NoError(db.Create(&upstreamImpl).Error)
	upstreamReq := relational.ImplementedRequirement{ControlImplementationId: *upstreamImpl.ID, ControlId: "ac-1"}
	suite.Require().NoError(db.Create(&upstreamReq).Error)
	upstreamStmt := relational.Statement{ImplementedRequirementId: *upstreamReq.ID, StatementId: "ac-1_smt.a"}
	suite.Require().NoError(db.Create(&upstreamStmt).Error)

	statementsType := "statements"
	upstreamBC := relational.ByComponent{ParentID: upstreamStmt.ID, ParentType: &statementsType}
	suite.Require().NoError(db.Create(&upstreamBC).Error)

	export := relational.Export{ByComponentId: *upstreamBC.ID}
	suite.Require().NoError(db.Create(&export).Error)
	provided := relational.ProvidedControlImplementation{ExportId: *export.ID, Description: "provided"}
	suite.Require().NoError(db.Create(&provided).Error)
	// A second capability, inherited downstream but never subscribed to — carries no
	// responsibilities, so it contributes nothing to the derived satisfaction of the linked one.
	providedUnlinked := relational.ProvidedControlImplementation{ExportId: *export.ID, Description: "provided (unlinked)"}
	suite.Require().NoError(db.Create(&providedUnlinked).Error)

	respA := relational.ControlImplementationResponsibility{
		ExportId: *export.ID, ProvidedUuid: *provided.ID, Description: "responsibility A",
	}
	suite.Require().NoError(db.Create(&respA).Error)
	respB := relational.ControlImplementationResponsibility{
		ExportId: *export.ID, ProvidedUuid: *provided.ID, Description: "responsibility B",
	}
	suite.Require().NoError(db.Create(&respB).Error)

	// Downstream side.
	downstreamSSP := relational.SystemSecurityPlan{}
	suite.Require().NoError(db.Create(&downstreamSSP).Error)
	downstreamImpl := relational.ControlImplementation{SystemSecurityPlanId: *downstreamSSP.ID}
	suite.Require().NoError(db.Create(&downstreamImpl).Error)
	downstreamReq := relational.ImplementedRequirement{ControlImplementationId: *downstreamImpl.ID, ControlId: "ac-1"}
	suite.Require().NoError(db.Create(&downstreamReq).Error)
	downstreamStmt := relational.Statement{ImplementedRequirementId: *downstreamReq.ID, StatementId: "ac-1_smt.a"}
	suite.Require().NoError(db.Create(&downstreamStmt).Error)
	downstreamBC := relational.ByComponent{ParentID: downstreamStmt.ID, ParentType: &statementsType}
	suite.Require().NoError(db.Create(&downstreamBC).Error)

	inherited := relational.InheritedControlImplementation{
		ByComponentId: *downstreamBC.ID, ProvidedUuid: *provided.ID, Description: "inherited",
	}
	suite.Require().NoError(db.Create(&inherited).Error)

	unlinkedInherited := relational.InheritedControlImplementation{
		ByComponentId: *downstreamBC.ID, ProvidedUuid: *providedUnlinked.ID, Description: "inherited (no link)",
	}
	suite.Require().NoError(db.Create(&unlinkedInherited).Error)

	// Starts `partial`: nothing is satisfied yet, so a stale value is distinguishable from a
	// freshly derived one.
	link := relational.SSPLeverageLink{
		DownstreamSSPID: *downstreamSSP.ID,
		UpstreamSSPID:   *upstreamSSP.ID,
		OfferingID:      uuid.New(),
		ControlID:       "ac-1",
		ProvidedUUID:    *provided.ID,
		InheritedUUID:   *inherited.ID,
		Satisfaction:    relational.SSPLeverageSatisfactionPartial,
		Status:          relational.SSPLeverageStatusActive,
	}
	suite.Require().NoError(db.Create(&link).Error)

	return subtreeLockFixture{
		downstreamSSPID:     *downstreamSSP.ID,
		byComponentID:       *downstreamBC.ID,
		inheritedID:         *inherited.ID,
		unlinkedInheritedID: *unlinkedInherited.ID,
		linkID:              *link.ID,
		respAID:             *respA.ID,
		respBID:             *respB.ID,
	}
}
