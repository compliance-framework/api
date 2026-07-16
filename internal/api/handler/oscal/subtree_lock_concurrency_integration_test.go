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
	fx := suite.seedTwoResponsibilityFixture()

	// Both writers target the same by-component, each satisfying one of the two responsibilities.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	responsibilities := []uuid.UUID{fx.respAID, fx.respBID}

	wg.Add(len(responsibilities))
	for i, respID := range responsibilities {
		go func(i int, respID uuid.UUID) {
			defer wg.Done()
			errs[i] = suite.DB.Transaction(func(tx *gorm.DB) error {
				if err := lockByComponentSubtreeWrite(tx, fx.byComponentID); err != nil {
					return err
				}
				satisfied := relational.SatisfiedControlImplementationResponsibility{
					ByComponentId:      fx.byComponentID,
					ResponsibilityUuid: respID,
					Description:        "satisfied concurrently",
				}
				if err := tx.Create(&satisfied).Error; err != nil {
					return err
				}
				return resyncLeverageSatisfaction(tx, fx.downstreamSSPID, fx.byComponentID)
			})
		}(i, respID)
	}
	wg.Wait()

	for i, err := range errs {
		suite.Require().NoErrorf(err, "concurrent satisfied write %d failed", i)
	}

	var satisfiedCount int64
	suite.Require().NoError(suite.DB.Model(&relational.SatisfiedControlImplementationResponsibility{}).
		Where("by_component_id = ?", fx.byComponentID).Count(&satisfiedCount).Error)
	suite.Require().Equal(int64(2), satisfiedCount, "both satisfied rows must persist")

	var link relational.SSPLeverageLink
	suite.Require().NoError(suite.DB.First(&link, "id = ?", fx.linkID).Error)
	suite.Equal(relational.SSPLeverageSatisfactionFull, link.Satisfaction,
		"both responsibilities are satisfied, so the stored satisfaction must be full — "+
			"`partial` means one writer's derivation overwrote the other's with a stale value")
}

// TestConcurrentSatisfiedWriteAndInheritedDeleteDoNotDangle: a satisfied create and a delete of the
// inherited row it depends on, racing. Whichever order they serialize in, the result must be
// coherent — the delete is either refused (the link owns the row) or the satisfied row is rejected
// as no longer inheritable. What must never happen is a surviving link whose inherited row is gone.
func (suite *SubtreeLockConcurrencySuite) TestConcurrentSatisfiedWriteAndInheritedDeleteDoNotDangle() {
	fx := suite.seedTwoResponsibilityFixture()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_ = suite.DB.Transaction(func(tx *gorm.DB) error {
			if err := lockByComponentSubtreeWrite(tx, fx.byComponentID); err != nil {
				return err
			}
			satisfied := relational.SatisfiedControlImplementationResponsibility{
				ByComponentId:      fx.byComponentID,
				ResponsibilityUuid: fx.respAID,
				Description:        "satisfied during delete",
			}
			if err := tx.Create(&satisfied).Error; err != nil {
				return err
			}
			return resyncLeverageSatisfaction(tx, fx.downstreamSSPID, fx.byComponentID)
		})
	}()

	go func() {
		defer wg.Done()
		_ = suite.DB.Transaction(func(tx *gorm.DB) error {
			if err := lockByComponentSubtreeWrite(tx, fx.byComponentID); err != nil {
				return err
			}
			if err := assertInheritedNotSubscribed(tx, []uuid.UUID{fx.inheritedID}); err != nil {
				return err
			}
			return tx.Delete(&relational.InheritedControlImplementation{}, "id = ?", fx.inheritedID).Error
		})
	}()

	wg.Wait()

	// The link is owned by a subscription, so the delete must have been refused outright: the
	// inherited row survives and nothing dangles.
	var inheritedCount int64
	suite.Require().NoError(suite.DB.Model(&relational.InheritedControlImplementation{}).
		Where("id = ?", fx.inheritedID).Count(&inheritedCount).Error)
	suite.Equal(int64(1), inheritedCount,
		"the inherited row is referenced by a leverage link, so it must never be deleted")

	var link relational.SSPLeverageLink
	suite.Require().NoError(suite.DB.First(&link, "id = ?", fx.linkID).Error)
	suite.Equal(fx.inheritedID, link.InheritedUUID, "link.InheritedUUID must still resolve")
}

type subtreeLockFixture struct {
	downstreamSSPID uuid.UUID
	byComponentID   uuid.UUID
	inheritedID     uuid.UUID
	linkID          uuid.UUID
	respAID         uuid.UUID
	respBID         uuid.UUID
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
		downstreamSSPID: *downstreamSSP.ID,
		byComponentID:   *downstreamBC.ID,
		inheritedID:     *inherited.ID,
		linkID:          *link.ID,
		respAID:         *respA.ID,
		respBID:         *respB.ID,
	}
}
