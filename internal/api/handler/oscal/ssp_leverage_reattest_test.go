package oscal

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func newReAttestRequestContext(sspID, linkID uuid.UUID) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id", "linkId")
	ctx.SetParamValues(sspID.String(), linkID.String())
	return ctx, rec
}

// subscribeAndDrift subscribes fx's downstream SSP to fx's offering item (satisfying
// respAID), then simulates an upstream content change bumping the offering's Version and
// drifts the resulting link — returning the now-drifted link and its drift risk id.
func subscribeAndDrift(t *testing.T, db *gorm.DB, fx leverageFixture) (relational.SSPLeverageLink, uuid.UUID) {
	t.Helper()

	pdp := &stubPDP{allow: true}
	subscribeHandler := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)
	body := subscribeBody(fx.downstreamSSPID, fx.itemID, fx.respAID)
	ctx, _, rec := newSubscribeRequestContext(fx.offeringID, body)
	require.NoError(t, subscribeHandler.Subscribe(ctx))
	require.Equal(t, http.StatusCreated, rec.Code)

	var link relational.SSPLeverageLink
	require.NoError(t, db.Where("downstream_ssp_id = ?", fx.downstreamSSPID).First(&link).Error)

	require.NoError(t, db.Model(&relational.SSPExportOffering{}).Where("id = ?", fx.offeringID).Update("version", 2).Error)
	var offering relational.SSPExportOffering
	require.NoError(t, db.First(&offering, "id = ?", fx.offeringID).Error)

	info, ok, err := applyDriftToLink(db, &link, "upstream offering content changed")
	require.NoError(t, err)
	require.True(t, ok)

	require.NoError(t, db.First(&link, "id = ?", link.ID).Error)
	return link, info.RiskID
}

func TestReAttestClearsDriftAndRemediatesRisk(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	link, riskID := subscribeAndDrift(t, db, fx)
	require.Equal(t, relational.SSPLeverageStatusDrifted, link.Status)

	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, &stubPDP{allow: true}, authz.FailClosed)
	ctx, rec := newReAttestRequestContext(fx.downstreamSSPID, *link.ID)
	require.NoError(t, h.ReAttest(ctx))
	require.Equal(t, http.StatusOK, rec.Code)

	var reloadedLink relational.SSPLeverageLink
	require.NoError(t, db.First(&reloadedLink, "id = ?", link.ID).Error)
	require.Equal(t, relational.SSPLeverageStatusActive, reloadedLink.Status)
	require.Equal(t, 2, reloadedLink.OfferingVersion)
	require.NotNil(t, reloadedLink.AttestedAt)

	var risk risks.Risk
	require.NoError(t, db.First(&risk, "id = ?", riskID).Error)
	require.Equal(t, string(risks.RiskStatusRemediated), risk.Status)
}

func TestReAttestRejectsNonDriftedLink(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)

	pdp := &stubPDP{allow: true}
	subscribeHandler := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)
	body := subscribeBody(fx.downstreamSSPID, fx.itemID, fx.respAID)
	ctx, _, rec := newSubscribeRequestContext(fx.offeringID, body)
	require.NoError(t, subscribeHandler.Subscribe(ctx))
	require.Equal(t, http.StatusCreated, rec.Code)

	var link relational.SSPLeverageLink
	require.NoError(t, db.Where("downstream_ssp_id = ?", fx.downstreamSSPID).First(&link).Error)
	require.Equal(t, relational.SSPLeverageStatusActive, link.Status)

	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, &stubPDP{allow: true}, authz.FailClosed)
	attestCtx, attestRec := newReAttestRequestContext(fx.downstreamSSPID, *link.ID)
	require.NoError(t, h.ReAttest(attestCtx))
	require.Equal(t, http.StatusBadRequest, attestRec.Code)
}

func TestReAttestRejectsWrongDownstreamSSP(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	link, _ := subscribeAndDrift(t, db, fx)

	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, &stubPDP{allow: true}, authz.FailClosed)
	ctx, rec := newReAttestRequestContext(uuid.New(), *link.ID)
	require.NoError(t, h.ReAttest(ctx))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

// TestReAttestRejectsWhenLinkNoLongerDriftedAtUpdateTime: ReAttest's pre-check reads the
// link once (must be Drifted) before opening its transaction. If the link stops being
// Drifted in between that read and the transaction's own update — a concurrent
// re-attest, or a fresh drift landing right after — the update must not silently
// overwrite that newer state. A query callback deterministically injects the concurrent
// change right after the pre-check read completes and before the transactional update
// runs, mirroring TestSyncExportOfferingAbortsOnConcurrentModification's technique.
func TestReAttestRejectsWhenLinkNoLongerDriftedAtUpdateTime(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	link, riskID := subscribeAndDrift(t, db, fx)
	require.Equal(t, relational.SSPLeverageStatusDrifted, link.Status)

	var queryCount int
	require.NoError(t, db.Callback().Query().After("gorm:query").
		Register("test:simulate-concurrent-reattest", func(*gorm.DB) {
			queryCount++
			if queryCount == 1 {
				// Simulate a concurrent request winning the race and clearing drift first.
				require.NoError(t, db.Exec(
					"UPDATE ssp_leverage_links SET status = ? WHERE id = ?",
					string(relational.SSPLeverageStatusActive), link.ID.String(),
				).Error)
			}
		}))
	t.Cleanup(func() { _ = db.Callback().Query().Remove("test:simulate-concurrent-reattest") })

	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, &stubPDP{allow: true}, authz.FailClosed)
	ctx, rec := newReAttestRequestContext(fx.downstreamSSPID, *link.ID)
	require.NoError(t, h.ReAttest(ctx))
	require.Equal(t, http.StatusConflict, rec.Code)

	// The concurrent write's state must survive untouched — no bogus double-attest.
	var reloadedLink relational.SSPLeverageLink
	require.NoError(t, db.First(&reloadedLink, "id = ?", link.ID).Error)
	require.Equal(t, relational.SSPLeverageStatusActive, reloadedLink.Status)
	require.Equal(t, 1, reloadedLink.OfferingVersion, "the losing request must not have bumped OfferingVersion")

	var risk risks.Risk
	require.NoError(t, db.First(&risk, "id = ?", riskID).Error)
	require.Equal(t, string(risks.RiskStatusOpen), risk.Status, "the losing request must not have remediated the risk")
}
