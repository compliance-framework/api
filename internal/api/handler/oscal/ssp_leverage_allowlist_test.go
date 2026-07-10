package oscal

import (
	"net/http"
	"testing"

	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestIsDownstreamAllowedDefaultsTrueWhenNoAllowListSet(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)

	allowed, err := isDownstreamAllowed(db, fx.offeringID, fx.downstreamSSPID)
	require.NoError(t, err)
	require.True(t, allowed)
}

func TestIsDownstreamAllowedTrueWhenListed(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	require.NoError(t, db.Create(&relational.SSPExportOfferingAllowedDownstream{
		OfferingID: fx.offeringID, DownstreamSSPID: fx.downstreamSSPID,
	}).Error)

	allowed, err := isDownstreamAllowed(db, fx.offeringID, fx.downstreamSSPID)
	require.NoError(t, err)
	require.True(t, allowed)
}

func TestIsDownstreamAllowedFalseWhenNotListed(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	// Allow-list has an entry, but not for fx.downstreamSSPID — some other SSP.
	require.NoError(t, db.Create(&relational.SSPExportOfferingAllowedDownstream{
		OfferingID: fx.offeringID, DownstreamSSPID: uuid.New(),
	}).Error)

	allowed, err := isDownstreamAllowed(db, fx.offeringID, fx.downstreamSSPID)
	require.NoError(t, err)
	require.False(t, allowed)
}

func TestSubscribeRejectsNonAllowListedDownstream(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	require.NoError(t, db.Create(&relational.SSPExportOfferingAllowedDownstream{
		OfferingID: fx.offeringID, DownstreamSSPID: uuid.New(),
	}).Error)

	pdp := &stubPDP{allow: true}
	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)

	body := subscribeBody(fx.downstreamSSPID, fx.itemID, fx.respAID)
	ctx, e, rec := newSubscribeRequestContext(fx.offeringID, body)
	err := h.Subscribe(ctx)
	require.Error(t, err)
	e.HTTPErrorHandler(err, ctx)
	require.Equal(t, http.StatusForbidden, rec.Code)

	var count int64
	require.NoError(t, db.Model(&relational.SSPLeverageLink{}).Count(&count).Error)
	require.Zero(t, count, "a rejected subscribe must not create a leverage link")
}

func TestSubscribeAllowsAllowListedDownstream(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	require.NoError(t, db.Create(&relational.SSPExportOfferingAllowedDownstream{
		OfferingID: fx.offeringID, DownstreamSSPID: fx.downstreamSSPID,
	}).Error)

	pdp := &stubPDP{allow: true}
	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)

	body := subscribeBody(fx.downstreamSSPID, fx.itemID, fx.respAID)
	ctx, _, rec := newSubscribeRequestContext(fx.offeringID, body)
	require.NoError(t, h.Subscribe(ctx))
	require.Equal(t, http.StatusCreated, rec.Code)
}

func TestSubscribeAllowsAnyDownstreamWhenNoAllowListSet(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)

	pdp := &stubPDP{allow: true}
	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)

	body := subscribeBody(fx.downstreamSSPID, fx.itemID, fx.respAID)
	ctx, _, rec := newSubscribeRequestContext(fx.offeringID, body)
	require.NoError(t, h.Subscribe(ctx))
	require.Equal(t, http.StatusCreated, rec.Code)
}
