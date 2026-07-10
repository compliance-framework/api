package oscal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newPublishRequestContext(sspID, offeringID uuid.UUID) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id", "offeringId")
	ctx.SetParamValues(sspID.String(), offeringID.String())
	return ctx, rec
}

// spyJobEnqueuer records every EnqueueLeverageDriftNotification call so tests can assert
// exactly which (risk, link) pairs were enqueued, without needing a real River client.
type spyJobEnqueuer struct {
	calls []spyEnqueueCall
}

type spyEnqueueCall struct {
	RiskID          uuid.UUID
	LinkID          uuid.UUID
	DownstreamSSPID uuid.UUID
	Reason          string
}

func (s *spyJobEnqueuer) EnqueueOrphanedRiskCleanup(context.Context, uuid.UUID, *uuid.UUID, *uuid.UUID) error {
	return nil
}

func (s *spyJobEnqueuer) EnqueueDashboardSuggestionCells(context.Context, uuid.UUID, int) error {
	return nil
}

func (s *spyJobEnqueuer) EnqueueLeverageDriftNotification(_ context.Context, riskID, linkID, downstreamSSPID uuid.UUID, reason string) error {
	s.calls = append(s.calls, spyEnqueueCall{RiskID: riskID, LinkID: linkID, DownstreamSSPID: downstreamSSPID, Reason: reason})
	return nil
}

func TestPublishEnqueuesLeverageDriftNotificationOnVersionBump(t *testing.T) {
	db := newSyncExportOfferingTestDB(t)

	export := relational.Export{}
	require.NoError(t, db.Create(&export).Error)
	provided := relational.ProvidedControlImplementation{ExportId: *export.ID}
	require.NoError(t, db.Create(&provided).Error)

	upstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&upstreamSSP).Error)
	offering := relational.SSPExportOffering{SSPID: *upstreamSSP.ID, Title: "Offering", Status: relational.SSPExportOfferingStatusDraft}
	require.NoError(t, db.Create(&offering).Error)
	require.NoError(t, db.Create(&relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-1", ComponentUUID: uuid.New(), ProvidedUUID: *provided.ID,
	}).Error)

	spy := &spyJobEnqueuer{}
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, spy)

	// First publish: sets Version=1, no leverage links exist yet.
	ctx, rec := newPublishRequestContext(offering.SSPID, *offering.ID)
	require.NoError(t, h.Publish(ctx))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, spy.calls)

	downstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&downstreamSSP).Error)
	link := relational.SSPLeverageLink{
		DownstreamSSPID: *downstreamSSP.ID, UpstreamSSPID: *upstreamSSP.ID, OfferingID: *offering.ID, OfferingVersion: 1,
		ControlID: "ac-1", ProvidedUUID: *provided.ID, InheritedUUID: uuid.New(), LeveragedAuthUUID: uuid.New(),
		Satisfaction: relational.SSPLeverageSatisfactionFull, Status: relational.SSPLeverageStatusActive,
	}
	require.NoError(t, db.Create(&link).Error)

	// Change content, re-publish: Version bumps to 2, link drifts, notification enqueued.
	require.NoError(t, db.Create(&relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-2", ComponentUUID: uuid.New(), ProvidedUUID: uuid.New(),
	}).Error)
	ctx2, rec2 := newPublishRequestContext(offering.SSPID, *offering.ID)
	require.NoError(t, h.Publish(ctx2))
	require.Equal(t, http.StatusOK, rec2.Code)

	require.Len(t, spy.calls, 1)
	require.Equal(t, *link.ID, spy.calls[0].LinkID)
	require.Equal(t, link.DownstreamSSPID, spy.calls[0].DownstreamSSPID)
}

func TestUpdateOfferingStatusEnqueuesLeverageDriftNotification(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	offering, link := seedPublishedOfferingWithActiveLink(t, db)
	spy := &spyJobEnqueuer{}
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, spy)

	ctx, rec := newOfferingStatusRequestContext(offering.SSPID, *offering.ID, `{"status":"deprecated"}`)
	require.NoError(t, h.UpdateOfferingStatus(ctx))
	require.Equal(t, http.StatusOK, rec.Code)

	require.Len(t, spy.calls, 1)
	require.Equal(t, *link.ID, spy.calls[0].LinkID)
	require.Equal(t, "upstream offering deprecated", spy.calls[0].Reason)
}

func TestDeleteLeveragedAuthorizationEnqueuesLeverageDriftNotification(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	require.NoError(t, db.AutoMigrate(&relational.SystemImplementation{}, &relational.LeveragedAuthorization{}))

	ssp := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&ssp).Error)
	sysImpl := relational.SystemImplementation{SystemSecurityPlanId: *ssp.ID}
	require.NoError(t, db.Create(&sysImpl).Error)
	auth := relational.LeveragedAuthorization{Title: "Trust", PartyUUID: uuid.New(), SystemImplementationId: *sysImpl.ID}
	require.NoError(t, db.Create(&auth).Error)

	upstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&upstreamSSP).Error)
	downstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&downstreamSSP).Error)
	export := relational.Export{}
	require.NoError(t, db.Create(&export).Error)
	provided := relational.ProvidedControlImplementation{ExportId: *export.ID}
	require.NoError(t, db.Create(&provided).Error)
	offering := relational.SSPExportOffering{SSPID: *upstreamSSP.ID, Title: "Offering", Status: relational.SSPExportOfferingStatusPublished, Version: 1}
	require.NoError(t, db.Create(&offering).Error)
	link := relational.SSPLeverageLink{
		DownstreamSSPID: *downstreamSSP.ID, UpstreamSSPID: *upstreamSSP.ID, OfferingID: *offering.ID, OfferingVersion: 1,
		ControlID: "ac-1", ProvidedUUID: *provided.ID, InheritedUUID: uuid.New(), LeveragedAuthUUID: *auth.ID,
		Satisfaction: relational.SSPLeverageSatisfactionFull, Status: relational.SSPLeverageStatusActive,
	}
	require.NoError(t, db.Create(&link).Error)

	spy := &spyJobEnqueuer{}
	h := NewSystemSecurityPlanHandler(zap.NewNop().Sugar(), db, nil, spy)
	ctx, rec := newDeleteLeveragedAuthRequestContext(*ssp.ID, *auth.ID)
	require.NoError(t, h.DeleteSystemImplementationLeveragedAuthorization(ctx))
	require.Equal(t, http.StatusNoContent, rec.Code)

	require.Len(t, spy.calls, 1)
	require.Equal(t, *link.ID, spy.calls[0].LinkID)
	require.Equal(t, "leveraged authorization revoked", spy.calls[0].Reason)
}

func TestUpdateOfferingStatusNoDriftEnqueuesNothing(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	upstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&upstreamSSP).Error)
	offering := relational.SSPExportOffering{SSPID: *upstreamSSP.ID, Title: "Offering", Status: relational.SSPExportOfferingStatusPublished, Version: 1}
	require.NoError(t, db.Create(&offering).Error)

	spy := &spyJobEnqueuer{}
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, spy)

	ctx, rec := newOfferingStatusRequestContext(offering.SSPID, *offering.ID, `{"status":"deprecated"}`)
	require.NoError(t, h.UpdateOfferingStatus(ctx))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, spy.calls)
}
