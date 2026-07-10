package oscal

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newDeleteLeveragedAuthRequestContext(sspID, authID uuid.UUID) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id", "authId")
	ctx.SetParamValues(sspID.String(), authID.String())
	return ctx, rec
}

// TestDeleteLeveragedAuthorizationDriftsReferencingActiveLinks: deleting a
// LeveragedAuthorization referenced by an active SSPLeverageLink is treated as the
// authorization having "lapsed" (BCH-1341) — the link drifts and gets its
// inherited-revoked risk, in the same transaction as the delete.
func TestDeleteLeveragedAuthorizationDriftsReferencingActiveLinks(t *testing.T) {
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

	h := NewSystemSecurityPlanHandler(zap.NewNop().Sugar(), db, nil, nil)
	ctx, rec := newDeleteLeveragedAuthRequestContext(*ssp.ID, *auth.ID)
	require.NoError(t, h.DeleteSystemImplementationLeveragedAuthorization(ctx))
	require.Equal(t, http.StatusNoContent, rec.Code)

	var authCount int64
	require.NoError(t, db.Model(&relational.LeveragedAuthorization{}).Count(&authCount).Error)
	require.Zero(t, authCount)

	var reloadedLink relational.SSPLeverageLink
	require.NoError(t, db.First(&reloadedLink, "id = ?", link.ID).Error)
	require.Equal(t, relational.SSPLeverageStatusDrifted, reloadedLink.Status)

	var riskCount int64
	require.NoError(t, db.Model(&risks.Risk{}).Where("source_type = ?", string(risks.RiskSourceTypeInheritedRevoked)).Count(&riskCount).Error)
	require.Equal(t, int64(1), riskCount)
}

// TestDeleteLeveragedAuthorizationNotReferencedIsPureNoOp: deleting an authorization no
// leverage link references behaves exactly as before — no drift, no error.
func TestDeleteLeveragedAuthorizationNotReferencedIsPureNoOp(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	require.NoError(t, db.AutoMigrate(&relational.SystemImplementation{}, &relational.LeveragedAuthorization{}))

	ssp := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&ssp).Error)
	sysImpl := relational.SystemImplementation{SystemSecurityPlanId: *ssp.ID}
	require.NoError(t, db.Create(&sysImpl).Error)
	auth := relational.LeveragedAuthorization{Title: "Trust", PartyUUID: uuid.New(), SystemImplementationId: *sysImpl.ID}
	require.NoError(t, db.Create(&auth).Error)

	h := NewSystemSecurityPlanHandler(zap.NewNop().Sugar(), db, nil, nil)
	ctx, rec := newDeleteLeveragedAuthRequestContext(*ssp.ID, *auth.ID)
	require.NoError(t, h.DeleteSystemImplementationLeveragedAuthorization(ctx))
	require.Equal(t, http.StatusNoContent, rec.Code)

	var riskCount int64
	require.NoError(t, db.Model(&risks.Risk{}).Count(&riskCount).Error)
	require.Zero(t, riskCount)
}

// TestDeleteLeveragedAuthorizationNotFoundReturns404: regression check — deleting a
// nonexistent authorization still 404s (unaffected by wrapping the delete in a
// transaction).
func TestDeleteLeveragedAuthorizationNotFoundReturns404(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	require.NoError(t, db.AutoMigrate(&relational.SystemImplementation{}, &relational.LeveragedAuthorization{}))

	ssp := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&ssp).Error)
	sysImpl := relational.SystemImplementation{SystemSecurityPlanId: *ssp.ID}
	require.NoError(t, db.Create(&sysImpl).Error)

	h := NewSystemSecurityPlanHandler(zap.NewNop().Sugar(), db, nil, nil)
	ctx, rec := newDeleteLeveragedAuthRequestContext(*ssp.ID, uuid.New())
	require.NoError(t, h.DeleteSystemImplementationLeveragedAuthorization(ctx))
	require.Equal(t, http.StatusNotFound, rec.Code)
}
