package oscal

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func newOfferingStatusRequestContext(sspID, offeringID uuid.UUID, body string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPatch, "/", bytes.NewBufferString(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id", "offeringId")
	ctx.SetParamValues(sspID.String(), offeringID.String())
	return ctx, rec
}

// seedPublishedOfferingWithActiveLink seeds a published offering (Version=1) plus one
// active SSPLeverageLink pointing at it, ready for a deprecate/revoke transition.
func seedPublishedOfferingWithActiveLink(t *testing.T, db *gorm.DB) (*relational.SSPExportOffering, *relational.SSPLeverageLink) {
	t.Helper()

	upstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&upstreamSSP).Error)
	downstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&downstreamSSP).Error)

	export := relational.Export{}
	require.NoError(t, db.Create(&export).Error)
	provided := relational.ProvidedControlImplementation{ExportId: *export.ID}
	require.NoError(t, db.Create(&provided).Error)

	offering := relational.SSPExportOffering{
		SSPID: *upstreamSSP.ID, Title: "Offering", Status: relational.SSPExportOfferingStatusPublished, Version: 1,
	}
	require.NoError(t, db.Create(&offering).Error)

	link := relational.SSPLeverageLink{
		DownstreamSSPID: *downstreamSSP.ID, UpstreamSSPID: *upstreamSSP.ID, OfferingID: *offering.ID, OfferingVersion: 1,
		ControlID: "ac-1", ProvidedUUID: *provided.ID, InheritedUUID: uuid.New(), LeveragedAuthUUID: uuid.New(),
		Satisfaction: relational.SSPLeverageSatisfactionFull, Status: relational.SSPLeverageStatusActive,
	}
	require.NoError(t, db.Create(&link).Error)

	return &offering, &link
}

func TestUpdateOfferingStatusDeprecateDriftsActiveLinks(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	offering, link := seedPublishedOfferingWithActiveLink(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	ctx, rec := newOfferingStatusRequestContext(offering.SSPID, *offering.ID, `{"status":"deprecated"}`)
	require.NoError(t, h.UpdateOfferingStatus(ctx))
	require.Equal(t, http.StatusOK, rec.Code)

	var reloadedOffering relational.SSPExportOffering
	require.NoError(t, db.First(&reloadedOffering, "id = ?", offering.ID).Error)
	require.Equal(t, relational.SSPExportOfferingStatusDeprecated, reloadedOffering.Status)
	require.Equal(t, 1, reloadedOffering.Version, "deprecating must not touch Version/ContentHash")

	var reloadedLink relational.SSPLeverageLink
	require.NoError(t, db.First(&reloadedLink, "id = ?", link.ID).Error)
	require.Equal(t, relational.SSPLeverageStatusDrifted, reloadedLink.Status)

	var riskCount int64
	require.NoError(t, db.Model(&risks.Risk{}).Where("source_type = ?", string(risks.RiskSourceTypeInheritedRevoked)).Count(&riskCount).Error)
	require.Equal(t, int64(1), riskCount)
}

func TestUpdateOfferingStatusRevokeDriftsActiveLinks(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	offering, link := seedPublishedOfferingWithActiveLink(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	ctx, rec := newOfferingStatusRequestContext(offering.SSPID, *offering.ID, `{"status":"revoked"}`)
	require.NoError(t, h.UpdateOfferingStatus(ctx))
	require.Equal(t, http.StatusOK, rec.Code)

	var reloadedLink relational.SSPLeverageLink
	require.NoError(t, db.First(&reloadedLink, "id = ?", link.ID).Error)
	require.Equal(t, relational.SSPLeverageStatusDrifted, reloadedLink.Status)
}

func TestUpdateOfferingStatusRejectsInvalidStatus(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	offering, _ := seedPublishedOfferingWithActiveLink(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	ctx, rec := newOfferingStatusRequestContext(offering.SSPID, *offering.ID, `{"status":"published"}`)
	require.NoError(t, h.UpdateOfferingStatus(ctx))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestUpdateOfferingStatusRejectsNonPublishedOffering(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	upstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&upstreamSSP).Error)
	offering := relational.SSPExportOffering{SSPID: *upstreamSSP.ID, Title: "Draft", Status: relational.SSPExportOfferingStatusDraft}
	require.NoError(t, db.Create(&offering).Error)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	ctx, rec := newOfferingStatusRequestContext(offering.SSPID, *offering.ID, `{"status":"deprecated"}`)
	require.NoError(t, h.UpdateOfferingStatus(ctx))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}
