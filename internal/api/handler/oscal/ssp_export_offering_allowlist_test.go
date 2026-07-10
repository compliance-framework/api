package oscal

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newAllowedDownstreamsRequestContext(method string, sspID, offeringID uuid.UUID, extraParam, extraValue string, body string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	var reader *bytes.Reader
	if body != "" {
		reader = bytes.NewReader([]byte(body))
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/", reader)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	if extraParam != "" {
		ctx.SetParamNames("id", "offeringId", extraParam)
		ctx.SetParamValues(sspID.String(), offeringID.String(), extraValue)
	} else {
		ctx.SetParamNames("id", "offeringId")
		ctx.SetParamValues(sspID.String(), offeringID.String())
	}
	return ctx, rec
}

func TestAllowedDownstreamsAddListRemoveRoundTrip(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	addBody, err := json.Marshal(allowedDownstreamRequest{DownstreamSSPID: fx.downstreamSSPID.String()})
	require.NoError(t, err)
	addCtx, addRec := newAllowedDownstreamsRequestContext(http.MethodPost, fx.upstreamSSPID, fx.offeringID, "", "", string(addBody))
	require.NoError(t, h.AddAllowedDownstream(addCtx))
	require.Equal(t, http.StatusCreated, addRec.Code)

	listCtx, listRec := newAllowedDownstreamsRequestContext(http.MethodGet, fx.upstreamSSPID, fx.offeringID, "", "", "")
	require.NoError(t, h.ListAllowedDownstreams(listCtx))
	require.Equal(t, http.StatusOK, listRec.Code)

	var listResp handler.GenericDataListResponse[relational.SSPExportOfferingAllowedDownstream]
	require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &listResp))
	require.Len(t, listResp.Data, 1)
	require.Equal(t, fx.downstreamSSPID, listResp.Data[0].DownstreamSSPID)

	removeCtx, removeRec := newAllowedDownstreamsRequestContext(http.MethodDelete, fx.upstreamSSPID, fx.offeringID, "downstreamSspId", fx.downstreamSSPID.String(), "")
	require.NoError(t, h.RemoveAllowedDownstream(removeCtx))
	require.Equal(t, http.StatusNoContent, removeRec.Code)

	var count int64
	require.NoError(t, db.Model(&relational.SSPExportOfferingAllowedDownstream{}).Count(&count).Error)
	require.Zero(t, count)
}

func TestAllowedDownstreamsAddIsIdempotent(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	addBody, err := json.Marshal(allowedDownstreamRequest{DownstreamSSPID: fx.downstreamSSPID.String()})
	require.NoError(t, err)

	ctx1, rec1 := newAllowedDownstreamsRequestContext(http.MethodPost, fx.upstreamSSPID, fx.offeringID, "", "", string(addBody))
	require.NoError(t, h.AddAllowedDownstream(ctx1))
	require.Equal(t, http.StatusCreated, rec1.Code)

	ctx2, rec2 := newAllowedDownstreamsRequestContext(http.MethodPost, fx.upstreamSSPID, fx.offeringID, "", "", string(addBody))
	require.NoError(t, h.AddAllowedDownstream(ctx2))
	require.Equal(t, http.StatusCreated, rec2.Code)

	var count int64
	require.NoError(t, db.Model(&relational.SSPExportOfferingAllowedDownstream{}).Count(&count).Error)
	require.Equal(t, int64(1), count)
}

func TestAllowedDownstreamsRejectsInvalidDownstreamID(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	addBody, err := json.Marshal(allowedDownstreamRequest{DownstreamSSPID: "not-a-uuid"})
	require.NoError(t, err)
	ctx, rec := newAllowedDownstreamsRequestContext(http.MethodPost, fx.upstreamSSPID, fx.offeringID, "", "", string(addBody))
	require.NoError(t, h.AddAllowedDownstream(ctx))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAllowedDownstreamsRejectsInvalidOfferingID(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	ctx, rec := newAllowedDownstreamsRequestContext(http.MethodGet, fx.upstreamSSPID, uuid.New(), "", "", "")
	require.NoError(t, h.ListAllowedDownstreams(ctx))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRemoveAllowedDownstreamNotFoundReturns404(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	ctx, rec := newAllowedDownstreamsRequestContext(http.MethodDelete, fx.upstreamSSPID, fx.offeringID, "downstreamSspId", uuid.New().String(), "")
	require.NoError(t, h.RemoveAllowedDownstream(ctx))
	require.Equal(t, http.StatusNotFound, rec.Code)
}
