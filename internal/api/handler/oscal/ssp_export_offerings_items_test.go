package oscal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/service/relational"
)

// --- ByControl pagination vs. the downstream allow-list -----------------------------------

// seqUUID builds a deterministically ordered uuid, so a test can pin the order
// `ORDER BY ssp_export_offering_items.id ASC` produces. Random v4 ids would make "the
// matching rows are on the SECOND page" a coin flip rather than a fact.
func seqUUID(n int) uuid.UUID {
	return uuid.MustParse(fmt.Sprintf("00000000-0000-0000-0000-%012d", n))
}

// seedByControlPage adds `count` published offerings, each with a single ac-2 item, whose item
// ids sort in creation order starting at `startSeq`. Every item points at the fixture's real
// component and provided rows so ByControl resolves them like any other. `allowed` names the
// downstream SSP each offering is allow-listed for; the zero uuid means "no allow-list rows",
// i.e. open to every downstream.
func seedByControlPage(t *testing.T, db *gorm.DB, fx sharedResponsibilityFixture, startSeq, count int, allowed uuid.UUID) []uuid.UUID {
	t.Helper()

	itemIDs := make([]uuid.UUID, 0, count)
	for i := 0; i < count; i++ {
		offering := relational.SSPExportOffering{
			SSPID: fx.upstreamSSPID, Title: fmt.Sprintf("Offering %d", startSeq+i), Version: 1,
			Status: relational.SSPExportOfferingStatusPublished,
		}
		require.NoError(t, db.Create(&offering).Error)

		itemID := seqUUID(startSeq + i)
		item := relational.SSPExportOfferingItem{
			OfferingID: *offering.ID, ControlID: "ac-2", StatementID: statementID("ac-2_smt.a"),
			ComponentUUID: fx.componentID, ProvidedUUID: fx.providedID,
		}
		item.ID = &itemID
		require.NoError(t, db.Create(&item).Error)
		itemIDs = append(itemIDs, itemID)

		if allowed != uuid.Nil {
			require.NoError(t, db.Create(&relational.SSPExportOfferingAllowedDownstream{
				OfferingID: *offering.ID, DownstreamSSPID: allowed,
			}).Error)
		}
	}
	return itemIDs
}

func byControlPage(t *testing.T, h *SSPExportOfferingHandler, downstream *uuid.UUID, limit, offset int) []ControlExportOffer {
	t.Helper()

	target := fmt.Sprintf("/?limit=%d&offset=%d", limit, offset)
	if downstream != nil {
		target += "&downstreamSspId=" + downstream.String()
	}
	e := echo.New()
	rec := httptest.NewRecorder()
	ctx := e.NewContext(httptest.NewRequest(http.MethodGet, target, nil), rec)
	ctx.SetParamNames("controlId")
	ctx.SetParamValues("ac-2")

	require.NoError(t, h.ByControl(ctx))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp handler.GenericDataListResponse[ControlExportOffer]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// TestByControlPaginatesOverAllowListFilteredRows is the pagination bug the allow-list predicate
// exists to prevent. When the filter ran AFTER Limit/Offset, a page whose rows were all filtered
// out came back as `200 []` — indistinguishable from the end of the collection — so a client
// paginating from offset 0 with downstreamSspId set stopped before reaching any match. Here the
// only permitted offerings sort last, so the first page is entirely non-matching under the old
// ordering; the filtered rows must still be returned.
func TestByControlPaginatesOverAllowListFilteredRows(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	// The fixture's own offering would sort unpredictably (random uuid) — drop its item so the
	// only rows in play are the sequenced ones below.
	require.NoError(t, db.Delete(&relational.SSPExportOfferingItem{}, "id = ?", fx.itemID).Error)

	stranger := uuid.New()
	// Ten offerings allow-listed to somebody else: they sort first and match nothing.
	seedByControlPage(t, db, fx, 1, 10, stranger)
	// Two offerings with no allow-list at all: open to every downstream, and they sort last.
	wanted := seedByControlPage(t, db, fx, 11, 2, uuid.Nil)

	// Unfiltered, the first page is full and the matches are indeed on page three.
	require.Len(t, byControlPage(t, h, nil, 5, 0), 5)

	// Filtered, the two matches must arrive on the FIRST page — the filter is applied before
	// LIMIT/OFFSET, so pagination walks the filtered set, not the raw one.
	page := byControlPage(t, h, &fx.downstreamSSPID, 5, 0)
	require.Len(t, page, 2, "the allow-listed rows must be returned, not swallowed by a page of filtered-out rows")
	got := []uuid.UUID{page[0].ItemID, page[1].ItemID}
	require.ElementsMatch(t, wanted, got)

	// And the page after them is genuinely empty, which is what "end of collection" should mean.
	require.Empty(t, byControlPage(t, h, &fx.downstreamSSPID, 5, 2))
}

// TestByControlEmptyAllowListMatchesNothing pins the degenerate direction of the SQL predicate:
// when EVERY candidate offering carries an allow-list and none names the caller's downstream,
// the permitted set is empty and the query must match NOTHING. A filter that collapses to
// "no constraint" when the permitted set is empty would leak the entire catalog.
func TestByControlEmptyAllowListMatchesNothing(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	// Put the fixture's own offering behind an allow-list too, so nothing is open by default.
	stranger := uuid.New()
	require.NoError(t, db.Create(&relational.SSPExportOfferingAllowedDownstream{
		OfferingID: fx.offeringID, DownstreamSSPID: stranger,
	}).Error)
	seedByControlPage(t, db, fx, 1, 3, stranger)

	require.Len(t, byControlPage(t, h, nil, 100, 0), 4, "the rows exist and are visible unfiltered")
	require.Empty(t, byControlPage(t, h, &fx.downstreamSSPID, 100, 0),
		"an empty permitted set must match nothing, never everything")
	require.Len(t, byControlPage(t, h, &stranger, 100, 0), 4)
}

// --- CreateItem / UpdateItem parity -------------------------------------------------------

// offeringItemWriteCase drives one of the two item write handlers through the same request, so
// the create and update paths cannot drift apart on validation or on the control-id casing
// invariant — the reason UpdateItem being untested mattered.
type offeringItemWriteCase struct {
	name       string
	method     string
	okStatus   int
	invoke     func(h *SSPExportOfferingHandler, ctx echo.Context) error
	extraParam func(fx sharedResponsibilityFixture) (name, value string)
}

func offeringItemWriteCases() []offeringItemWriteCase {
	return []offeringItemWriteCase{
		{
			name:     "CreateItem",
			method:   http.MethodPost,
			okStatus: http.StatusCreated,
			invoke:   func(h *SSPExportOfferingHandler, ctx echo.Context) error { return h.CreateItem(ctx) },
		},
		{
			name:     "UpdateItem",
			method:   http.MethodPut,
			okStatus: http.StatusOK,
			invoke:   func(h *SSPExportOfferingHandler, ctx echo.Context) error { return h.UpdateItem(ctx) },
			extraParam: func(fx sharedResponsibilityFixture) (string, string) {
				return "itemId", fx.itemID.String()
			},
		},
	}
}

func (c offeringItemWriteCase) call(t *testing.T, h *SSPExportOfferingHandler, fx sharedResponsibilityFixture, body string) *httptest.ResponseRecorder {
	t.Helper()

	e := echo.New()
	httpReq := httptest.NewRequest(c.method, "/", bytes.NewBufferString(body))
	httpReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(httpReq, rec)

	names := []string{"id", "offeringId"}
	values := []string{fx.upstreamSSPID.String(), fx.offeringID.String()}
	if c.extraParam != nil {
		n, v := c.extraParam(fx)
		names = append(names, n)
		values = append(values, v)
	}
	ctx.SetParamNames(names...)
	ctx.SetParamValues(values...)

	require.NoError(t, c.invoke(h, ctx))
	return rec
}

// TestOfferingItemWriteStoresCanonicalControlIdCasing covers BOTH write paths: whatever casing
// the curator sends, validateOfferingItemCoherence canonicalizes it to the requirement's catalog
// casing THROUGH THE POINTER, and the handler must persist that canonicalized value — not the
// bytes the client sent. Subscribe's findOrCreateImplementedRequirement matches control_id
// EXACTLY, so storing "AC-2" against a catalog "ac-2" splits a downstream's tree across two
// requirement rows for one control. The create path was covered; the update path was not.
func TestOfferingItemWriteStoresCanonicalControlIdCasing(t *testing.T) {
	for _, tc := range offeringItemWriteCases() {
		t.Run(tc.name, func(t *testing.T) {
			db := newSSPLeverageTestDB(t)
			fx := newSharedResponsibilityFixture(t, db)
			h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

			// Poison the stored casing first, so a handler that writes the pre-canonicalization
			// value leaves "AC-2" behind rather than coincidentally matching the fixture.
			require.NoError(t, db.Model(&relational.SSPExportOfferingItem{}).
				Where("id = ?", fx.itemID).Update("control_id", "AC-2").Error)

			body := `{"controlId":"AC-2","statementId":"ac-2_smt.a","componentUuid":"` +
				fx.componentID.String() + `","providedUuid":"` + fx.providedID.String() + `"}`
			rec := tc.call(t, h, fx, body)
			require.Equal(t, tc.okStatus, rec.Code, rec.Body.String())

			var resp handler.GenericDataResponse[relational.SSPExportOfferingItem]
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			require.Equal(t, "ac-2", resp.Data.ControlID)

			// The response could be built from the request struct; assert what is actually on disk.
			var stored relational.SSPExportOfferingItem
			require.NoError(t, db.First(&stored, "id = ?", resp.Data.ID).Error)
			require.Equal(t, "ac-2", stored.ControlID,
				"the persisted control-id must be the catalog's canonical casing, not the client's")
		})
	}
}

// TestOfferingItemWriteRejectsIncoherentTuple: both write paths must reject a
// (controlId, statementId, componentUuid, providedUuid) tuple whose parts do not describe one
// real statement-anchored by-component inside the offering's own SSP, rather than persisting
// four independently-plausible identifiers for the incoherence to surface downstream.
func TestOfferingItemWriteRejectsIncoherentTuple(t *testing.T) {
	for _, tc := range offeringItemWriteCases() {
		t.Run(tc.name, func(t *testing.T) {
			db := newSSPLeverageTestDB(t)
			fx := newSharedResponsibilityFixture(t, db)
			h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

			for _, bad := range []struct {
				name, body, wantErr string
			}{
				{
					name: "statement-id does not belong to the provided capability",
					body: `{"controlId":"ac-2","statementId":"ac-2_smt.z","componentUuid":"` +
						fx.componentID.String() + `","providedUuid":"` + fx.providedID.String() + `"}`,
					wantErr: "does not match the statement",
				},
				{
					name: "control-id does not belong to the provided capability",
					body: `{"controlId":"ac-99","statementId":"ac-2_smt.a","componentUuid":"` +
						fx.componentID.String() + `","providedUuid":"` + fx.providedID.String() + `"}`,
					wantErr: "does not match the control",
				},
				{
					name: "component is not the one exporting the provided capability",
					body: `{"controlId":"ac-2","statementId":"ac-2_smt.a","componentUuid":"` +
						uuid.New().String() + `","providedUuid":"` + fx.providedID.String() + `"}`,
					wantErr: "does not match the component",
				},
				{
					name: "provided capability does not exist",
					body: `{"controlId":"ac-2","statementId":"ac-2_smt.a","componentUuid":"` +
						fx.componentID.String() + `","providedUuid":"` + uuid.New().String() + `"}`,
					wantErr: "does not exist",
				},
			} {
				t.Run(bad.name, func(t *testing.T) {
					rec := tc.call(t, h, fx, bad.body)
					require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
					require.Contains(t, rec.Body.String(), bad.wantErr)
				})
			}

			// Nothing was written or overwritten by any of the rejected requests.
			var stored relational.SSPExportOfferingItem
			require.NoError(t, db.First(&stored, "id = ?", fx.itemID).Error)
			require.Equal(t, "ac-2", stored.ControlID)
			require.Equal(t, fx.providedID, stored.ProvidedUUID)
			require.Equal(t, int64(1), countRows(t, db, &relational.SSPExportOfferingItem{}, "offering_id = ?", fx.offeringID))
		})
	}
}

// TestUpdateItemUnknownItemReturns404: the update targets a row by (itemId, offeringId), so an
// id that belongs to no item of this offering must 404 rather than silently succeed.
func TestUpdateItemUnknownItemReturns404(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	e := echo.New()
	body := `{"controlId":"ac-2","statementId":"ac-2_smt.a","componentUuid":"` +
		fx.componentID.String() + `","providedUuid":"` + fx.providedID.String() + `"}`
	httpReq := httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(body))
	httpReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(httpReq, rec)
	ctx.SetParamNames("id", "offeringId", "itemId")
	ctx.SetParamValues(fx.upstreamSSPID.String(), fx.offeringID.String(), uuid.New().String())

	require.NoError(t, h.UpdateItem(ctx))
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
}
