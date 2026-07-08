package oscal

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newSSPLeverageTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&relational.Export{},
		&relational.ProvidedControlImplementation{},
		&relational.ControlImplementationResponsibility{},
		&relational.SSPExportOffering{},
		&relational.SSPExportOfferingItem{},
		&relational.SSPLeverageLink{},
		&relational.SystemSecurityPlan{},
		&relational.SystemImplementation{},
		&relational.SystemComponent{},
		&relational.ControlImplementation{},
		&relational.ImplementedRequirement{},
		&relational.Statement{},
		&relational.ByComponent{},
		&relational.InheritedControlImplementation{},
		&relational.SatisfiedControlImplementationResponsibility{},
		&relational.LeveragedAuthorization{},
	))
	return db
}

// stubPDP is a minimal authz.PDP double that records every resource it was asked to
// evaluate and always returns a fixed decision — used to assert exactly which (resource,
// action) pairs Subscribe checks (in particular, that it never checks ssp:read on the
// upstream SSP).
type stubPDP struct {
	allow bool
	calls []authz.Resource
}

func (s *stubPDP) Evaluate(_ context.Context, _ authz.Subject, _ string, r authz.Resource, _ map[string]any) (authz.Decision, error) {
	s.calls = append(s.calls, r)
	return authz.Decision{Allow: s.allow}, nil
}

func (s *stubPDP) Evaluations(_ context.Context, reqs []authz.EvalRequest) ([]authz.Decision, error) {
	out := make([]authz.Decision, len(reqs))
	for i := range out {
		out[i] = authz.Decision{Allow: s.allow}
	}
	return out, nil
}

// leverageFixture is the object graph a subscribe test needs: an upstream SSP with a
// published offering (one item, whose provided-uuid has two upstream responsibilities),
// and a downstream SSP ready to receive the subscription.
type leverageFixture struct {
	upstreamSSPID   uuid.UUID
	downstreamSSPID uuid.UUID
	offeringID      uuid.UUID
	itemID          uuid.UUID
	respAID         uuid.UUID
	respBID         uuid.UUID
}

func newLeverageFixture(t *testing.T, db *gorm.DB) leverageFixture {
	t.Helper()

	upstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&upstreamSSP).Error)

	export := relational.Export{}
	require.NoError(t, db.Create(&export).Error)

	provided := relational.ProvidedControlImplementation{ExportId: *export.ID, Description: "provided capability"}
	require.NoError(t, db.Create(&provided).Error)

	respA := relational.ControlImplementationResponsibility{ExportId: *export.ID, ProvidedUuid: *provided.ID, Description: "resp a"}
	require.NoError(t, db.Create(&respA).Error)
	respB := relational.ControlImplementationResponsibility{ExportId: *export.ID, ProvidedUuid: *provided.ID, Description: "resp b"}
	require.NoError(t, db.Create(&respB).Error)

	offering := relational.SSPExportOffering{
		SSPID: *upstreamSSP.ID, Title: "Offering", Version: 1,
		Status: relational.SSPExportOfferingStatusPublished,
	}
	require.NoError(t, db.Create(&offering).Error)

	item := relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-1",
		ComponentUUID: uuid.New(), ProvidedUUID: *provided.ID,
	}
	require.NoError(t, db.Create(&item).Error)

	downstreamSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&downstreamSSP).Error)
	require.NoError(t, db.Create(&relational.ControlImplementation{SystemSecurityPlanId: *downstreamSSP.ID}).Error)
	require.NoError(t, db.Create(&relational.SystemImplementation{SystemSecurityPlanId: *downstreamSSP.ID}).Error)

	return leverageFixture{
		upstreamSSPID:   *upstreamSSP.ID,
		downstreamSSPID: *downstreamSSP.ID,
		offeringID:      *offering.ID,
		itemID:          *item.ID,
		respAID:         *respA.ID,
		respBID:         *respB.ID,
	}
}

func newSubscribeRequestContext(offeringID uuid.UUID, body string) (echo.Context, *echo.Echo, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id")
	ctx.SetParamValues(offeringID.String())
	ctx.Set("user", &authn.UserClaims{UserUUID: uuid.New().String()})
	return ctx, e, rec
}

func subscribeBody(downstreamSSPID uuid.UUID, itemID uuid.UUID, satisfiedRespIDs ...uuid.UUID) string {
	quoted := make([]string, 0, len(satisfiedRespIDs))
	for _, id := range satisfiedRespIDs {
		quoted = append(quoted, fmt.Sprintf("%q", id.String()))
	}
	return fmt.Sprintf(
		`{"downstreamSspId":%q,"leveragedAuthorization":{"title":"Trust","partyUuid":%q},"items":[{"itemId":%q,"satisfiedResponsibilityUuids":[%s]}]}`,
		downstreamSSPID.String(), uuid.New().String(), itemID.String(), strings.Join(quoted, ","),
	)
}

// TestResolveUpstreamResponsibilitiesReturnsSiblingsUnderSameExport: responsibilities
// referencing the given provided-uuid, scoped to the provided item's own Export, are
// returned; responsibilities under an unrelated provided-uuid are not.
func TestResolveUpstreamResponsibilitiesReturnsSiblingsUnderSameExport(t *testing.T) {
	db := newSSPLeverageTestDB(t)

	export := relational.Export{}
	require.NoError(t, db.Create(&export).Error)

	provided := relational.ProvidedControlImplementation{ExportId: *export.ID, Description: "provided"}
	require.NoError(t, db.Create(&provided).Error)

	otherProvided := relational.ProvidedControlImplementation{ExportId: *export.ID, Description: "other provided"}
	require.NoError(t, db.Create(&otherProvided).Error)

	respA := relational.ControlImplementationResponsibility{ExportId: *export.ID, ProvidedUuid: *provided.ID, Description: "resp a"}
	require.NoError(t, db.Create(&respA).Error)
	respB := relational.ControlImplementationResponsibility{ExportId: *export.ID, ProvidedUuid: *provided.ID, Description: "resp b"}
	require.NoError(t, db.Create(&respB).Error)
	unrelated := relational.ControlImplementationResponsibility{ExportId: *export.ID, ProvidedUuid: *otherProvided.ID, Description: "unrelated"}
	require.NoError(t, db.Create(&unrelated).Error)

	got, err := resolveUpstreamResponsibilities(db, *provided.ID)
	require.NoError(t, err)
	require.Len(t, got, 2)

	uuids := []uuid.UUID{got[0].ResponsibilityUUID, got[1].ResponsibilityUUID}
	require.ElementsMatch(t, uuids, []uuid.UUID{*respA.ID, *respB.ID})
}

// TestResolveUpstreamResponsibilitiesUnknownProvidedReturnsEmpty: a provided_uuid that
// doesn't correspond to any ProvidedControlImplementation row (e.g. the upstream row was
// since deleted) yields an empty slice, not an error.
func TestResolveUpstreamResponsibilitiesUnknownProvidedReturnsEmpty(t *testing.T) {
	db := newSSPLeverageTestDB(t)

	got, err := resolveUpstreamResponsibilities(db, uuid.New())
	require.NoError(t, err)
	require.Empty(t, got)
}

// TestDeriveSatisfaction: full iff every upstream responsibility has a matching
// downstream satisfied uuid — vacuously full when there are no upstream responsibilities
// at all, partial when some (but not all) are covered, and the outstanding list is
// exactly the uncovered subset.
func TestDeriveSatisfaction(t *testing.T) {
	respA := upstreamResponsibility{ResponsibilityUUID: uuid.New(), Description: "a"}
	respB := upstreamResponsibility{ResponsibilityUUID: uuid.New(), Description: "b"}
	full := []upstreamResponsibility{respA, respB}

	t.Run("full when every responsibility is satisfied", func(t *testing.T) {
		satisfaction, outstanding := deriveSatisfaction(full, map[uuid.UUID]bool{respA.ResponsibilityUUID: true, respB.ResponsibilityUUID: true})
		require.Equal(t, relational.SSPLeverageSatisfactionFull, satisfaction)
		require.Empty(t, outstanding)
	})

	t.Run("partial when only some are satisfied", func(t *testing.T) {
		satisfaction, outstanding := deriveSatisfaction(full, map[uuid.UUID]bool{respA.ResponsibilityUUID: true})
		require.Equal(t, relational.SSPLeverageSatisfactionPartial, satisfaction)
		require.Equal(t, []upstreamResponsibility{respB}, outstanding)
	})

	t.Run("partial when none are satisfied", func(t *testing.T) {
		satisfaction, outstanding := deriveSatisfaction(full, map[uuid.UUID]bool{})
		require.Equal(t, relational.SSPLeverageSatisfactionPartial, satisfaction)
		require.Len(t, outstanding, 2)
	})

	t.Run("vacuously full when there are no upstream responsibilities", func(t *testing.T) {
		satisfaction, outstanding := deriveSatisfaction(nil, map[uuid.UUID]bool{})
		require.Equal(t, relational.SSPLeverageSatisfactionFull, satisfaction)
		require.Empty(t, outstanding)
	})
}

// TestFindOrCreateThisSystemComponent: creates a placeholder component when none exists,
// and returns the same row (not a duplicate) on a second call.
func TestFindOrCreateThisSystemComponent(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	si := relational.SystemImplementation{}
	require.NoError(t, db.Create(&si).Error)

	first, err := findOrCreateThisSystemComponent(db, *si.ID)
	require.NoError(t, err)
	require.Equal(t, thisSystemComponentType, first.Type)

	second, err := findOrCreateThisSystemComponent(db, *si.ID)
	require.NoError(t, err)
	require.Equal(t, *first.ID, *second.ID)

	var count int64
	require.NoError(t, db.Model(&relational.SystemComponent{}).Where("system_implementation_id = ?", si.ID).Count(&count).Error)
	require.Equal(t, int64(1), count)
}

// TestFindOrCreateImplementedRequirement: creates a requirement for a control_id when
// none exists under the given ControlImplementation, and returns the same row (not a
// duplicate) on a second call for the same control_id.
func TestFindOrCreateImplementedRequirement(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	ci := relational.ControlImplementation{}
	require.NoError(t, db.Create(&ci).Error)

	first, err := findOrCreateImplementedRequirement(db, *ci.ID, "ac-1")
	require.NoError(t, err)
	require.Equal(t, "ac-1", first.ControlId)

	second, err := findOrCreateImplementedRequirement(db, *ci.ID, "ac-1")
	require.NoError(t, err)
	require.Equal(t, *first.ID, *second.ID)

	third, err := findOrCreateImplementedRequirement(db, *ci.ID, "ac-2")
	require.NoError(t, err)
	require.NotEqual(t, *first.ID, *third.ID)
}

// TestFindOrCreateByComponent: creates a ByComponent row for a (parent, componentUUID)
// pair when none exists, and returns the same row on a second call.
func TestFindOrCreateByComponent(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	parentID := uuid.New()
	componentUUID := uuid.New()

	first, err := findOrCreateByComponent(db, parentID, "implemented_requirements", componentUUID)
	require.NoError(t, err)
	require.Equal(t, componentUUID, first.ComponentUUID)

	second, err := findOrCreateByComponent(db, parentID, "implemented_requirements", componentUUID)
	require.NoError(t, err)
	require.Equal(t, *first.ID, *second.ID)
}

// TestSubscribePartialSatisfactionWritesAtomically: subscribing to an item whose
// provided-uuid has two upstream responsibilities, satisfying only one, writes exactly
// one InheritedControlImplementation, one SatisfiedControlImplementationResponsibility,
// one LeveragedAuthorization, and one SSPLeverageLink with satisfaction "partial" — and
// checks ssp:update on the downstream SSP only, never anything against the upstream SSP
// (the trust-boundary property ticket AC #2 requires).
func TestSubscribePartialSatisfactionWritesAtomically(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)

	pdp := &stubPDP{allow: true}
	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)

	body := subscribeBody(fx.downstreamSSPID, fx.itemID, fx.respAID)
	ctx, _, rec := newSubscribeRequestContext(fx.offeringID, body)
	require.NoError(t, h.Subscribe(ctx))
	require.Equal(t, http.StatusCreated, rec.Code)

	var links []relational.SSPLeverageLink
	require.NoError(t, db.Find(&links).Error)
	require.Len(t, links, 1)
	require.Equal(t, fx.downstreamSSPID, links[0].DownstreamSSPID)
	require.Equal(t, fx.upstreamSSPID, links[0].UpstreamSSPID)
	require.Equal(t, relational.SSPLeverageSatisfactionPartial, links[0].Satisfaction)
	require.Equal(t, relational.SSPLeverageStatusActive, links[0].Status)

	var inheritedCount, satisfiedCount, authCount int64
	require.NoError(t, db.Model(&relational.InheritedControlImplementation{}).Count(&inheritedCount).Error)
	require.NoError(t, db.Model(&relational.SatisfiedControlImplementationResponsibility{}).Count(&satisfiedCount).Error)
	require.NoError(t, db.Model(&relational.LeveragedAuthorization{}).Count(&authCount).Error)
	require.Equal(t, int64(1), inheritedCount)
	require.Equal(t, int64(1), satisfiedCount)
	require.Equal(t, int64(1), authCount)

	require.Len(t, pdp.calls, 1, "subscribe must check exactly one authz resource")
	require.Equal(t, authz.ResourceSSP, pdp.calls[0].Type)
	require.Equal(t, fx.downstreamSSPID.String(), pdp.calls[0].ID,
		"the only ssp resource checked must be the downstream, never the upstream")
}

// TestSubscribeFullSatisfactionWhenEveryResponsibilitySatisfied: satisfying both
// upstream responsibilities yields satisfaction "full".
func TestSubscribeFullSatisfactionWhenEveryResponsibilitySatisfied(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)

	pdp := &stubPDP{allow: true}
	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)

	body := subscribeBody(fx.downstreamSSPID, fx.itemID, fx.respAID, fx.respBID)
	ctx, _, rec := newSubscribeRequestContext(fx.offeringID, body)
	require.NoError(t, h.Subscribe(ctx))
	require.Equal(t, http.StatusCreated, rec.Code)

	var link relational.SSPLeverageLink
	require.NoError(t, db.First(&link).Error)
	require.Equal(t, relational.SSPLeverageSatisfactionFull, link.Satisfaction)
}

// TestSubscribeRejectsDuplicateProvidedUUID: re-subscribing to a provided-uuid the
// downstream is already linked to returns 409, enforcing the
// UNIQUE(downstream_ssp_id, provided_uuid) invariant at the API layer.
func TestSubscribeRejectsDuplicateProvidedUUID(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	pdp := &stubPDP{allow: true}
	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)

	body := subscribeBody(fx.downstreamSSPID, fx.itemID, fx.respAID)

	ctx, _, rec := newSubscribeRequestContext(fx.offeringID, body)
	require.NoError(t, h.Subscribe(ctx))
	require.Equal(t, http.StatusCreated, rec.Code)

	ctx2, _, rec2 := newSubscribeRequestContext(fx.offeringID, body)
	require.NoError(t, h.Subscribe(ctx2))
	require.Equal(t, http.StatusConflict, rec2.Code)

	var count int64
	require.NoError(t, db.Model(&relational.SSPLeverageLink{}).Count(&count).Error)
	require.Equal(t, int64(1), count)
}

// TestSubscribeForbiddenWhenDownstreamUpdateDenied: when the PDP denies ssp:update on
// the downstream SSP, Subscribe returns 403 and writes nothing.
func TestSubscribeForbiddenWhenDownstreamUpdateDenied(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	pdp := &stubPDP{allow: false}
	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)

	body := subscribeBody(fx.downstreamSSPID, fx.itemID, fx.respAID)
	ctx, e, rec := newSubscribeRequestContext(fx.offeringID, body)

	err := h.Subscribe(ctx)
	require.Error(t, err)
	e.HTTPErrorHandler(err, ctx)
	require.Equal(t, http.StatusForbidden, rec.Code)

	var count int64
	require.NoError(t, db.Model(&relational.SSPLeverageLink{}).Count(&count).Error)
	require.Equal(t, int64(0), count)
}

// TestSubscribeUnknownResponsibilityUUIDRejected: satisfying a responsibility uuid that
// isn't part of the item's provided-uuid rolls back the whole transaction.
func TestSubscribeUnknownResponsibilityUUIDRejected(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	pdp := &stubPDP{allow: true}
	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)

	body := subscribeBody(fx.downstreamSSPID, fx.itemID, uuid.New())
	ctx, _, rec := newSubscribeRequestContext(fx.offeringID, body)
	require.NoError(t, h.Subscribe(ctx))
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	var count int64
	require.NoError(t, db.Model(&relational.SSPLeverageLink{}).Count(&count).Error)
	require.Equal(t, int64(0), count)
	require.NoError(t, db.Model(&relational.LeveragedAuthorization{}).Count(&count).Error)
	require.Equal(t, int64(0), count, "the shared leveraged authorization must roll back too")
}

// TestLeveragedControlsProjectionShowsPartialAndOutstanding: after a partial subscribe,
// the projection endpoint reports satisfaction "partial" and exactly the unsatisfied
// responsibility as outstanding.
func TestLeveragedControlsProjectionShowsPartialAndOutstanding(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newLeverageFixture(t, db)
	pdp := &stubPDP{allow: true}
	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)

	body := subscribeBody(fx.downstreamSSPID, fx.itemID, fx.respAID)
	subCtx, _, subRec := newSubscribeRequestContext(fx.offeringID, body)
	require.NoError(t, h.Subscribe(subCtx))
	require.Equal(t, http.StatusCreated, subRec.Code)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id")
	ctx.SetParamValues(fx.downstreamSSPID.String())

	require.NoError(t, h.LeveragedControls(ctx))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"satisfaction":"partial"`)
	require.Contains(t, rec.Body.String(), fx.respBID.String())
	require.NotContains(t, rec.Body.String(), fx.respAID.String())
}
