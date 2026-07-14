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
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

// sharedResponsibilityFixture is one upstream SSP that exports a statement-anchored provided
// capability with two responsibilities, published in an offering — plus a downstream SSP ready
// to subscribe to it. It mirrors the real shape the statement-anchored model requires:
// SSP -> ControlImplementation -> ImplementedRequirement -> Statement -> ByComponent -> Export.
type sharedResponsibilityFixture struct {
	upstreamSSPID   uuid.UUID
	downstreamSSPID uuid.UUID

	requirementID uuid.UUID
	statementID   uuid.UUID
	byComponentID uuid.UUID
	componentID   uuid.UUID
	exportID      uuid.UUID
	providedID    uuid.UUID

	respAID uuid.UUID
	respBID uuid.UUID

	offeringID uuid.UUID
	itemID     uuid.UUID
}

func newSharedResponsibilityFixture(t *testing.T, db *gorm.DB) sharedResponsibilityFixture {
	t.Helper()

	upstream := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&upstream).Error)
	upstreamImpl := relational.ControlImplementation{SystemSecurityPlanId: *upstream.ID}
	require.NoError(t, db.Create(&upstreamImpl).Error)
	upstreamSysImpl := relational.SystemImplementation{SystemSecurityPlanId: *upstream.ID}
	require.NoError(t, db.Create(&upstreamSysImpl).Error)

	component := relational.SystemComponent{
		Type: "software", Title: "Meridian Runtime",
		SystemImplementationId: *upstreamSysImpl.ID,
	}
	require.NoError(t, db.Create(&component).Error)

	requirement := relational.ImplementedRequirement{
		ControlImplementationId: *upstreamImpl.ID, ControlId: "ac-2",
	}
	require.NoError(t, db.Create(&requirement).Error)

	statement := relational.Statement{
		ImplementedRequirementId: *requirement.ID, StatementId: "ac-2_smt.a",
	}
	require.NoError(t, db.Create(&statement).Error)

	statementsType := "statements"
	byComponent := relational.ByComponent{
		ParentID: statement.ID, ParentType: &statementsType,
		ComponentUUID: *component.ID,
		Description:   "original description",
		Remarks:       "original remarks",
	}
	require.NoError(t, db.Create(&byComponent).Error)

	export := relational.Export{ByComponentId: *byComponent.ID, Description: "export"}
	require.NoError(t, db.Create(&export).Error)

	provided := relational.ProvidedControlImplementation{ExportId: *export.ID, Description: "provided capability"}
	require.NoError(t, db.Create(&provided).Error)

	respA := relational.ControlImplementationResponsibility{
		ExportId: *export.ID, ProvidedUuid: *provided.ID, Description: "resp a",
	}
	require.NoError(t, db.Create(&respA).Error)
	respB := relational.ControlImplementationResponsibility{
		ExportId: *export.ID, ProvidedUuid: *provided.ID, Description: "resp b",
	}
	require.NoError(t, db.Create(&respB).Error)

	offering := relational.SSPExportOffering{
		SSPID: *upstream.ID, Title: "Meridian Offering", Version: 3,
		Status: relational.SSPExportOfferingStatusPublished,
	}
	require.NoError(t, db.Create(&offering).Error)

	item := relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-2", StatementID: statementID("ac-2_smt.a"),
		ComponentUUID: *component.ID, ProvidedUUID: *provided.ID,
	}
	require.NoError(t, db.Create(&item).Error)

	downstream := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&downstream).Error)
	require.NoError(t, db.Create(&relational.ControlImplementation{SystemSecurityPlanId: *downstream.ID}).Error)
	require.NoError(t, db.Create(&relational.SystemImplementation{SystemSecurityPlanId: *downstream.ID}).Error)

	return sharedResponsibilityFixture{
		upstreamSSPID:   *upstream.ID,
		downstreamSSPID: *downstream.ID,
		requirementID:   *requirement.ID,
		statementID:     *statement.ID,
		byComponentID:   *byComponent.ID,
		componentID:     *component.ID,
		exportID:        *export.ID,
		providedID:      *provided.ID,
		respAID:         *respA.ID,
		respBID:         *respB.ID,
		offeringID:      *offering.ID,
		itemID:          *item.ID,
	}
}

// newByComponentContext builds an echo context addressed at one statement-level by-component,
// with any extra path params (inheritedId/satisfiedId) appended.
func newByComponentContext(method, body string, sspID, reqID, stmtID, bcID uuid.UUID, extra ...[2]string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(method, "/", bytes.NewBufferString(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	names := []string{"id", "reqId", "stmtId", "byComponentId"}
	values := []string{sspID.String(), reqID.String(), stmtID.String(), bcID.String()}
	for _, pair := range extra {
		names = append(names, pair[0])
		values = append(values, pair[1])
	}
	ctx.SetParamNames(names...)
	ctx.SetParamValues(values...)
	return ctx, rec
}

func newSSPHandler(db *gorm.DB) *SystemSecurityPlanHandler {
	return NewSystemSecurityPlanHandler(zap.NewNop().Sugar(), db, nil, nil)
}

// subscribeFixture runs a real Subscribe against the fixture, satisfying the given
// responsibilities, and returns the created leverage link plus the meta.created block.
func subscribeFixture(t *testing.T, db *gorm.DB, fx sharedResponsibilityFixture, satisfied ...uuid.UUID) (relational.SSPLeverageLink, subscribeCreated) {
	t.Helper()

	pdp := &stubPDP{allow: true}
	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)
	ctx, _, rec := newSubscribeRequestContext(fx.offeringID, subscribeBody(fx.downstreamSSPID, fx.itemID, satisfied...))
	require.NoError(t, h.Subscribe(ctx))
	require.Equal(t, http.StatusCreated, rec.Code)

	var resp struct {
		Data []relational.SSPLeverageLink `json:"data"`
		Meta subscribeMeta                `json:"meta"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 1)
	return resp.Data[0], resp.Meta.Created
}

// --- Part 1: statement anchoring ---------------------------------------------------------

// TestCreateOfferingItemRequiresStatementID: an offering item with no statement-id is the
// ambiguous requirement-anchored case this work eliminates, and is rejected on the write path.
func TestCreateOfferingItemRequiresStatementID(t *testing.T) {
	req := createExportOfferingItemRequest{
		ControlID:     "ac-2",
		ComponentUUID: uuid.New().String(),
		ProvidedUUID:  uuid.New().String(),
	}
	err := req.validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "statementId is required")

	blank := ""
	req.StatementID = &blank
	require.Error(t, req.validate())

	req.StatementID = statementID("ac-2_smt.a")
	require.NoError(t, req.validate())
}

// TestOfferingItemCoherenceRejectsIncoherentTuples: the (controlId, statementId,
// componentUuid, providedUuid) tuple must actually resolve to one real statement-anchored
// by-component inside this SSP. Nothing validated this before.
func TestOfferingItemCoherenceRejectsIncoherentTuples(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	coherent := createExportOfferingItemRequest{
		ControlID:     "ac-2",
		StatementID:   statementID("ac-2_smt.a"),
		ComponentUUID: fx.componentID.String(),
		ProvidedUUID:  fx.providedID.String(),
	}
	require.NoError(t, h.validateOfferingItemCoherence(fx.upstreamSSPID, &coherent))

	wrongControl := coherent
	wrongControl.ControlID = "ac-3"
	require.ErrorContains(t, h.validateOfferingItemCoherence(fx.upstreamSSPID, &wrongControl), "controlId")

	wrongStatement := coherent
	wrongStatement.StatementID = statementID("ac-2_smt.b")
	require.ErrorContains(t, h.validateOfferingItemCoherence(fx.upstreamSSPID, &wrongStatement), "statementId")

	wrongComponent := coherent
	wrongComponent.ComponentUUID = uuid.New().String()
	require.ErrorContains(t, h.validateOfferingItemCoherence(fx.upstreamSSPID, &wrongComponent), "componentUuid")

	unknownProvided := coherent
	unknownProvided.ProvidedUUID = uuid.New().String()
	require.ErrorContains(t, h.validateOfferingItemCoherence(fx.upstreamSSPID, &unknownProvided), "does not exist")

	// Coherent in itself, but belonging to a different SSP entirely.
	otherSSP := relational.SystemSecurityPlan{}
	require.NoError(t, db.Create(&otherSSP).Error)
	require.NoError(t, db.Create(&relational.ControlImplementation{SystemSecurityPlanId: *otherSSP.ID}).Error)
	require.ErrorContains(t, h.validateOfferingItemCoherence(*otherSSP.ID, &coherent), "does not resolve inside this SSP")
}

// TestOfferingItemCoherenceRejectsRequirementAnchoredProvided: a provided capability exported
// from a requirement-anchored by-component cannot be offered — there is no statement to
// attribute the responsibility against.
func TestOfferingItemCoherenceRejectsRequirementAnchoredProvided(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	requirementsType := "implemented_requirements"
	legacyBC := relational.ByComponent{
		ParentID: &fx.requirementID, ParentType: &requirementsType, ComponentUUID: fx.componentID,
	}
	require.NoError(t, db.Create(&legacyBC).Error)
	legacyExport := relational.Export{ByComponentId: *legacyBC.ID}
	require.NoError(t, db.Create(&legacyExport).Error)
	legacyProvided := relational.ProvidedControlImplementation{ExportId: *legacyExport.ID}
	require.NoError(t, db.Create(&legacyProvided).Error)

	err := h.validateOfferingItemCoherence(fx.upstreamSSPID, &createExportOfferingItemRequest{
		ControlID:     "ac-2",
		StatementID:   statementID("ac-2_smt.a"),
		ComponentUUID: fx.componentID.String(),
		ProvidedUUID:  legacyProvided.ID.String(),
	})
	require.ErrorContains(t, err, "requirement-anchored")
}

// TestSubscribeRejectsStatementlessLegacyItem: subscribing to a legacy NULL-statement item
// fails with 422 naming the item, rather than silently falling back to requirement-anchoring
// (which produced by-component rows the API could never delete).
func TestSubscribeRejectsStatementlessLegacyItem(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	require.NoError(t, db.Model(&relational.SSPExportOfferingItem{}).
		Where("id = ?", fx.itemID).
		Update("statement_id", nil).Error)

	pdp := &stubPDP{allow: true}
	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)
	ctx, _, rec := newSubscribeRequestContext(fx.offeringID, subscribeBody(fx.downstreamSSPID, fx.itemID))
	require.NoError(t, h.Subscribe(ctx))

	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	require.Contains(t, rec.Body.String(), fx.itemID.String())

	// Nothing was materialized on the downstream.
	var links int64
	require.NoError(t, db.Model(&relational.SSPLeverageLink{}).Count(&links).Error)
	require.Zero(t, links)
}

// TestSubscribeReportsCreatedTree: Subscribe reports the requirement/statement/by-component it
// materialized, flagging inserts as created:true, so the UI can render newly-created
// requirements without re-walking the SSP. The tree is always requirement -> statement ->
// by-component, never requirement-anchored.
func TestSubscribeReportsCreatedTree(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	link, created := subscribeFixture(t, db, fx, fx.respAID)

	require.Len(t, created.ImplementedRequirements, 1)
	require.Equal(t, "ac-2", created.ImplementedRequirements[0].ControlID)
	require.True(t, created.ImplementedRequirements[0].Created, "downstream never implemented ac-2, so it was inserted")

	require.Len(t, created.Statements, 1)
	require.Equal(t, "ac-2_smt.a", created.Statements[0].StatementID)
	require.True(t, created.Statements[0].Created)
	require.Equal(t, created.ImplementedRequirements[0].UUID, created.Statements[0].ImplementedRequirementUUID)

	require.Len(t, created.ByComponents, 1)
	require.True(t, created.ByComponents[0].Created)
	require.Equal(t, created.Statements[0].UUID, created.ByComponents[0].StatementUUID)

	// The materialized by-component really is statement-anchored.
	var bc relational.ByComponent
	require.NoError(t, db.First(&bc, "id = ?", created.ByComponents[0].UUID).Error)
	require.NotNil(t, bc.ParentType)
	require.Equal(t, "statements", *bc.ParentType)
	require.Equal(t, created.Statements[0].UUID, *bc.ParentID)

	// ...and carries the inherited + satisfied rows, with the link pointing at them.
	var inherited relational.InheritedControlImplementation
	require.NoError(t, db.First(&inherited, "by_component_id = ?", bc.ID).Error)
	require.Equal(t, link.InheritedUUID, *inherited.ID)

	var satisfiedCount int64
	require.NoError(t, db.Model(&relational.SatisfiedControlImplementationResponsibility{}).
		Where("by_component_id = ?", bc.ID).Count(&satisfiedCount).Error)
	require.Equal(t, int64(1), satisfiedCount)
	require.Equal(t, relational.SSPLeverageSatisfactionPartial, link.Satisfaction)
}

// TestSubscribeReportsReusedRowsAsNotCreated: a second item on the same statement reuses the
// requirement, statement and by-component already materialized, and reports created:false.
func TestSubscribeReportsReusedRowsAsNotCreated(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	// A second provided capability on the same statement-anchored by-component, offered as a
	// second item in the same offering.
	provided2 := relational.ProvidedControlImplementation{ExportId: fx.exportID, Description: "second capability"}
	require.NoError(t, db.Create(&provided2).Error)
	item2 := relational.SSPExportOfferingItem{
		OfferingID: fx.offeringID, ControlID: "ac-2", StatementID: statementID("ac-2_smt.a"),
		ComponentUUID: fx.componentID, ProvidedUUID: *provided2.ID,
	}
	require.NoError(t, db.Create(&item2).Error)

	pdp := &stubPDP{allow: true}
	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)
	body := fmt.Sprintf(
		`{"downstreamSspId":%q,"leveragedAuthorization":{"title":"Trust","partyUuid":%q},"items":[{"itemId":%q},{"itemId":%q}]}`,
		fx.downstreamSSPID.String(), uuid.New().String(), fx.itemID.String(), item2.ID.String())
	ctx, _, rec := newSubscribeRequestContext(fx.offeringID, body)
	require.NoError(t, h.Subscribe(ctx))
	require.Equal(t, http.StatusCreated, rec.Code)

	var resp struct {
		Data []relational.SSPLeverageLink `json:"data"`
		Meta subscribeMeta                `json:"meta"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 2, "two items subscribed, two links")

	// Both items land on the same requirement/statement/by-component: each is reported once,
	// as created (the first item inserted it), not duplicated per item.
	require.Len(t, resp.Meta.Created.ImplementedRequirements, 1)
	require.Len(t, resp.Meta.Created.Statements, 1)
	require.Len(t, resp.Meta.Created.ByComponents, 1)
	require.True(t, resp.Meta.Created.ByComponents[0].Created)
}

// TestSubscribeReportsExistingRequirementAsNotCreated: when the downstream already implements
// the control, the requirement is matched rather than inserted — created:false.
func TestSubscribeReportsExistingRequirementAsNotCreated(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	var downstreamImpl relational.ControlImplementation
	require.NoError(t, db.First(&downstreamImpl, "system_security_plan_id = ?", fx.downstreamSSPID).Error)
	existing := relational.ImplementedRequirement{
		ControlImplementationId: *downstreamImpl.ID, ControlId: "ac-2",
	}
	require.NoError(t, db.Create(&existing).Error)

	_, created := subscribeFixture(t, db, fx)

	require.Len(t, created.ImplementedRequirements, 1)
	require.Equal(t, *existing.ID, created.ImplementedRequirements[0].UUID)
	require.False(t, created.ImplementedRequirements[0].Created, "the requirement already existed")
	require.True(t, created.Statements[0].Created, "but its statement did not")
}

// --- Part 2: by-component reads -----------------------------------------------------------

// TestGetStatementByComponentReturnsFullSubtree: the single-by-component GET is what lets the
// UI refetch after editing a sub-resource, so it must carry export (with provided and
// responsibilities), inherited, satisfied and responsible-roles.
func TestGetStatementByComponentReturnsFullSubtree(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	inherited := relational.InheritedControlImplementation{
		ByComponentId: fx.byComponentID, ProvidedUuid: uuid.New(), Description: "inherited thing",
	}
	require.NoError(t, db.Create(&inherited).Error)
	satisfied := relational.SatisfiedControlImplementationResponsibility{
		ByComponentId: fx.byComponentID, ResponsibilityUuid: uuid.New(), Description: "satisfied thing",
	}
	require.NoError(t, db.Create(&satisfied).Error)

	h := newSSPHandler(db)
	ctx, rec := newByComponentContext(http.MethodGet, "", fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
	require.NoError(t, h.GetImplementedRequirementStatementByComponent(ctx))
	require.Equal(t, http.StatusOK, rec.Code)

	var resp handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	require.Equal(t, fx.byComponentID.String(), resp.Data.UUID)
	require.NotNil(t, resp.Data.Export)
	require.NotNil(t, resp.Data.Export.Provided)
	require.Len(t, *resp.Data.Export.Provided, 1)
	require.NotNil(t, resp.Data.Export.Responsibilities)
	require.Len(t, *resp.Data.Export.Responsibilities, 2)
	require.NotNil(t, resp.Data.Inherited)
	require.Len(t, *resp.Data.Inherited, 1)
	require.NotNil(t, resp.Data.Satisfied)
	require.Len(t, *resp.Data.Satisfied, 1)
}

// TestListStatementByComponentsReturnsAll: the list GET returns every by-component on the
// statement.
func TestListStatementByComponentsReturnsAll(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	statementsType := "statements"
	second := relational.ByComponent{
		ParentID: &fx.statementID, ParentType: &statementsType, ComponentUUID: uuid.New(),
	}
	require.NoError(t, db.Create(&second).Error)

	h := newSSPHandler(db)
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id", "reqId", "stmtId")
	ctx.SetParamValues(fx.upstreamSSPID.String(), fx.requirementID.String(), fx.statementID.String())

	require.NoError(t, h.GetImplementedRequirementStatementByComponents(ctx))
	require.Equal(t, http.StatusOK, rec.Code)

	var resp handler.GenericDataListResponse[oscalTypes_1_1_3.ByComponent]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 2)
}

// TestGetByComponentExportSubResources: the provided and responsibilities collections are
// readable on their own, which they never were.
func TestGetByComponentExportSubResources(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := newSSPHandler(db)

	ctx, rec := newByComponentContext(http.MethodGet, "", fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
	require.NoError(t, h.GetImplementedRequirementStatementByComponentExportProvided(ctx))
	require.Equal(t, http.StatusOK, rec.Code)
	var provided handler.GenericDataListResponse[oscalTypes_1_1_3.ProvidedControlImplementation]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &provided))
	require.Len(t, provided.Data, 1)
	require.Equal(t, fx.providedID.String(), provided.Data[0].UUID)

	ctx, rec = newByComponentContext(http.MethodGet, "", fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
	require.NoError(t, h.GetImplementedRequirementStatementByComponentExportResponsibilities(ctx))
	require.Equal(t, http.StatusOK, rec.Code)
	var responsibilities handler.GenericDataListResponse[oscalTypes_1_1_3.ControlImplementationResponsibility]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &responsibilities))
	require.Len(t, responsibilities.Data, 2)
}

// --- The blind-Save regression ------------------------------------------------------------

// TestUpdateByComponentDoesNotClobberSubtreesOrOmittedFields is the regression test for the
// latent bug in both by-component PUTs: they blind-Saved a struct rebuilt from the request
// body, so a PUT carrying only a description zeroed every other field, and a PUT carrying a
// nested export upserted it as a GORM association with no cascade cleanup.
func TestUpdateByComponentDoesNotClobberSubtreesOrOmittedFields(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	inherited := relational.InheritedControlImplementation{
		ByComponentId: fx.byComponentID, ProvidedUuid: uuid.New(), Description: "inherited thing",
	}
	require.NoError(t, db.Create(&inherited).Error)
	satisfied := relational.SatisfiedControlImplementationResponsibility{
		ByComponentId: fx.byComponentID, ResponsibilityUuid: uuid.New(), Description: "satisfied thing",
	}
	require.NoError(t, db.Create(&satisfied).Error)

	h := newSSPHandler(db)

	// A PUT that omits export/inherited/satisfied entirely, and additionally tries to smuggle
	// a nested export in — neither the omission nor the smuggled subtree may touch the stored
	// subtrees.
	body := fmt.Sprintf(`{
		"uuid": %q,
		"component-uuid": %q,
		"description": "updated description",
		"export": {"description": "smuggled export", "provided": [{"uuid": %q, "description": "smuggled provided"}]}
	}`, fx.byComponentID.String(), fx.componentID.String(), uuid.New().String())

	ctx, rec := newByComponentContext(http.MethodPut, body, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
	require.NoError(t, h.UpdateImplementedRequirementStatementByComponent(ctx))
	require.Equal(t, http.StatusOK, rec.Code)

	// The field the PUT actually set landed.
	var stored relational.ByComponent
	require.NoError(t, db.First(&stored, "id = ?", fx.byComponentID).Error)
	require.Equal(t, "updated description", stored.Description)

	// implementation-status is optional: a by-component that never had one must not gain an
	// empty {"state": ""} from a PUT that doesn't mention it.
	var updatedBC handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updatedBC))
	require.Nil(t, updatedBC.Data.ImplementationStatus)

	// The export subtree is untouched: still exactly one export with its original description,
	// one provided, two responsibilities. The smuggled export was not upserted.
	var exports []relational.Export
	require.NoError(t, db.Where("by_component_id = ?", fx.byComponentID).Find(&exports).Error)
	require.Len(t, exports, 1)
	require.Equal(t, fx.exportID, *exports[0].ID)
	require.Equal(t, "export", exports[0].Description)

	var providedCount, responsibilityCount int64
	require.NoError(t, db.Model(&relational.ProvidedControlImplementation{}).
		Where("export_id = ?", fx.exportID).Count(&providedCount).Error)
	require.Equal(t, int64(1), providedCount)
	require.NoError(t, db.Model(&relational.ControlImplementationResponsibility{}).
		Where("export_id = ?", fx.exportID).Count(&responsibilityCount).Error)
	require.Equal(t, int64(2), responsibilityCount)

	// Inherited and satisfied survive a PUT that never mentioned them.
	var inheritedCount, satisfiedCount int64
	require.NoError(t, db.Model(&relational.InheritedControlImplementation{}).
		Where("by_component_id = ?", fx.byComponentID).Count(&inheritedCount).Error)
	require.Equal(t, int64(1), inheritedCount)
	require.NoError(t, db.Model(&relational.SatisfiedControlImplementationResponsibility{}).
		Where("by_component_id = ?", fx.byComponentID).Count(&satisfiedCount).Error)
	require.Equal(t, int64(1), satisfiedCount)
}

// --- Part 3: Inherited / Satisfied CRUD ---------------------------------------------------

// TestInheritedCRUDRoundTrip: create, read, update and delete a hand-authored inherited entry.
func TestInheritedCRUDRoundTrip(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := newSSPHandler(db)

	// A provided-uuid that actually resolves — the create now rejects one that doesn't.
	providedUUID := fx.providedID
	body := fmt.Sprintf(`{"provided-uuid": %q, "description": "we inherit this"}`, providedUUID.String())
	ctx, rec := newByComponentContext(http.MethodPost, body, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
	require.NoError(t, h.CreateImplementedRequirementStatementByComponentInherited(ctx))
	require.Equal(t, http.StatusCreated, rec.Code)

	var created handler.GenericDataResponse[oscalTypes_1_1_3.InheritedControlImplementation]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.Equal(t, providedUUID.String(), created.Data.ProvidedUuid)
	inheritedID := created.Data.UUID

	ctx, rec = newByComponentContext(http.MethodGet, "", fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
	require.NoError(t, h.GetImplementedRequirementStatementByComponentInherited(ctx))
	require.Equal(t, http.StatusOK, rec.Code)
	var list handler.GenericDataListResponse[oscalTypes_1_1_3.InheritedControlImplementation]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Len(t, list.Data, 1)

	updateBody := `{"description": "revised"}`
	ctx, rec = newByComponentContext(http.MethodPut, updateBody, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID,
		[2]string{"inheritedId", inheritedID})
	require.NoError(t, h.UpdateImplementedRequirementStatementByComponentInherited(ctx))
	require.Equal(t, http.StatusOK, rec.Code)
	var updated handler.GenericDataResponse[oscalTypes_1_1_3.InheritedControlImplementation]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.Equal(t, "revised", updated.Data.Description)
	require.Equal(t, providedUUID.String(), updated.Data.ProvidedUuid, "provided-uuid survives a PUT that omits it")

	ctx, rec = newByComponentContext(http.MethodDelete, "", fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID,
		[2]string{"inheritedId", inheritedID})
	require.NoError(t, h.DeleteImplementedRequirementStatementByComponentInherited(ctx))
	require.Equal(t, http.StatusNoContent, rec.Code, "hand-authored inherited entries delete freely")

	var count int64
	require.NoError(t, db.Model(&relational.InheritedControlImplementation{}).
		Where("by_component_id = ?", fx.byComponentID).Count(&count).Error)
	require.Zero(t, count)
}

// TestInheritedPutRejectsProvidedUuidChange: provided-uuid is the identity the leverage link
// and the drift detector join on, so it is immutable.
func TestInheritedPutRejectsProvidedUuidChange(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := newSSPHandler(db)

	inherited := relational.InheritedControlImplementation{
		ByComponentId: fx.byComponentID, ProvidedUuid: uuid.New(), Description: "inherited",
	}
	require.NoError(t, db.Create(&inherited).Error)

	body := fmt.Sprintf(`{"provided-uuid": %q, "description": "sneaky"}`, uuid.New().String())
	ctx, rec := newByComponentContext(http.MethodPut, body, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID,
		[2]string{"inheritedId", inherited.ID.String()})
	require.NoError(t, h.UpdateImplementedRequirementStatementByComponentInherited(ctx))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "immutable")
}

// TestDeleteSubscriptionOwnedInheritedConflicts: an inherited entry an SSPLeverageLink still
// references is owned by that subscription — deleting it would leave the link pointing at
// nothing, so it returns 409 and points at unsubscribe.
func TestDeleteSubscriptionOwnedInheritedConflicts(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	link, created := subscribeFixture(t, db, fx, fx.respAID)
	bcID := created.ByComponents[0].UUID
	stmtID := created.Statements[0].UUID
	reqID := created.ImplementedRequirements[0].UUID

	h := newSSPHandler(db)
	ctx, rec := newByComponentContext(http.MethodDelete, "", fx.downstreamSSPID, reqID, stmtID, bcID,
		[2]string{"inheritedId", link.InheritedUUID.String()})
	require.NoError(t, h.DeleteImplementedRequirementStatementByComponentInherited(ctx))

	require.Equal(t, http.StatusConflict, rec.Code)
	require.Contains(t, rec.Body.String(), "unsubscribe")

	var count int64
	require.NoError(t, db.Model(&relational.InheritedControlImplementation{}).
		Where("id = ?", link.InheritedUUID).Count(&count).Error)
	require.Equal(t, int64(1), count, "the inherited entry survives the rejected delete")
}

// TestSatisfiedCreateRejectsForeignResponsibility: the responsibility-uuid must resolve to a
// responsibility on an export this by-component actually inherits from.
func TestSatisfiedCreateRejectsForeignResponsibility(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	_, created := subscribeFixture(t, db, fx)
	bcID := created.ByComponents[0].UUID

	h := newSSPHandler(db)
	body := fmt.Sprintf(`{"responsibility-uuid": %q, "description": "not ours"}`, uuid.New().String())
	ctx, rec := newByComponentContext(http.MethodPost, body, fx.downstreamSSPID,
		created.ImplementedRequirements[0].UUID, created.Statements[0].UUID, bcID)
	require.NoError(t, h.CreateImplementedRequirementStatementByComponentSatisfied(ctx))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "not a responsibility")
}

// TestSatisfiedWritesRederiveLeverageSatisfaction: adding the last outstanding satisfied entry
// flips the owning link partial -> full, and removing it flips it back — in the same
// transaction as the write, so the drift detector never reads stale bookkeeping. The
// leveraged-controls projection agrees, since it recomputes satisfaction live.
func TestSatisfiedWritesRederiveLeverageSatisfaction(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	// Subscribe satisfying only respA, of two responsibilities -> partial.
	link, created := subscribeFixture(t, db, fx, fx.respAID)
	require.Equal(t, relational.SSPLeverageSatisfactionPartial, link.Satisfaction)

	reqID := created.ImplementedRequirements[0].UUID
	stmtID := created.Statements[0].UUID
	bcID := created.ByComponents[0].UUID
	h := newSSPHandler(db)

	// Satisfy respB too -> full.
	body := fmt.Sprintf(`{"responsibility-uuid": %q, "description": "and now b"}`, fx.respBID.String())
	ctx, rec := newByComponentContext(http.MethodPost, body, fx.downstreamSSPID, reqID, stmtID, bcID)
	require.NoError(t, h.CreateImplementedRequirementStatementByComponentSatisfied(ctx))
	require.Equal(t, http.StatusCreated, rec.Code)

	var satisfiedResp handler.GenericDataResponse[oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &satisfiedResp))

	var reloaded relational.SSPLeverageLink
	require.NoError(t, db.First(&reloaded, "id = ?", link.ID).Error)
	require.Equal(t, relational.SSPLeverageSatisfactionFull, reloaded.Satisfaction)

	projection, err := projectLeveragedControls(db, fx.downstreamSSPID)
	require.NoError(t, err)
	require.Len(t, projection, 1)
	require.Equal(t, relational.SSPLeverageSatisfactionFull, projection[0].Satisfaction)
	require.Empty(t, projection[0].Outstanding)

	// Remove it again -> back to partial.
	ctx, rec = newByComponentContext(http.MethodDelete, "", fx.downstreamSSPID, reqID, stmtID, bcID,
		[2]string{"satisfiedId", satisfiedResp.Data.UUID})
	require.NoError(t, h.DeleteImplementedRequirementStatementByComponentSatisfied(ctx))
	require.Equal(t, http.StatusNoContent, rec.Code)

	require.NoError(t, db.First(&reloaded, "id = ?", link.ID).Error)
	require.Equal(t, relational.SSPLeverageSatisfactionPartial, reloaded.Satisfaction)

	projection, err = projectLeveragedControls(db, fx.downstreamSSPID)
	require.NoError(t, err)
	require.Equal(t, relational.SSPLeverageSatisfactionPartial, projection[0].Satisfaction)
	require.Len(t, projection[0].Outstanding, 1)
}

// TestSatisfiedPutRejectsResponsibilityUuidChange: responsibility-uuid is what satisfaction
// derivation matches on, so it is immutable.
func TestSatisfiedPutRejectsResponsibilityUuidChange(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := newSSPHandler(db)

	satisfied := relational.SatisfiedControlImplementationResponsibility{
		ByComponentId: fx.byComponentID, ResponsibilityUuid: fx.respAID, Description: "satisfied",
	}
	require.NoError(t, db.Create(&satisfied).Error)

	body := fmt.Sprintf(`{"responsibility-uuid": %q}`, uuid.New().String())
	ctx, rec := newByComponentContext(http.MethodPut, body, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID,
		[2]string{"satisfiedId", satisfied.ID.String()})
	require.NoError(t, h.UpdateImplementedRequirementStatementByComponentSatisfied(ctx))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "immutable")
}

// TestSatisfiedWritesOnHandAuthoredEntriesSkipLeverageResync: a by-component with no leverage
// link (hand-authored inherited entries) has no bookkeeping to re-derive — the write succeeds
// and nothing blows up.
func TestSatisfiedWritesOnHandAuthoredEntriesSkipLeverageResync(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	// Hand-authored: an inherited entry pointing at the upstream's provided-uuid, with no
	// SSPLeverageLink anywhere.
	inherited := relational.InheritedControlImplementation{
		ByComponentId: fx.byComponentID, ProvidedUuid: fx.providedID, Description: "hand-authored",
	}
	require.NoError(t, db.Create(&inherited).Error)

	h := newSSPHandler(db)
	body := fmt.Sprintf(`{"responsibility-uuid": %q, "description": "done"}`, fx.respAID.String())
	ctx, rec := newByComponentContext(http.MethodPost, body, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
	require.NoError(t, h.CreateImplementedRequirementStatementByComponentSatisfied(ctx))
	require.Equal(t, http.StatusCreated, rec.Code)

	var count int64
	require.NoError(t, db.Model(&relational.SatisfiedControlImplementationResponsibility{}).
		Where("by_component_id = ?", fx.byComponentID).Count(&count).Error)
	require.Equal(t, int64(1), count)
}

// --- Part 4: the requirement-level hole ---------------------------------------------------

// TestDeleteRequirementByComponentCascades: the new requirement-level DELETE winds a legacy
// row down completely — export, provided, responsibilities, inherited and satisfied all go.
func TestDeleteRequirementByComponentCascades(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	requirementsType := "implemented_requirements"
	legacyBC := relational.ByComponent{
		ParentID: &fx.requirementID, ParentType: &requirementsType, ComponentUUID: fx.componentID,
	}
	require.NoError(t, db.Create(&legacyBC).Error)
	legacyExport := relational.Export{ByComponentId: *legacyBC.ID}
	require.NoError(t, db.Create(&legacyExport).Error)
	legacyProvided := relational.ProvidedControlImplementation{ExportId: *legacyExport.ID}
	require.NoError(t, db.Create(&legacyProvided).Error)
	legacyResp := relational.ControlImplementationResponsibility{
		ExportId: *legacyExport.ID, ProvidedUuid: *legacyProvided.ID,
	}
	require.NoError(t, db.Create(&legacyResp).Error)
	legacyInherited := relational.InheritedControlImplementation{
		ByComponentId: *legacyBC.ID, ProvidedUuid: uuid.New(),
	}
	require.NoError(t, db.Create(&legacyInherited).Error)
	legacySatisfied := relational.SatisfiedControlImplementationResponsibility{
		ByComponentId: *legacyBC.ID, ResponsibilityUuid: uuid.New(),
	}
	require.NoError(t, db.Create(&legacySatisfied).Error)

	h := newSSPHandler(db)
	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id", "reqId", "byComponentId")
	ctx.SetParamValues(fx.upstreamSSPID.String(), fx.requirementID.String(), legacyBC.ID.String())

	require.NoError(t, h.DeleteImplementedRequirementByComponent(ctx))
	require.Equal(t, http.StatusNoContent, rec.Code)

	for name, count := range map[string]func() int64{
		"by_component": func() int64 { return countRows(t, db, &relational.ByComponent{}, "id = ?", legacyBC.ID) },
		"export":       func() int64 { return countRows(t, db, &relational.Export{}, "id = ?", legacyExport.ID) },
		"provided": func() int64 {
			return countRows(t, db, &relational.ProvidedControlImplementation{}, "id = ?", legacyProvided.ID)
		},
		"responsibility": func() int64 {
			return countRows(t, db, &relational.ControlImplementationResponsibility{}, "id = ?", legacyResp.ID)
		},
		"inherited": func() int64 {
			return countRows(t, db, &relational.InheritedControlImplementation{}, "id = ?", legacyInherited.ID)
		},
		"satisfied": func() int64 {
			return countRows(t, db, &relational.SatisfiedControlImplementationResponsibility{}, "id = ?", legacySatisfied.ID)
		},
	} {
		require.Zerof(t, count(), "expected %s rows to be cascade-deleted with the by-component", name)
	}

	// The statement-anchored by-component alongside it is untouched.
	require.Equal(t, int64(1), countRows(t, db, &relational.ByComponent{}, "id = ?", fx.byComponentID))
}

func countRows(t *testing.T, db *gorm.DB, model any, query string, args ...any) int64 {
	t.Helper()
	var count int64
	require.NoError(t, db.Model(model).Where(query, args...).Count(&count).Error)
	return count
}

// --- Part 5: control-centric queries ------------------------------------------------------

// TestByControlResolvesEveryPointer: the by-control catalog answers "what's exported for this
// control, by whom, against which statement" with everything resolved, so the Controls UI walks
// nothing.
func TestByControlResolvesEveryPointer(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("controlId")
	ctx.SetParamValues("AC-2") // deliberately different casing from the stored "ac-2"

	require.NoError(t, h.ByControl(ctx))
	require.Equal(t, http.StatusOK, rec.Code)

	var resp handler.GenericDataListResponse[ControlExportOffer]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 1)

	offer := resp.Data[0]
	require.Equal(t, fx.offeringID, offer.OfferingID)
	require.Equal(t, "Meridian Offering", offer.OfferingTitle)
	require.Equal(t, 3, offer.OfferingVersion)
	require.Equal(t, relational.SSPExportOfferingStatusPublished, offer.OfferingStatus)
	require.Equal(t, fx.upstreamSSPID, offer.UpstreamSSPID)
	require.Equal(t, fx.itemID, offer.ItemID)
	require.NotNil(t, offer.StatementID)
	require.Equal(t, "ac-2_smt.a", *offer.StatementID)
	require.Equal(t, "Meridian Runtime", offer.ComponentTitle)
	require.NotNil(t, offer.Provided)
	require.Equal(t, "provided capability", offer.Provided.Description)
	require.Len(t, offer.Responsibilities, 2)
	for _, r := range offer.Responsibilities {
		require.Equal(t, fx.providedID, r.ProvidedUUID)
		require.NotEmpty(t, r.Description)
	}
}

// TestByControlExcludesUnpublishedOfferings: only published offerings are catalogued.
func TestByControlExcludesUnpublishedOfferings(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	require.NoError(t, db.Model(&relational.SSPExportOffering{}).
		Where("id = ?", fx.offeringID).
		Update("status", relational.SSPExportOfferingStatusDraft).Error)

	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)
	e := echo.New()
	rec := httptest.NewRecorder()
	ctx := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
	ctx.SetParamNames("controlId")
	ctx.SetParamValues("ac-2")

	require.NoError(t, h.ByControl(ctx))
	require.Equal(t, http.StatusOK, rec.Code)

	var resp handler.GenericDataListResponse[ControlExportOffer]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Empty(t, resp.Data)
}

// TestByControlHonoursDownstreamAllowList: with downstreamSspId set, only offerings that SSP is
// actually allow-listed to subscribe to come back.
func TestByControlHonoursDownstreamAllowList(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	byControl := func(downstream uuid.UUID) []ControlExportOffer {
		e := echo.New()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/?downstreamSspId="+downstream.String(), nil)
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("controlId")
		ctx.SetParamValues("ac-2")
		require.NoError(t, h.ByControl(ctx))
		require.Equal(t, http.StatusOK, rec.Code)

		var resp handler.GenericDataListResponse[ControlExportOffer]
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp.Data
	}

	// No allow-list rows: the type-level default, any downstream may subscribe.
	require.Len(t, byControl(fx.downstreamSSPID), 1)

	// Once an allow-list exists, a downstream not on it sees nothing.
	other := uuid.New()
	require.NoError(t, db.Create(&relational.SSPExportOfferingAllowedDownstream{
		OfferingID: fx.offeringID, DownstreamSSPID: other,
	}).Error)
	require.Empty(t, byControl(fx.downstreamSSPID))
	require.Len(t, byControl(other), 1)
}

// TestSharedResponsibilityRollup: provides/inherits/satisfies/legacy for a seeded SSP.
func TestSharedResponsibilityRollup(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := newSSPHandler(db)

	// A legacy requirement-anchored by-component that must be reported, not silently dropped —
	// it carries an actual export, which is what makes it shared-responsibility debt.
	requirementsType := "implemented_requirements"
	legacyBC := relational.ByComponent{
		ParentID: &fx.requirementID, ParentType: &requirementsType, ComponentUUID: fx.componentID,
	}
	require.NoError(t, db.Create(&legacyBC).Error)
	legacyExport := relational.Export{ByComponentId: *legacyBC.ID, Description: "legacy export"}
	require.NoError(t, db.Create(&legacyExport).Error)

	// ...and a bare requirement-anchored by-component that carries NOTHING. This is the ordinary
	// OSCAL shape for "this component implements this control", which every imported SSP is full
	// of — it must NOT be reported as debt.
	ordinaryBC := relational.ByComponent{
		ParentID: &fx.requirementID, ParentType: &requirementsType, ComponentUUID: uuid.New(),
		Description: "an ordinary requirement-level implementation",
	}
	require.NoError(t, db.Create(&ordinaryBC).Error)

	rollup := func(sspID uuid.UUID, query string) SharedResponsibilityRollup {
		e := echo.New()
		rec := httptest.NewRecorder()
		ctx := e.NewContext(httptest.NewRequest(http.MethodGet, "/"+query, nil), rec)
		ctx.SetParamNames("id")
		ctx.SetParamValues(sspID.String())
		require.NoError(t, h.SharedResponsibility(ctx))
		require.Equal(t, http.StatusOK, rec.Code)

		var resp handler.GenericDataResponse[SharedResponsibilityRollup]
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp.Data
	}

	// Upstream: it provides, and has one legacy row. It offers the capability, so offered=true.
	up := rollup(fx.upstreamSSPID, "")
	require.Len(t, up.Provides, 1)
	require.Equal(t, "ac-2", up.Provides[0].ControlID)
	require.Equal(t, "ac-2_smt.a", up.Provides[0].StatementID)
	require.Equal(t, fx.byComponentID, up.Provides[0].ByComponentUUID)
	require.Equal(t, "Meridian Runtime", up.Provides[0].ComponentTitle)
	require.Equal(t, fx.exportID, up.Provides[0].ExportUUID)
	require.Len(t, up.Provides[0].Provided, 1)
	require.Len(t, up.Provides[0].Responsibilities, 2)
	require.True(t, up.Provides[0].Offered, "an offering item points at this provided-uuid")

	require.Len(t, up.Legacy, 1, "only the by-component actually carrying an export is debt")
	require.Equal(t, *legacyBC.ID, up.Legacy[0].ByComponentUUID)
	require.Equal(t, "requirement-anchored export", up.Legacy[0].Reason)

	require.Empty(t, up.Inherits)
	require.Empty(t, up.Satisfies)

	// Downstream: after subscribing it inherits and satisfies, and provides nothing.
	link, _ := subscribeFixture(t, db, fx, fx.respAID)
	down := rollup(fx.downstreamSSPID, "")

	require.Empty(t, down.Provides)
	require.Empty(t, down.Legacy)

	require.Len(t, down.Inherits, 1)
	require.Equal(t, "ac-2", down.Inherits[0].ControlID)
	require.NotNil(t, down.Inherits[0].StatementID)
	require.Equal(t, "ac-2_smt.a", *down.Inherits[0].StatementID)
	require.Equal(t, fx.upstreamSSPID, down.Inherits[0].UpstreamSSPID)
	require.Equal(t, fx.offeringID, down.Inherits[0].OfferingID)
	require.Equal(t, 3, down.Inherits[0].OfferingVersion)
	require.Equal(t, *link.ID, down.Inherits[0].LeverageLinkID)
	require.Equal(t, relational.SSPLeverageSatisfactionPartial, down.Inherits[0].Satisfaction)
	require.Equal(t, relational.SSPLeverageStatusActive, down.Inherits[0].Status)
	require.Equal(t, link.InheritedUUID, down.Inherits[0].InheritedUUID)

	require.Len(t, down.Satisfies, 1)
	require.Equal(t, "ac-2", down.Satisfies[0].ControlID)
	require.Equal(t, "ac-2_smt.a", down.Satisfies[0].StatementID)
	require.Equal(t, fx.respAID, down.Satisfies[0].ResponsibilityUUID)
}

// TestSharedResponsibilityFiltersByControl: ?controlId= narrows every arm of the rollup.
func TestSharedResponsibilityFiltersByControl(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := newSSPHandler(db)

	subscribeFixture(t, db, fx, fx.respAID)

	rollup := func(sspID uuid.UUID, controlID string) SharedResponsibilityRollup {
		e := echo.New()
		rec := httptest.NewRecorder()
		ctx := e.NewContext(httptest.NewRequest(http.MethodGet, "/?controlId="+controlID, nil), rec)
		ctx.SetParamNames("id")
		ctx.SetParamValues(sspID.String())
		require.NoError(t, h.SharedResponsibility(ctx))
		// Without this, an error response still returns nil from the handler and its JSON body
		// unmarshals into a ZERO-VALUE rollup — so every "Empty" assertion below would pass just
		// as happily on a 500 as on a correctly-filtered 200.
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		var resp handler.GenericDataResponse[SharedResponsibilityRollup]
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp.Data
	}

	// Case-folded match on the control this SSP actually exports.
	matched := rollup(fx.upstreamSSPID, "AC-2")
	require.Len(t, matched.Provides, 1)

	// A control it has nothing for.
	unmatched := rollup(fx.upstreamSSPID, "ac-99")
	require.Empty(t, unmatched.Provides)

	downMatched := rollup(fx.downstreamSSPID, "ac-2")
	require.Len(t, downMatched.Inherits, 1)
	require.Len(t, downMatched.Satisfies, 1)

	downUnmatched := rollup(fx.downstreamSSPID, "ac-99")
	require.Empty(t, downUnmatched.Inherits)
	require.Empty(t, downUnmatched.Satisfies)
}

// --- responsible-roles: the polymorphic m2m nobody was exercising ------------------------

// countRoleParties reports how many responsible_role_parties join rows exist for the
// responsible-roles hanging off one polymorphic parent. Party rows themselves are shared and
// must never be deleted — only the join rows and the roles.
func countRoleParties(t *testing.T, db *gorm.DB, parentID uuid.UUID) int64 {
	t.Helper()
	var count int64
	require.NoError(t, db.Table("responsible_role_parties").
		Joins("JOIN responsible_roles ON responsible_roles.id = responsible_role_parties.responsible_role_id").
		Where("responsible_roles.parent_id = ?", parentID).
		Count(&count).Error)
	return count
}

// seedParty creates a Party with an explicit id. Party overrides BeforeCreate to add an
// OnConflict-DoNothing clause, which shadows UUIDModel's id-assigning hook — so a Party created
// without an id never gets one. Every production path sets it from the OSCAL uuid; so does this.
func seedParty(t *testing.T, db *gorm.DB) uuid.UUID {
	t.Helper()
	id := uuid.New()
	name := "Acme"
	party := relational.Party{
		UUIDModel: relational.UUIDModel{ID: &id},
		Type:      "organization",
		Name:      &name,
	}
	require.NoError(t, db.Create(&party).Error)
	return *party.ID
}

// TestInheritedResponsibleRolesSurviveCreateUpdateAndClearOnDelete exercises the polymorphic
// ResponsibleRole + responsible_role_parties m2m under an inherited entry: roles land on create,
// a PUT replaces them (deleting the old rows and their join rows rather than orphaning them),
// and a DELETE clears both the roles and the join rows while leaving the shared Party alone.
func TestInheritedResponsibleRolesSurviveCreateUpdateAndClearOnDelete(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := newSSPHandler(db)
	partyID := seedParty(t, db)

	createBody := fmt.Sprintf(`{
		"provided-uuid": %q,
		"description": "inherited with roles",
		"responsible-roles": [{"role-id": "provider", "party-uuids": [%q]}]
	}`, fx.providedID.String(), partyID.String())

	ctx, rec := newByComponentContext(http.MethodPost, createBody, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
	require.NoError(t, h.CreateImplementedRequirementStatementByComponentInherited(ctx))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var created handler.GenericDataResponse[oscalTypes_1_1_3.InheritedControlImplementation]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.NotNil(t, created.Data.ResponsibleRoles)
	require.Len(t, *created.Data.ResponsibleRoles, 1)
	require.Equal(t, "provider", (*created.Data.ResponsibleRoles)[0].RoleId)

	inheritedID := uuid.MustParse(created.Data.UUID)
	require.Equal(t, int64(1), countRows(t, db, &relational.ResponsibleRole{}, "parent_id = ?", inheritedID))
	require.Equal(t, int64(1), countRoleParties(t, db, inheritedID))

	// A PUT replaces the role set: the old role and its join row go, the new one lands.
	updateBody := fmt.Sprintf(`{
		"description": "revised",
		"responsible-roles": [{"role-id": "auditor", "party-uuids": [%q]}]
	}`, partyID.String())

	ctx, rec = newByComponentContext(http.MethodPut, updateBody, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID,
		[2]string{"inheritedId", inheritedID.String()})
	require.NoError(t, h.UpdateImplementedRequirementStatementByComponentInherited(ctx))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var updated handler.GenericDataResponse[oscalTypes_1_1_3.InheritedControlImplementation]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.NotNil(t, updated.Data.ResponsibleRoles)
	require.Len(t, *updated.Data.ResponsibleRoles, 1, "the replaced role set must not accumulate")
	require.Equal(t, "auditor", (*updated.Data.ResponsibleRoles)[0].RoleId)

	require.Equal(t, int64(1), countRows(t, db, &relational.ResponsibleRole{}, "parent_id = ?", inheritedID),
		"the superseded role must be deleted, not orphaned")
	require.Equal(t, int64(1), countRoleParties(t, db, inheritedID))

	// DELETE clears the roles and their join rows...
	ctx, rec = newByComponentContext(http.MethodDelete, "", fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID,
		[2]string{"inheritedId", inheritedID.String()})
	require.NoError(t, h.DeleteImplementedRequirementStatementByComponentInherited(ctx))
	require.Equal(t, http.StatusNoContent, rec.Code)

	require.Zero(t, countRows(t, db, &relational.ResponsibleRole{}, "parent_id = ?", inheritedID))
	require.Zero(t, countRoleParties(t, db, inheritedID))

	// ...but the Party is shared and must survive.
	require.Equal(t, int64(1), countRows(t, db, &relational.Party{}, "id = ?", partyID))
}

// TestSatisfiedResponsibleRolesSurviveCreateUpdateAndClearOnDelete is the same contract on the
// satisfied side.
func TestSatisfiedResponsibleRolesSurviveCreateUpdateAndClearOnDelete(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := newSSPHandler(db)
	partyID := seedParty(t, db)

	// Hand-authored inherited entry so respA is a legitimate thing to satisfy.
	inherited := relational.InheritedControlImplementation{
		ByComponentId: fx.byComponentID, ProvidedUuid: fx.providedID, Description: "hand-authored",
	}
	require.NoError(t, db.Create(&inherited).Error)

	createBody := fmt.Sprintf(`{
		"responsibility-uuid": %q,
		"description": "we do this",
		"responsible-roles": [{"role-id": "operator", "party-uuids": [%q]}]
	}`, fx.respAID.String(), partyID.String())

	ctx, rec := newByComponentContext(http.MethodPost, createBody, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
	require.NoError(t, h.CreateImplementedRequirementStatementByComponentSatisfied(ctx))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var created handler.GenericDataResponse[oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.NotNil(t, created.Data.ResponsibleRoles)
	require.Len(t, *created.Data.ResponsibleRoles, 1)

	satisfiedID := uuid.MustParse(created.Data.UUID)
	require.Equal(t, int64(1), countRows(t, db, &relational.ResponsibleRole{}, "parent_id = ?", satisfiedID))
	require.Equal(t, int64(1), countRoleParties(t, db, satisfiedID))

	updateBody := fmt.Sprintf(`{
		"description": "revised",
		"responsible-roles": [
			{"role-id": "operator", "party-uuids": [%q]},
			{"role-id": "reviewer", "party-uuids": [%q]}
		]
	}`, partyID.String(), partyID.String())

	ctx, rec = newByComponentContext(http.MethodPut, updateBody, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID,
		[2]string{"satisfiedId", satisfiedID.String()})
	require.NoError(t, h.UpdateImplementedRequirementStatementByComponentSatisfied(ctx))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var updated handler.GenericDataResponse[oscalTypes_1_1_3.SatisfiedControlImplementationResponsibility]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.NotNil(t, updated.Data.ResponsibleRoles)
	require.Len(t, *updated.Data.ResponsibleRoles, 2)
	require.Equal(t, int64(2), countRows(t, db, &relational.ResponsibleRole{}, "parent_id = ?", satisfiedID))
	require.Equal(t, int64(2), countRoleParties(t, db, satisfiedID))

	ctx, rec = newByComponentContext(http.MethodDelete, "", fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID,
		[2]string{"satisfiedId", satisfiedID.String()})
	require.NoError(t, h.DeleteImplementedRequirementStatementByComponentSatisfied(ctx))
	require.Equal(t, http.StatusNoContent, rec.Code)

	require.Zero(t, countRows(t, db, &relational.ResponsibleRole{}, "parent_id = ?", satisfiedID))
	require.Zero(t, countRoleParties(t, db, satisfiedID))
	require.Equal(t, int64(1), countRows(t, db, &relational.Party{}, "id = ?", partyID))
}

// TestUpdateByComponentReplacesResponsibleRoles: the by-component PUT owns responsible-roles, so
// it replaces them — and the superseded rows (and their join rows) are deleted, not orphaned.
func TestUpdateByComponentReplacesResponsibleRoles(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := newSSPHandler(db)
	partyID := seedParty(t, db)

	put := func(body string) *httptest.ResponseRecorder {
		ctx, rec := newByComponentContext(http.MethodPut, body, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
		require.NoError(t, h.UpdateImplementedRequirementStatementByComponent(ctx))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		return rec
	}

	put(fmt.Sprintf(`{
		"uuid": %q, "component-uuid": %q, "description": "with roles",
		"responsible-roles": [{"role-id": "owner", "party-uuids": [%q]}]
	}`, fx.byComponentID.String(), fx.componentID.String(), partyID.String()))

	require.Equal(t, int64(1), countRows(t, db, &relational.ResponsibleRole{}, "parent_id = ?", fx.byComponentID))
	require.Equal(t, int64(1), countRoleParties(t, db, fx.byComponentID))

	// A PUT with no responsible-roles clears them — the field is one this route owns.
	rec := put(fmt.Sprintf(`{"uuid": %q, "component-uuid": %q, "description": "no roles"}`,
		fx.byComponentID.String(), fx.componentID.String()))

	var updated handler.GenericDataResponse[oscalTypes_1_1_3.ByComponent]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.Nil(t, updated.Data.ResponsibleRoles)

	require.Zero(t, countRows(t, db, &relational.ResponsibleRole{}, "parent_id = ?", fx.byComponentID))
	require.Zero(t, countRoleParties(t, db, fx.byComponentID))
	require.Equal(t, int64(1), countRows(t, db, &relational.Party{}, "id = ?", partyID), "Party rows are shared and must survive")

	// The export subtree is still untouched by any of this.
	require.Equal(t, int64(1), countRows(t, db, &relational.Export{}, "by_component_id = ?", fx.byComponentID))
}

// TestBulkAllowedOfferingsMatchesIsDownstreamAllowed: the batched allow-list resolution the
// by-control catalog uses must agree, offering for offering, with the per-offering rule Subscribe
// enforces. Two encodings of one rule is exactly how they drift.
func TestBulkAllowedOfferingsMatchesIsDownstreamAllowed(t *testing.T) {
	db := newSSPLeverageTestDB(t)

	downstream := uuid.New()
	other := uuid.New()

	noAllowList := relational.SSPExportOffering{Title: "open to all"}
	require.NoError(t, db.Create(&noAllowList).Error)

	allowsDownstream := relational.SSPExportOffering{Title: "allows our downstream"}
	require.NoError(t, db.Create(&allowsDownstream).Error)
	require.NoError(t, db.Create(&relational.SSPExportOfferingAllowedDownstream{
		OfferingID: *allowsDownstream.ID, DownstreamSSPID: downstream,
	}).Error)

	excludesDownstream := relational.SSPExportOffering{Title: "allows someone else"}
	require.NoError(t, db.Create(&excludesDownstream).Error)
	require.NoError(t, db.Create(&relational.SSPExportOfferingAllowedDownstream{
		OfferingID: *excludesDownstream.ID, DownstreamSSPID: other,
	}).Error)

	offeringIDs := []uuid.UUID{*noAllowList.ID, *allowsDownstream.ID, *excludesDownstream.ID}
	bulk, err := bulkAllowedOfferings(db, offeringIDs, downstream)
	require.NoError(t, err)

	for _, offeringID := range offeringIDs {
		single, err := isDownstreamAllowed(db, offeringID, downstream)
		require.NoError(t, err)
		require.Equalf(t, single, bulk[offeringID], "batched and per-offering allow-list disagree for %s", offeringID)
	}

	require.True(t, bulk[*noAllowList.ID], "no allow-list rows means the type-level default: any downstream")
	require.True(t, bulk[*allowsDownstream.ID])
	require.False(t, bulk[*excludesDownstream.ID])

	empty, err := bulkAllowedOfferings(db, nil, downstream)
	require.NoError(t, err)
	require.Empty(t, empty)
}

// TestByControlRouteIsNotShadowedByGetByID: /ssp-export-offerings/by-control/:controlId lives under
// the same prefix as /ssp-export-offerings/:id, so a router that resolved the param route first
// would send "by-control" to GetByID and fail with "invalid offering id" — silently, since both
// routes are registered and both are reachable in isolation. This drives the real echo router to
// pin the dispatch.
func TestByControlRouteIsNotShadowedByGetByID(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	pep := middleware.NewPEP(&stubPDP{allow: true}, authz.FailClosed, zap.NewNop().Sugar())
	e := echo.New()
	NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil).
		Register(e.Group("/api/oscal/ssp-export-offerings"), pep.For(authz.ResourceSSPExportOffering))

	// The static by-control segment must win over :id.
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/oscal/ssp-export-offerings/by-control/ac-2", nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var byControl handler.GenericDataListResponse[ControlExportOffer]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &byControl))
	require.Len(t, byControl.Data, 1)
	require.Equal(t, fx.itemID, byControl.Data[0].ItemID)

	// ...and a real offering id still reaches GetByID.
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/oscal/ssp-export-offerings/"+fx.offeringID.String(), nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var byID handler.GenericDataResponse[catalogOffering]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &byID))
	require.Equal(t, fx.offeringID, *byID.Data.ID)
}

// TestSharedResponsibilityOfferedIsPublishedOnly: `offered` claims a downstream can actually
// find and subscribe to the capability. A draft/deprecated/revoked offering is invisible to
// every downstream (ListAll and ByControl are published-only, Subscribe 404s on anything else),
// so an item on one must not set the flag — otherwise the rollup advertises a capability nothing
// can reach.
func TestSharedResponsibilityOfferedIsPublishedOnly(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := newSSPHandler(db)

	provides := func() SharedResponsibilityProvides {
		e := echo.New()
		rec := httptest.NewRecorder()
		ctx := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
		ctx.SetParamNames("id")
		ctx.SetParamValues(fx.upstreamSSPID.String())
		require.NoError(t, h.SharedResponsibility(ctx))
		require.Equal(t, http.StatusOK, rec.Code)

		var resp handler.GenericDataResponse[SharedResponsibilityRollup]
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		require.Len(t, resp.Data.Provides, 1)
		return resp.Data.Provides[0]
	}

	// The fixture's offering is published, and its item points at this provided-uuid.
	require.True(t, provides().Offered)

	setStatus := func(status relational.SSPExportOfferingStatus) {
		require.NoError(t, db.Model(&relational.SSPExportOffering{}).
			Where("id = ?", fx.offeringID).
			Update("status", status).Error)
	}

	// Every non-published status hides the offering from downstreams, so none of them count.
	for _, status := range []relational.SSPExportOfferingStatus{
		relational.SSPExportOfferingStatusDraft,
		relational.SSPExportOfferingStatusDeprecated,
		relational.SSPExportOfferingStatusRevoked,
	} {
		setStatus(status)
		row := provides()
		require.Falsef(t, row.Offered, "an item on a %q offering must not count as offered", status)
		// The capability itself is still reported — only the flag changes.
		require.Equal(t, fx.byComponentID, row.ByComponentUUID)
		require.Len(t, row.Provided, 1)
	}

	setStatus(relational.SSPExportOfferingStatusPublished)
	require.True(t, provides().Offered)
}

// TestUpdateByComponentRejectsComponentUuidChange: component-uuid identifies which component the
// by-component describes, and the offering-item coherence check joins on it — so a PUT naming a
// different one is rejected rather than silently ignored. Omitting it stays legal.
func TestUpdateByComponentRejectsComponentUuidChange(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := newSSPHandler(db)

	body := fmt.Sprintf(`{"uuid": %q, "component-uuid": %q, "description": "moved"}`,
		fx.byComponentID.String(), uuid.New().String())
	ctx, rec := newByComponentContext(http.MethodPut, body, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
	require.NoError(t, h.UpdateImplementedRequirementStatementByComponent(ctx))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "immutable")

	var stored relational.ByComponent
	require.NoError(t, db.First(&stored, "id = ?", fx.byComponentID).Error)
	require.Equal(t, fx.componentID, stored.ComponentUUID, "the rejected PUT must not have moved the by-component")
	require.Equal(t, "original description", stored.Description, "the rejected PUT must not have written anything")

	// Omitting component-uuid entirely is still legal — it defaults to the stored value.
	body = fmt.Sprintf(`{"uuid": %q, "description": "renamed"}`, fx.byComponentID.String())
	ctx, rec = newByComponentContext(http.MethodPut, body, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
	require.NoError(t, h.UpdateImplementedRequirementStatementByComponent(ctx))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	require.NoError(t, db.First(&stored, "id = ?", fx.byComponentID).Error)
	require.Equal(t, fx.componentID, stored.ComponentUUID)
	require.Equal(t, "renamed", stored.Description)
}

// --- the guard must hold on EVERY delete path, not just the sub-resource route -------------

// TestDeletingByComponentWithSubscribedInheritedConflicts: the 409 that protects a
// subscription-owned inherited entry must not be bypassable by deleting its PARENT. Every path
// that destroys a by-component destroys its Inherited rows with it, and SSPLeverageLink.InheritedUUID
// is a bare value with no FK — so an unguarded parent delete leaves the link pointing at nothing.
//
// A link with a dangling InheritedUUID is not merely untidy: projectLeveragedControls finds no
// inherited row, falls back to the zero by-component id, and derives satisfaction against an empty
// satisfied set — silently reporting `partial` with every responsibility outstanding on a link that
// was fully satisfied. ReAttest, meanwhile, 500s on the missing row and the link can never be
// re-attested.
func TestDeletingByComponentWithSubscribedInheritedConflicts(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	link, created := subscribeFixture(t, db, fx, fx.respAID)
	reqID := created.ImplementedRequirements[0].UUID
	stmtID := created.Statements[0].UUID
	bcID := created.ByComponents[0].UUID

	h := newSSPHandler(db)

	// The statement-level by-component DELETE — this is the by-component Subscribe always creates.
	ctx, rec := newByComponentContext(http.MethodDelete, "", fx.downstreamSSPID, reqID, stmtID, bcID)
	require.NoError(t, h.DeleteImplementedRequirementStatementByComponent(ctx))
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "unsubscribe")

	// The requirement DELETE, which cascades through every by-component beneath it.
	e := echo.New()
	rec = httptest.NewRecorder()
	ctx = e.NewContext(httptest.NewRequest(http.MethodDelete, "/", nil), rec)
	ctx.SetParamNames("id", "reqId")
	ctx.SetParamValues(fx.downstreamSSPID.String(), reqID.String())
	require.NoError(t, h.DeleteImplementedRequirement(ctx))
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())

	// Nothing was destroyed, and the link still resolves to its inherited row.
	require.Equal(t, int64(1), countRows(t, db, &relational.ByComponent{}, "id = ?", bcID))
	require.Equal(t, int64(1), countRows(t, db, &relational.InheritedControlImplementation{}, "id = ?", link.InheritedUUID))
	require.Equal(t, int64(1), countRows(t, db, &relational.ImplementedRequirement{}, "id = ?", reqID))

	projection, err := projectLeveragedControls(db, fx.downstreamSSPID)
	require.NoError(t, err)
	require.Len(t, projection, 1)
	require.NotNil(t, projection[0].Inherited, "the link must still resolve to a live inherited row")
	require.Equal(t, bcID, projection[0].ByComponentID)
}

// TestDeletingByComponentWithHandAuthoredInheritedSucceeds is the control for the test above: the
// guard keys on an actual SSPLeverageLink, so a hand-authored inherited entry (no link) does not
// block the delete — otherwise the cascade would be unusable.
func TestDeletingByComponentWithHandAuthoredInheritedSucceeds(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	inherited := relational.InheritedControlImplementation{
		ByComponentId: fx.byComponentID, ProvidedUuid: uuid.New(), Description: "hand-authored",
	}
	require.NoError(t, db.Create(&inherited).Error)

	h := newSSPHandler(db)
	ctx, rec := newByComponentContext(http.MethodDelete, "", fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
	require.NoError(t, h.DeleteImplementedRequirementStatementByComponent(ctx))
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())

	require.Zero(t, countRows(t, db, &relational.ByComponent{}, "id = ?", fx.byComponentID))
	require.Zero(t, countRows(t, db, &relational.InheritedControlImplementation{}, "id = ?", inherited.ID))
}

// TestOfferingItemStoresCanonicalControlIdCasing: coherence folds case when matching a control-id,
// but the stored item must carry the requirement's catalog-canonical casing — because Subscribe's
// findOrCreateImplementedRequirement matches control_id EXACTLY. Store the client's casing and a
// downstream that already implements the control under the canonical casing gets a SECOND
// requirement row, splitting its tree across two rows for the same control.
func TestOfferingItemStoresCanonicalControlIdCasing(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), db, nil)

	// The upstream requirement is stored as "ac-2"; the curator sends "AC-2".
	req := createExportOfferingItemRequest{
		ControlID:     "AC-2",
		StatementID:   statementID("ac-2_smt.a"),
		ComponentUUID: fx.componentID.String(),
		ProvidedUUID:  fx.providedID.String(),
	}
	require.NoError(t, h.validateOfferingItemCoherence(fx.upstreamSSPID, &req))
	require.Equal(t, "ac-2", req.ControlID,
		"coherence must normalize the control-id to the requirement's canonical casing before it is stored")

	// End-to-end through the write path: the persisted item carries the canonical casing...
	e := echo.New()
	body := `{"controlId":"AC-2","statementId":"ac-2_smt.a","componentUuid":"` + fx.componentID.String() +
		`","providedUuid":"` + fx.providedID.String() + `"}`
	httpReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(body))
	httpReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(httpReq, rec)
	ctx.SetParamNames("id", "offeringId")
	ctx.SetParamValues(fx.upstreamSSPID.String(), fx.offeringID.String())

	require.NoError(t, h.CreateItem(ctx))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var createdItem handler.GenericDataResponse[relational.SSPExportOfferingItem]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &createdItem))
	require.Equal(t, "ac-2", createdItem.Data.ControlID)

	// ...so Subscribe's exact match finds the downstream's existing requirement rather than
	// inserting a duplicate for the same control.
	var downstreamImpl relational.ControlImplementation
	require.NoError(t, db.First(&downstreamImpl, "system_security_plan_id = ?", fx.downstreamSSPID).Error)
	existing := relational.ImplementedRequirement{ControlImplementationId: *downstreamImpl.ID, ControlId: "ac-2"}
	require.NoError(t, db.Create(&existing).Error)

	pdp := &stubPDP{allow: true}
	lh := NewSSPLeverageHandler(zap.NewNop().Sugar(), db, pdp, authz.FailClosed)
	sctx, _, srec := newSubscribeRequestContext(fx.offeringID, subscribeBody(fx.downstreamSSPID, *createdItem.Data.ID))
	require.NoError(t, lh.Subscribe(sctx))
	require.Equal(t, http.StatusCreated, srec.Code, srec.Body.String())

	var count int64
	require.NoError(t, db.Model(&relational.ImplementedRequirement{}).
		Where("control_implementation_id = ?", downstreamImpl.ID).Count(&count).Error)
	require.Equal(t, int64(1), count,
		"subscribe must reuse the downstream's existing ac-2 requirement, not insert a case-variant duplicate")
}

// TestSharedResponsibilityLegacyExcludesOrdinaryImplementations: a requirement-anchored
// by-component that carries no export, no inherited and no satisfied row is NOT legacy debt — it
// is the ordinary OSCAL shape for "this component implements this control", and every SSP created
// or imported through POST /api/oscal/import is full of them. Reporting those would hand the UI an
// SSP's entire control implementation as debt and invite the user to delete their own work.
func TestSharedResponsibilityLegacyExcludesOrdinaryImplementations(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := newSSPHandler(db)

	requirementsType := "implemented_requirements"
	newLegacyBC := func(desc string) relational.ByComponent {
		bc := relational.ByComponent{
			ParentID: &fx.requirementID, ParentType: &requirementsType,
			ComponentUUID: uuid.New(), Description: desc,
		}
		require.NoError(t, db.Create(&bc).Error)
		return bc
	}

	// Three ordinary requirement-level implementations — the shape a normal imported SSP is full of.
	ordinaryA := newLegacyBC("ordinary a")
	newLegacyBC("ordinary b")
	newLegacyBC("ordinary c")

	// One that carries an export, and one that carries only consumer-side rows.
	withExport := newLegacyBC("carries an export")
	require.NoError(t, db.Create(&relational.Export{ByComponentId: *withExport.ID}).Error)

	withInherited := newLegacyBC("carries an inherited entry")
	require.NoError(t, db.Create(&relational.InheritedControlImplementation{
		ByComponentId: *withInherited.ID, ProvidedUuid: uuid.New(), Description: "inherited",
	}).Error)

	withSatisfied := newLegacyBC("carries a satisfied entry")
	require.NoError(t, db.Create(&relational.SatisfiedControlImplementationResponsibility{
		ByComponentId: *withSatisfied.ID, ResponsibilityUuid: uuid.New(), Description: "satisfied",
	}).Error)

	e := echo.New()
	rec := httptest.NewRecorder()
	ctx := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
	ctx.SetParamNames("id")
	ctx.SetParamValues(fx.upstreamSSPID.String())
	require.NoError(t, h.SharedResponsibility(ctx))
	require.Equal(t, http.StatusOK, rec.Code)

	var resp handler.GenericDataResponse[SharedResponsibilityRollup]
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	reported := make(map[uuid.UUID]string, len(resp.Data.Legacy))
	for _, l := range resp.Data.Legacy {
		reported[l.ByComponentUUID] = l.Reason
	}

	require.Len(t, resp.Data.Legacy, 3, "only the three by-components actually carrying shared responsibility are debt")
	require.Equal(t, "requirement-anchored export", reported[*withExport.ID])
	require.Equal(t, "requirement-anchored inherited/satisfied", reported[*withInherited.ID])
	require.Equal(t, "requirement-anchored inherited/satisfied", reported[*withSatisfied.ID])

	require.NotContains(t, reported, *ordinaryA.ID,
		"an ordinary requirement-level implementation is not shared-responsibility debt")
}

// TestCreateInheritedRejectsUnresolvableProvidedUuid: a well-formed but unresolvable provided-uuid
// creates an inert row — inheritableResponsibilities resolves nothing for it, so no satisfied entry
// can ever be accepted against it, yet it reads back as a real inherited capability. The satisfied
// POST already validates its responsibility-uuid this way; this closes the same gap one layer down.
func TestCreateInheritedRejectsUnresolvableProvidedUuid(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)
	h := newSSPHandler(db)

	body := fmt.Sprintf(`{"provided-uuid": %q, "description": "points at nothing"}`, uuid.New().String())
	ctx, rec := newByComponentContext(http.MethodPost, body, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
	require.NoError(t, h.CreateImplementedRequirementStatementByComponentInherited(ctx))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "does not resolve")
	require.Zero(t, countRows(t, db, &relational.InheritedControlImplementation{}, "by_component_id = ?", fx.byComponentID))

	// A provided-uuid that does resolve is accepted.
	body = fmt.Sprintf(`{"provided-uuid": %q, "description": "real"}`, fx.providedID.String())
	ctx, rec = newByComponentContext(http.MethodPost, body, fx.upstreamSSPID, fx.requirementID, fx.statementID, fx.byComponentID)
	require.NoError(t, h.CreateImplementedRequirementStatementByComponentInherited(ctx))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	require.Equal(t, int64(1), countRows(t, db, &relational.InheritedControlImplementation{}, "by_component_id = ?", fx.byComponentID))
}

// TestSubscribeStoresSatisfactionAgreeingWithTheProjection: deriveSatisfaction is shared, but its
// INPUT used to differ — Subscribe saw only the responsibilities this request asked to satisfy,
// while every reader recomputes from all satisfied rows on the by-component. A pre-existing
// hand-authored satisfied row therefore made the stored value ("partial") disagree with what the
// projection reports ("full"), and the stored value is what the drift detector consumes.
func TestSubscribeStoresSatisfactionAgreeingWithTheProjection(t *testing.T) {
	db := newSSPLeverageTestDB(t)
	fx := newSharedResponsibilityFixture(t, db)

	// The downstream already hand-authored the whole tree for this statement, satisfying BOTH of
	// the upstream's responsibilities — no leverage link, so the duplicate-link pre-check is silent.
	var downstreamImpl relational.ControlImplementation
	require.NoError(t, db.First(&downstreamImpl, "system_security_plan_id = ?", fx.downstreamSSPID).Error)
	var downstreamSysImpl relational.SystemImplementation
	require.NoError(t, db.First(&downstreamSysImpl, "system_security_plan_id = ?", fx.downstreamSSPID).Error)

	thisSystem := relational.SystemComponent{
		Type: thisSystemComponentType, Title: "This System",
		SystemImplementationId: *downstreamSysImpl.ID,
	}
	require.NoError(t, db.Create(&thisSystem).Error)

	req := relational.ImplementedRequirement{ControlImplementationId: *downstreamImpl.ID, ControlId: "ac-2"}
	require.NoError(t, db.Create(&req).Error)
	stmt := relational.Statement{ImplementedRequirementId: *req.ID, StatementId: "ac-2_smt.a"}
	require.NoError(t, db.Create(&stmt).Error)

	statementsType := "statements"
	bc := relational.ByComponent{ParentID: stmt.ID, ParentType: &statementsType, ComponentUUID: *thisSystem.ID}
	require.NoError(t, db.Create(&bc).Error)

	for _, respID := range []uuid.UUID{fx.respAID, fx.respBID} {
		require.NoError(t, db.Create(&relational.SatisfiedControlImplementationResponsibility{
			ByComponentId: *bc.ID, ResponsibilityUuid: respID, Description: "hand-authored",
		}).Error)
	}

	// Subscribe WITHOUT naming any responsibility to satisfy: the request's own satisfied set is
	// empty, so the old code would have stored "partial".
	link, _ := subscribeFixture(t, db, fx)

	var stored relational.SSPLeverageLink
	require.NoError(t, db.First(&stored, "id = ?", link.ID).Error)

	projection, err := projectLeveragedControls(db, fx.downstreamSSPID)
	require.NoError(t, err)
	require.Len(t, projection, 1)

	require.Equal(t, relational.SSPLeverageSatisfactionFull, projection[0].Satisfaction,
		"the reader sees both responsibilities covered by the pre-existing satisfied rows")
	require.Equal(t, projection[0].Satisfaction, stored.Satisfaction,
		"the value Subscribe stored — what the drift detector reads — must agree with the projection")
	require.Equal(t, projection[0].Satisfaction, link.Satisfaction,
		"and the subscribe response must report what was actually committed")
}
