//go:build integration

package oscal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/compliance-framework/api/internal/tests"
)

// FilterResponsibilityIntegrationSuite exercises the filter↔responsibility attach/detach
// endpoints (the write side of BCH-1339's filter_responsibilities), their control-link
// ownership semantics, and the responsibility-filters projection — end to end through the
// real subscribe pipeline, so the "responsibility this SSP inherits" validation runs
// against genuinely materialized leverage links.
type FilterResponsibilityIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func TestFilterResponsibilityIntegrationSuite(t *testing.T) {
	suite.Run(t, new(FilterResponsibilityIntegrationSuite))
}

// newCedarServerWithFilters is newCedarServer plus the /api/filters mount — the attach and
// detach routes live on the filters handler (package handler), which the oscal-only test
// server doesn't register.
func newCedarServerWithFilters(suite *tests.IntegrationTestSuite) *api.Server {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	pdp, err := authz.Open(authz.Options{Driver: authz.DriverCedar}, authz.Deps{
		DB:     suite.DB,
		Config: suite.Config,
		Logger: logger.Sugar(),
	})
	suite.Require().NoError(err)
	pep := middleware.NewPEP(pdp, authz.FailClosed, logger.Sugar())

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil, pep)

	filterHandler := handler.NewFilterHandler(logger.Sugar(), suite.DB)
	filterGroup := server.API().Group("/filters")
	filterGroup.Use(middleware.JWTMiddleware(suite.Config.JWTPublicKey))
	filterHandler.Register(filterGroup, pep.For(authz.ResourceFilter))

	return server
}

type filterResponsibilityFixture struct {
	server           *api.Server
	contributorToken string

	downstreamSSPID string
	providedUUID    string
	respAUUID       string
	respBUUID       string
}

// setupFilterResponsibilityFixture materializes a real leverage link: upstream SSP with a
// leverageable AC-1 capability (two responsibilities), published offering + item, downstream
// SSP, subscribe with nothing satisfied — plus a catalog control "ac-1" for the control-link
// side of attach.
func (suite *FilterResponsibilityIntegrationSuite) setupFilterResponsibilityFixture() filterResponsibilityFixture {
	suite.Require().NoError(suite.Migrator.Refresh())

	contributorToken := createRoledUser(&suite.IntegrationTestSuite, "contributor-fr@example.com", "contributor")
	server := newCedarServerWithFilters(&suite.IntegrationTestSuite)

	upstreamComponentUUID := uuid.New().String()
	providedUUID := uuid.New().String()
	respAUUID := uuid.New().String()
	respBUUID := uuid.New().String()
	upstreamSSP := sspWithLeverageableCapability(upstreamComponentUUID, providedUUID, respAUUID, respBUUID)
	rec := authedRequest(&suite.IntegrationTestSuite, server, "POST", "/api/oscal/system-security-plans", contributorToken, upstreamSSP)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings", upstreamSSP.UUID),
		contributorToken, map[string]string{"title": "AC-1 capability"})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var createdOffering handler.GenericDataResponse[relational.SSPExportOffering]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &createdOffering))
	offeringID := createdOffering.Data.ID.String()

	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings/%s/items", upstreamSSP.UUID, offeringID),
		contributorToken, leverageOfferingItemBody(upstreamComponentUUID, providedUUID))
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var createdItem handler.GenericDataResponse[relational.SSPExportOfferingItem]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &createdItem))

	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings/%s/publish", upstreamSSP.UUID, offeringID),
		contributorToken, nil)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())

	downstreamSSP := minimalSSP(uuid.New().String())
	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST", "/api/oscal/system-security-plans", contributorToken, downstreamSSP)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		"/api/oscal/ssp-export-offerings/"+offeringID+"/subscribe", contributorToken,
		map[string]any{
			"downstreamSspId": downstreamSSP.UUID,
			"items":           []map[string]any{{"itemId": createdItem.Data.ID.String()}},
		})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	// A catalog control for the control-link side. Deliberately lowercase — attach is
	// called with the SSP's casing ("AC-1") and must match case-insensitively.
	catalog := relational.Catalog{}
	suite.Require().NoError(suite.DB.Create(&catalog).Error)
	suite.Require().NoError(suite.DB.Create(&relational.Control{CatalogID: *catalog.ID, ID: "ac-1", Title: "Access Control Policy"}).Error)

	return filterResponsibilityFixture{
		server:           server,
		contributorToken: contributorToken,
		downstreamSSPID:  downstreamSSP.UUID,
		providedUUID:     providedUUID,
		respAUUID:        respAUUID,
		respBUUID:        respBUUID,
	}
}

func (suite *FilterResponsibilityIntegrationSuite) makeFilter(name string, sspID string) relational.Filter {
	parsed := uuid.MustParse(sspID)
	f := relational.Filter{
		Name:  name,
		SSPID: &parsed,
		Filter: datatypes.NewJSONType(labelfilter.Filter{
			Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "env", Operator: "=", Value: "prod"}},
		}),
	}
	suite.Require().NoError(suite.DB.Create(&f).Error)
	return f
}

func (suite *FilterResponsibilityIntegrationSuite) controlLinkCount(filterID uuid.UUID, controlID string) int64 {
	var n int64
	suite.Require().NoError(suite.DB.Table("filter_controls").
		Where("filter_id = ? AND control_id = ?", filterID, controlID).
		Count(&n).Error)
	return n
}

func (suite *FilterResponsibilityIntegrationSuite) attach(fx filterResponsibilityFixture, filterID uuid.UUID, respUUID string, controlID *string) *api.Server {
	body := map[string]any{"responsibilityUuid": respUUID, "sspId": fx.downstreamSSPID}
	if controlID != nil {
		body["controlId"] = *controlID
	}
	rec := authedRequest(&suite.IntegrationTestSuite, fx.server, "POST",
		fmt.Sprintf("/api/filters/%s/responsibilities", filterID), fx.contributorToken, body)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	return fx.server
}

func (suite *FilterResponsibilityIntegrationSuite) TestAttachDetachOwnsControlLink() {
	fx := suite.setupFilterResponsibilityFixture()
	filter := suite.makeFilter("resp filter", fx.downstreamSSPID)
	controlID := "AC-1" // SSP casing; catalog has "ac-1"

	// Attach with the control: creates the link and records ownership.
	rec := authedRequest(&suite.IntegrationTestSuite, fx.server, "POST",
		fmt.Sprintf("/api/filters/%s/responsibilities", filter.ID), fx.contributorToken,
		map[string]any{"responsibilityUuid": fx.respAUUID, "sspId": fx.downstreamSSPID, "controlId": controlID})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var created handler.GenericDataResponse[relational.FilterResponsibility]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &created))
	suite.True(created.Data.ControlLinkCreated)
	suite.Require().NotNil(created.Data.ControlID)
	suite.Equal("ac-1", *created.Data.ControlID, "the catalog's casing is what gets recorded")
	suite.Equal(int64(1), suite.controlLinkCount(*filter.ID, "ac-1"))

	// Duplicate triple → 409.
	rec = authedRequest(&suite.IntegrationTestSuite, fx.server, "POST",
		fmt.Sprintf("/api/filters/%s/responsibilities", filter.ID), fx.contributorToken,
		map[string]any{"responsibilityUuid": fx.respAUUID, "sspId": fx.downstreamSSPID})
	suite.Require().Equal(http.StatusConflict, rec.Code, rec.Body.String())

	// The projection surfaces the attachment with the filter name and provenance.
	rec = authedRequest(&suite.IntegrationTestSuite, fx.server, "GET",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/responsibility-filters", fx.downstreamSSPID),
		fx.contributorToken, nil)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var projection handler.GenericDataListResponse[responsibilityFilterResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &projection))
	suite.Require().Len(projection.Data, 1)
	suite.Equal(fx.respAUUID, projection.Data[0].ResponsibilityUUID.String())
	suite.Equal("resp filter", projection.Data[0].FilterName)
	suite.True(projection.Data[0].ControlLinkCreated)

	// Detach: the association goes, and so does the control link it created.
	rec = authedRequest(&suite.IntegrationTestSuite, fx.server, "DELETE",
		fmt.Sprintf("/api/filters/%s/responsibilities/%s?sspId=%s", filter.ID, fx.respAUUID, fx.downstreamSSPID),
		fx.contributorToken, nil)
	suite.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())
	suite.Equal(int64(0), suite.controlLinkCount(*filter.ID, "ac-1"))

	var remaining int64
	suite.Require().NoError(suite.DB.Model(&relational.FilterResponsibility{}).Count(&remaining).Error)
	suite.Equal(int64(0), remaining)
}

func (suite *FilterResponsibilityIntegrationSuite) TestDetachKeepsIndependentControlLink() {
	fx := suite.setupFilterResponsibilityFixture()

	// The filter is linked to the control independently (as POST/PUT /filters would do).
	var control relational.Control
	suite.Require().NoError(suite.DB.First(&control, "id = ?", "ac-1").Error)
	filter := suite.makeFilter("pre-linked filter", fx.downstreamSSPID)
	suite.Require().NoError(suite.DB.Model(&filter).Association("Controls").Append(&control))

	controlID := "ac-1"
	rec := authedRequest(&suite.IntegrationTestSuite, fx.server, "POST",
		fmt.Sprintf("/api/filters/%s/responsibilities", filter.ID), fx.contributorToken,
		map[string]any{"responsibilityUuid": fx.respAUUID, "sspId": fx.downstreamSSPID, "controlId": controlID})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var created handler.GenericDataResponse[relational.FilterResponsibility]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &created))
	suite.False(created.Data.ControlLinkCreated, "a pre-existing, independently created link is never owned")
	suite.Equal(int64(1), suite.controlLinkCount(*filter.ID, "ac-1"), "no duplicate link")

	rec = authedRequest(&suite.IntegrationTestSuite, fx.server, "DELETE",
		fmt.Sprintf("/api/filters/%s/responsibilities/%s?sspId=%s", filter.ID, fx.respAUUID, fx.downstreamSSPID),
		fx.contributorToken, nil)
	suite.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())
	suite.Equal(int64(1), suite.controlLinkCount(*filter.ID, "ac-1"), "the independent link survives detach")
}

func (suite *FilterResponsibilityIntegrationSuite) TestCoOwnedControlLinkRemovedByLastDetacher() {
	fx := suite.setupFilterResponsibilityFixture()
	filter := suite.makeFilter("co-owned filter", fx.downstreamSSPID)
	controlID := "ac-1"

	// respA creates the link; respB attaches while it exists and co-owns it.
	suite.attach(fx, *filter.ID, fx.respAUUID, &controlID)
	rec := authedRequest(&suite.IntegrationTestSuite, fx.server, "POST",
		fmt.Sprintf("/api/filters/%s/responsibilities", filter.ID), fx.contributorToken,
		map[string]any{"responsibilityUuid": fx.respBUUID, "sspId": fx.downstreamSSPID, "controlId": controlID})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var second handler.GenericDataResponse[relational.FilterResponsibility]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &second))
	suite.True(second.Data.ControlLinkCreated, "a responsibility-owned link is co-owned by later attachments")

	// First detach: the other claim keeps the link alive.
	rec = authedRequest(&suite.IntegrationTestSuite, fx.server, "DELETE",
		fmt.Sprintf("/api/filters/%s/responsibilities/%s?sspId=%s", filter.ID, fx.respAUUID, fx.downstreamSSPID),
		fx.contributorToken, nil)
	suite.Require().Equal(http.StatusNoContent, rec.Code)
	suite.Equal(int64(1), suite.controlLinkCount(*filter.ID, "ac-1"))

	// Last detach: nobody claims the link any more — it goes.
	rec = authedRequest(&suite.IntegrationTestSuite, fx.server, "DELETE",
		fmt.Sprintf("/api/filters/%s/responsibilities/%s?sspId=%s", filter.ID, fx.respBUUID, fx.downstreamSSPID),
		fx.contributorToken, nil)
	suite.Require().Equal(http.StatusNoContent, rec.Code)
	suite.Equal(int64(0), suite.controlLinkCount(*filter.ID, "ac-1"))
}

// TestDetachUnwindsLinkDespiteUnowningSibling: a filter_responsibilities row with
// ControlLinkCreated=false is not a claim on the link, so it must not block the unwind.
//
// The sequence is the reachable one: an independent link makes R1 unowned; the independent link is
// then removed; R2 attaches and creates the link itself. Detaching R2 must unwind the link R2
// created — counting R1 (same filter+control, but never a claimant) would strand it forever.
func (suite *FilterResponsibilityIntegrationSuite) TestDetachUnwindsLinkDespiteUnowningSibling() {
	fx := suite.setupFilterResponsibilityFixture()
	filter := suite.makeFilter("unwind filter", fx.downstreamSSPID)
	controlID := "ac-1"

	// An independently created link (as POST/PUT /filters would make).
	var control relational.Control
	suite.Require().NoError(suite.DB.First(&control, "id = ?", "ac-1").Error)
	suite.Require().NoError(suite.DB.Model(&filter).Association("Controls").Append(&control))

	// R1 attaches while that link exists, so it never owns it.
	rec := authedRequest(&suite.IntegrationTestSuite, fx.server, "POST",
		fmt.Sprintf("/api/filters/%s/responsibilities", filter.ID), fx.contributorToken,
		map[string]any{"responsibilityUuid": fx.respAUUID, "sspId": fx.downstreamSSPID, "controlId": controlID})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var r1 handler.GenericDataResponse[relational.FilterResponsibility]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &r1))
	suite.Require().False(r1.Data.ControlLinkCreated)

	// The independent link goes away.
	suite.Require().NoError(suite.DB.Model(&filter).Association("Controls").Delete(&control))
	suite.Require().Equal(int64(0), suite.controlLinkCount(*filter.ID, "ac-1"))

	// R2 attaches with no link present, so R2 creates and owns it.
	rec = authedRequest(&suite.IntegrationTestSuite, fx.server, "POST",
		fmt.Sprintf("/api/filters/%s/responsibilities", filter.ID), fx.contributorToken,
		map[string]any{"responsibilityUuid": fx.respBUUID, "sspId": fx.downstreamSSPID, "controlId": controlID})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var r2 handler.GenericDataResponse[relational.FilterResponsibility]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &r2))
	suite.Require().True(r2.Data.ControlLinkCreated, "no link existed, so R2 created it")
	suite.Require().Equal(int64(1), suite.controlLinkCount(*filter.ID, "ac-1"))

	// Detaching R2 must unwind the link it created: R1 is not a claimant.
	rec = authedRequest(&suite.IntegrationTestSuite, fx.server, "DELETE",
		fmt.Sprintf("/api/filters/%s/responsibilities/%s?sspId=%s", filter.ID, fx.respBUUID, fx.downstreamSSPID),
		fx.contributorToken, nil)
	suite.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())
	suite.Equal(int64(0), suite.controlLinkCount(*filter.ID, "ac-1"),
		"a ControlLinkCreated=false row is not a claim, so it must not strand the link R2 created")
}

// TestAttachRejectsAmbiguousControlAcrossCatalogs: Control's PK is composite (catalog_id, id), and
// two catalogs routinely define the same id (NIST 800-53 rev4 and rev5 both have AC-2). With
// nothing to disambiguate, attach must refuse rather than resolve to an arbitrary catalog's
// control — the old `First(LOWER(id) = ...)` returned whichever row the planner happened to yield
// and recorded that catalog on the row.
func (suite *FilterResponsibilityIntegrationSuite) TestAttachRejectsAmbiguousControlAcrossCatalogs() {
	fx := suite.setupFilterResponsibilityFixture()

	// A second catalog defining the very same control id as the fixture's.
	secondCatalog := relational.Catalog{}
	suite.Require().NoError(suite.DB.Create(&secondCatalog).Error)
	suite.Require().NoError(suite.DB.Create(&relational.Control{
		CatalogID: *secondCatalog.ID, ID: "ac-1", Title: "Access Control Policy (rev 2)",
	}).Error)

	filter := suite.makeFilter("ambiguous filter", fx.downstreamSSPID)
	rec := authedRequest(&suite.IntegrationTestSuite, fx.server, "POST",
		fmt.Sprintf("/api/filters/%s/responsibilities", filter.ID), fx.contributorToken,
		map[string]any{"responsibilityUuid": fx.respAUUID, "sspId": fx.downstreamSSPID, "controlId": "AC-1"})
	suite.Require().Equal(http.StatusBadRequest, rec.Code, rec.Body.String())
	suite.Contains(rec.Body.String(), "multiple catalogs")

	// And nothing was half-written.
	var rows int64
	suite.Require().NoError(suite.DB.Model(&relational.FilterResponsibility{}).
		Where("filter_id = ?", filter.ID).Count(&rows).Error)
	suite.Zero(rows, "a rejected attach must not leave a filter_responsibilities row")
	suite.Equal(int64(0), suite.controlLinkCount(*filter.ID, "ac-1"))
}

func (suite *FilterResponsibilityIntegrationSuite) TestAttachValidation() {
	fx := suite.setupFilterResponsibilityFixture()
	filter := suite.makeFilter("validation filter", fx.downstreamSSPID)

	// A responsibility the SSP does not inherit → 400.
	rec := authedRequest(&suite.IntegrationTestSuite, fx.server, "POST",
		fmt.Sprintf("/api/filters/%s/responsibilities", filter.ID), fx.contributorToken,
		map[string]any{"responsibilityUuid": uuid.New().String(), "sspId": fx.downstreamSSPID})
	suite.Require().Equal(http.StatusBadRequest, rec.Code, rec.Body.String())

	// An unknown downstream SSP → 404.
	rec = authedRequest(&suite.IntegrationTestSuite, fx.server, "POST",
		fmt.Sprintf("/api/filters/%s/responsibilities", filter.ID), fx.contributorToken,
		map[string]any{"responsibilityUuid": fx.respAUUID, "sspId": uuid.New().String()})
	suite.Require().Equal(http.StatusNotFound, rec.Code, rec.Body.String())

	// Detach without the sspId query param → 400 (the association is keyed per SSP).
	rec = authedRequest(&suite.IntegrationTestSuite, fx.server, "DELETE",
		fmt.Sprintf("/api/filters/%s/responsibilities/%s", filter.ID, fx.respAUUID),
		fx.contributorToken, nil)
	suite.Require().Equal(http.StatusBadRequest, rec.Code, rec.Body.String())

	// Detach an association that doesn't exist → 404.
	rec = authedRequest(&suite.IntegrationTestSuite, fx.server, "DELETE",
		fmt.Sprintf("/api/filters/%s/responsibilities/%s?sspId=%s", filter.ID, fx.respAUUID, fx.downstreamSSPID),
		fx.contributorToken, nil)
	suite.Require().Equal(http.StatusNotFound, rec.Code, rec.Body.String())
}

func (suite *FilterResponsibilityIntegrationSuite) TestLeveragedControlsExposesAnchorAndPostureKeys() {
	fx := suite.setupFilterResponsibilityFixture()

	rec := authedRequest(&suite.IntegrationTestSuite, fx.server, "GET",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/leveraged-controls", fx.downstreamSSPID),
		fx.contributorToken, nil)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var projection handler.GenericDataListResponse[leveragedControlResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &projection))
	suite.Require().Len(projection.Data, 1)

	link := projection.Data[0]
	suite.Equal(fx.providedUUID, link.ProvidedUuid.String())

	// The anchor is the downstream by-component the subscribe materialized — the row the
	// UI authors satisfied entries against.
	suite.Require().NotNil(link.ByComponentId)
	var anchor relational.ByComponent
	suite.Require().NoError(suite.DB.First(&anchor, "id = ?", link.ByComponentId).Error)
	suite.Require().NotNil(anchor.ParentType)
	suite.Equal("statements", *anchor.ParentType)

	// The anchor's component REPRESENTS THE UPSTREAM SYSTEM: named after the upstream SSP,
	// typed `system`, identified by the leveraged-system-uuid prop — "Platform exports
	// control 1 → the importer gains a Platform component on that implementation".
	var anchorComponent relational.SystemComponent
	suite.Require().NoError(suite.DB.First(&anchorComponent, "id = ?", anchor.ComponentUUID).Error)
	suite.Equal("system", anchorComponent.Type)
	suite.Equal("Export Offering AuthZ Test SSP", anchorComponent.Title)
	propValues := map[string]string{}
	for _, prop := range anchorComponent.Props {
		propValues[prop.Name] = prop.Value
	}
	suite.NotEmpty(propValues[leveragedSystemUUIDProp])
	suite.Equal("external", propValues["implementation-point"])

	// Posture is keyed by the FULL upstream responsibility set — unknown until a filter
	// with matching evidence is attached.
	suite.Equal("unknown", link.ResponsibilityPosture[uuid.MustParse(fx.respAUUID)])
	suite.Equal("unknown", link.ResponsibilityPosture[uuid.MustParse(fx.respBUUID)])
}
