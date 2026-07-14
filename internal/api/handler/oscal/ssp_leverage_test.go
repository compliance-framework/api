//go:build integration

package oscal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"gorm.io/datatypes"

	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

// SSPLeverageIntegrationSuite exercises BCH-1338's subscribe/leverage flow through a real
// cedar-driven PEP, reusing the plumbing built for BCH-1337
// (newCedarServer/createRoledUser/authedRequest/minimalSSP in ssp_export_offerings_test.go).
type SSPLeverageIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func TestSSPLeverageIntegrationSuite(t *testing.T) {
	suite.Run(t, new(SSPLeverageIntegrationSuite))
}

// leverageStatementID is the statement the fixture's leverageable capability is exported from.
// The statement is the canonical anchor for shared responsibility, so an Export — and the
// offering item pointing at it — hangs off a statement-level by-component, never a
// requirement-level one.
const leverageStatementID = "ac-1_smt.a"

// sspWithLeverageableCapability builds on minimalSSP by giving the ac-1
// implemented-requirement a statement, and that statement a by-component with an Export: one
// provided control implementation and two responsibilities under it — the fixture the
// subscribe/leverage flow needs on the upstream side.
func sspWithLeverageableCapability(componentUUID, providedUUID, respAUUID, respBUUID string) *oscalTypes_1_1_3.SystemSecurityPlan {
	ssp := minimalSSP(componentUUID)
	ssp.ControlImplementation.ImplementedRequirements[0].Statements = &[]oscalTypes_1_1_3.Statement{
		{
			UUID:        uuid.New().String(),
			StatementId: leverageStatementID,
			ByComponents: &[]oscalTypes_1_1_3.ByComponent{
				{
					UUID:          uuid.New().String(),
					ComponentUuid: componentUUID,
					Description:   "AC-1 statement (a) implemented by test component",
					Export: &oscalTypes_1_1_3.Export{
						Provided: &[]oscalTypes_1_1_3.ProvidedControlImplementation{
							{UUID: providedUUID, Description: "Provides AC-1 capability"},
						},
						Responsibilities: &[]oscalTypes_1_1_3.ControlImplementationResponsibility{
							{UUID: respAUUID, ProvidedUuid: providedUUID, Description: "Responsibility A"},
							{UUID: respBUUID, ProvidedUuid: providedUUID, Description: "Responsibility B"},
						},
					},
				},
			},
		},
	}
	return ssp
}

// leverageOfferingItemBody is the statement-anchored offering item pointing at the fixture's
// provided capability. statementId is required on every write, and the whole (controlId,
// statementId, componentUuid, providedUuid) tuple must actually resolve inside the upstream SSP.
func leverageOfferingItemBody(componentUUID, providedUUID string) map[string]any {
	return map[string]any{
		"controlId":     "ac-1",
		"statementId":   leverageStatementID,
		"componentUuid": componentUUID,
		"providedUuid":  providedUUID,
	}
}

// TestSubscribePartialThenProjection is the ticket's core integration scenario: a
// downstream subscriber holding only ssp-export-offering:subscribe + ssp:update (no
// ssp:read anywhere, in particular none on the upstream) subscribes to an offering item
// whose provided-uuid has 2 upstream responsibilities, satisfying only 1 — the
// projection then shows satisfaction "partial" with exactly the unsatisfied
// responsibility outstanding. It also proves the trust boundary (subscribe succeeds
// despite no ssp:read; the same subscriber is 403'd reading the upstream SSP directly),
// and confirms AC #4 by preloading the downstream's OSCAL subtree and marshaling it,
// showing the inherited/satisfied/leveraged-authorization entries round-trip with zero
// new export code.
func (suite *SSPLeverageIntegrationSuite) TestSubscribePartialThenProjection() {
	suite.Require().NoError(suite.Migrator.Refresh())

	contributorToken := createRoledUser(&suite.IntegrationTestSuite, "contributor@example.com", "contributor")
	subscriberToken := createRoledUser(&suite.IntegrationTestSuite, "subscriber@example.com", "ssp-subscriber")

	server := newCedarServer(&suite.IntegrationTestSuite)

	// Upstream SSP with a leverageable AC-1 capability (2 responsibilities).
	upstreamComponentUUID := uuid.New().String()
	providedUUID := uuid.New().String()
	respAUUID := uuid.New().String()
	respBUUID := uuid.New().String()
	upstreamSSP := sspWithLeverageableCapability(upstreamComponentUUID, providedUUID, respAUUID, respBUUID)
	rec := authedRequest(&suite.IntegrationTestSuite, server, "POST", "/api/oscal/system-security-plans", contributorToken, upstreamSSP)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	// Curate + publish the offering as the contributor (ssp:export on the upstream).
	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings", upstreamSSP.UUID),
		contributorToken,
		map[string]string{"title": "AC-1 leverageable capability"},
	)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var createdOffering handler.GenericDataResponse[relational.SSPExportOffering]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &createdOffering))
	offeringID := createdOffering.Data.ID.String()

	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings/%s/items", upstreamSSP.UUID, offeringID),
		contributorToken,
		leverageOfferingItemBody(upstreamComponentUUID, providedUUID),
	)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var createdItem handler.GenericDataResponse[relational.SSPExportOfferingItem]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &createdItem))
	itemID := createdItem.Data.ID.String()

	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings/%s/publish", upstreamSSP.UUID, offeringID),
		contributorToken, nil)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())

	// The catalog exposes the upstream's responsibility UUIDs (task 004) — a downstream
	// subscriber can discover them without ssp:read on the upstream.
	rec = authedRequest(&suite.IntegrationTestSuite, server, "GET", "/api/oscal/ssp-export-offerings/"+offeringID, subscriberToken, nil)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var catalogEntry handler.GenericDataResponse[catalogOffering]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &catalogEntry))
	suite.Require().Len(catalogEntry.Data.Items, 1)
	suite.Require().Len(catalogEntry.Data.Items[0].Responsibilities, 2)

	// Downstream SSP, created by the contributor — the subscriber only needs ssp:update
	// on an existing SSP, not ssp:create.
	downstreamComponentUUID := uuid.New().String()
	downstreamSSP := minimalSSP(downstreamComponentUUID)
	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST", "/api/oscal/system-security-plans", contributorToken, downstreamSSP)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	// Subscribe as the ssp-subscriber user, satisfying only 1 of the 2 responsibilities.
	subscribeReqBody := map[string]any{
		"downstreamSspId": downstreamSSP.UUID,
		"leveragedAuthorization": map[string]string{
			"title":     "Trust in upstream provider",
			"partyUuid": uuid.New().String(),
		},
		"items": []map[string]any{
			{"itemId": itemID, "satisfiedResponsibilityUuids": []string{respAUUID}},
		},
	}
	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		"/api/oscal/ssp-export-offerings/"+offeringID+"/subscribe", subscriberToken, subscribeReqBody)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var links handler.GenericDataListResponse[relational.SSPLeverageLink]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &links))
	suite.Require().Len(links.Data, 1)
	suite.Equal(relational.SSPLeverageSatisfactionPartial, links.Data[0].Satisfaction)

	// Re-subscribing to the same provided-uuid is rejected (unique constraint).
	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		"/api/oscal/ssp-export-offerings/"+offeringID+"/subscribe", subscriberToken, subscribeReqBody)
	suite.Require().Equal(http.StatusConflict, rec.Code, rec.Body.String())

	// Trust boundary: the subscriber has no ssp:read anywhere, so reading the upstream
	// SSP directly is forbidden — despite having just successfully subscribed to it.
	rec = authedRequest(&suite.IntegrationTestSuite, server, "GET", "/api/oscal/system-security-plans/"+upstreamSSP.UUID, subscriberToken, nil)
	suite.Require().Equal(http.StatusForbidden, rec.Code, rec.Body.String())

	// Projection (read via the contributor, who has ssp:read): satisfaction is partial,
	// with respB outstanding and respA not.
	rec = authedRequest(&suite.IntegrationTestSuite, server, "GET",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/leveraged-controls", downstreamSSP.UUID), contributorToken, nil)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var projection handler.GenericDataListResponse[leveragedControlResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &projection))
	suite.Require().Len(projection.Data, 1)
	suite.Equal("ac-1", projection.Data[0].ControlID)
	suite.Equal(relational.SSPLeverageSatisfactionPartial, projection.Data[0].Satisfaction)
	suite.Require().Len(projection.Data[0].OutstandingResponsibilities, 1)
	suite.Equal(respBUUID, projection.Data[0].OutstandingResponsibilities[0].ResponsibilityUUID.String())

	// AC #4: the downstream's OSCAL subtree, marshaled with zero new export code, contains the
	// inherited/satisfied/leveraged-authorization entries subscribe wrote — and the tree it
	// materialized is requirement -> statement -> by-component, never requirement-anchored.
	var downstream relational.SystemSecurityPlan
	suite.Require().NoError(suite.DB.
		Preload("SystemImplementation.LeveragedAuthorizations").
		Preload("ControlImplementation.ImplementedRequirements.ByComponents").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Inherited").
		Preload("ControlImplementation.ImplementedRequirements.Statements.ByComponents.Satisfied").
		First(&downstream, "id = ?", downstreamSSP.UUID).Error)

	marshaled := downstream.MarshalOscal()
	suite.Require().NotNil(marshaled.SystemImplementation.LeveragedAuthorizations)
	suite.Require().Len(*marshaled.SystemImplementation.LeveragedAuthorizations, 1)
	suite.Equal("Trust in upstream provider", (*marshaled.SystemImplementation.LeveragedAuthorizations)[0].Title)

	var foundInherited, foundSatisfied bool
	for _, req := range marshaled.ControlImplementation.ImplementedRequirements {
		if req.ControlId != "ac-1" {
			continue
		}

		// Nothing is anchored at the requirement level any more: the statement is the
		// canonical anchor, and Subscribe no longer has a requirement-anchoring fallback.
		suite.Nil(req.ByComponents, "subscribe must not anchor a by-component at the requirement level")

		suite.Require().NotNil(req.Statements)
		for _, stmt := range *req.Statements {
			if stmt.StatementId != leverageStatementID || stmt.ByComponents == nil {
				continue
			}
			for _, bc := range *stmt.ByComponents {
				if bc.Inherited != nil {
					for _, inh := range *bc.Inherited {
						if inh.ProvidedUuid == providedUUID {
							foundInherited = true
						}
					}
				}
				if bc.Satisfied != nil {
					for _, sat := range *bc.Satisfied {
						if sat.ResponsibilityUuid == respAUUID {
							foundSatisfied = true
						}
					}
				}
			}
		}
	}
	suite.True(foundInherited, "expected an inherited-control-implementation referencing the upstream provided-uuid, on a statement-anchored by-component")
	suite.True(foundSatisfied, "expected a satisfied responsibility referencing respA, on a statement-anchored by-component")
}

// TestSubscribeRequiresSSPUpdateOnDownstream: a viewer (ssp:read on everything, but no
// ssp:update and no ssp-export-offering:subscribe) is forbidden from subscribing.
func (suite *SSPLeverageIntegrationSuite) TestSubscribeRequiresSSPUpdateOnDownstream() {
	suite.Require().NoError(suite.Migrator.Refresh())

	contributorToken := createRoledUser(&suite.IntegrationTestSuite, "contributor2@example.com", "contributor")
	viewerToken := createRoledUser(&suite.IntegrationTestSuite, "viewer2@example.com", "viewer")

	server := newCedarServer(&suite.IntegrationTestSuite)

	componentUUID := uuid.New().String()
	providedUUID := uuid.New().String()
	respUUID := uuid.New().String()
	upstreamSSP := sspWithLeverageableCapability(componentUUID, providedUUID, respUUID, uuid.New().String())
	rec := authedRequest(&suite.IntegrationTestSuite, server, "POST", "/api/oscal/system-security-plans", contributorToken, upstreamSSP)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings", upstreamSSP.UUID),
		contributorToken, map[string]string{"title": "Offering"})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var createdOffering handler.GenericDataResponse[relational.SSPExportOffering]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &createdOffering))
	offeringID := createdOffering.Data.ID.String()

	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings/%s/items", upstreamSSP.UUID, offeringID),
		contributorToken, leverageOfferingItemBody(componentUUID, providedUUID))
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

	// The viewer role has ssp:read everywhere but no ssp:update and no
	// ssp-export-offering:subscribe — forbidden at the route guard before it even reaches
	// the handler's downstream ssp:update check.
	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		"/api/oscal/ssp-export-offerings/"+offeringID+"/subscribe", viewerToken, map[string]any{
			"downstreamSspId":        downstreamSSP.UUID,
			"leveragedAuthorization": map[string]string{"title": "Trust", "partyUuid": uuid.New().String()},
			"items":                  []map[string]any{{"itemId": createdItem.Data.ID.String(), "satisfiedResponsibilityUuids": []string{respUUID}}},
		})
	suite.Require().Equal(http.StatusForbidden, rec.Code, rec.Body.String())
}

// TestResponsibilityFilterFlipsPosture is BCH-1339's core integration scenario: a
// filter_responsibilities row targeting respB (the responsibility left outstanding by
// the subscribe in TestSubscribePartialThenProjection's style flow) drives live,
// evidence-backed posture on the Inherited Capability projection — independent of the
// subscribe-time satisfaction/outstandingResponsibilities fields (BCH-1338), and posture
// flips as newer evidence for the same stream changes status. respA, which has no filter
// targeting it, stays "unknown" throughout. The SSP-resolution half of AC #1 (matched
// filter → filter_responsibilities → ssp_leverage_links → downstream SSP) is covered
// against real Postgres by
// internal/service/worker's TestRiskEvidenceWorkerResponsibilityIntegrationSuite.
func (suite *SSPLeverageIntegrationSuite) TestResponsibilityFilterFlipsPosture() {
	suite.Require().NoError(suite.Migrator.Refresh())

	contributorToken := createRoledUser(&suite.IntegrationTestSuite, "posture-contributor@example.com", "contributor")
	subscriberToken := createRoledUser(&suite.IntegrationTestSuite, "posture-subscriber@example.com", "ssp-subscriber")

	server := newCedarServer(&suite.IntegrationTestSuite)

	upstreamComponentUUID := uuid.New().String()
	providedUUID := uuid.New().String()
	respAUUID := uuid.New().String()
	respBUUID := uuid.New().String()
	upstreamSSP := sspWithLeverageableCapability(upstreamComponentUUID, providedUUID, respAUUID, respBUUID)
	rec := authedRequest(&suite.IntegrationTestSuite, server, "POST", "/api/oscal/system-security-plans", contributorToken, upstreamSSP)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings", upstreamSSP.UUID),
		contributorToken, map[string]string{"title": "Offering"})
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
	itemID := createdItem.Data.ID.String()

	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		fmt.Sprintf("/api/oscal/system-security-plans/%s/export-offerings/%s/publish", upstreamSSP.UUID, offeringID),
		contributorToken, nil)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())

	downstreamSSP := minimalSSP(uuid.New().String())
	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST", "/api/oscal/system-security-plans", contributorToken, downstreamSSP)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	rec = authedRequest(&suite.IntegrationTestSuite, server, "POST",
		"/api/oscal/ssp-export-offerings/"+offeringID+"/subscribe", subscriberToken, map[string]any{
			"downstreamSspId":        downstreamSSP.UUID,
			"leveragedAuthorization": map[string]string{"title": "Trust in upstream provider", "partyUuid": uuid.New().String()},
			"items": []map[string]any{
				{"itemId": itemID, "satisfiedResponsibilityUuids": []string{respAUUID}},
			},
		})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	// A responsibility-targeting filter (BCH-1339) on respB, scoped to the downstream SSP.
	f := relational.Filter{
		Name: "respB-filter",
		Filter: datatypes.NewJSONType(labelfilter.Filter{
			Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "resp", Operator: "=", Value: "b"}},
		}),
	}
	suite.Require().NoError(suite.DB.Create(&f).Error)
	suite.Require().NoError(suite.DB.Create(&relational.FilterResponsibility{
		FilterID:           *f.ID,
		ResponsibilityUUID: uuid.MustParse(respBUUID),
		SSPID:              uuid.MustParse(downstreamSSP.UUID),
	}).Error)

	now := time.Now().UTC()
	streamUUID := uuid.New()
	submitEvidence := func(status string, end time.Time) {
		evID := uuid.New()
		suite.Require().NoError(suite.DB.Create(&relational.Evidence{
			UUIDModel: relational.UUIDModel{ID: &evID},
			UUID:      streamUUID,
			Title:     "resp-b-evidence",
			Start:     now, End: end, Expires: &end,
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: status, Reason: "auto"}),
		}).Error)
		suite.Require().NoError(suite.DB.Exec(
			"INSERT INTO labels (name, value) VALUES ('resp', 'b') ON CONFLICT DO NOTHING").Error)
		suite.Require().NoError(suite.DB.Exec(
			"INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, 'resp', 'b')", evID).Error)
	}

	fetchProjection := func() leveragedControlResponse {
		rec := authedRequest(&suite.IntegrationTestSuite, server, "GET",
			fmt.Sprintf("/api/oscal/system-security-plans/%s/leveraged-controls", downstreamSSP.UUID), contributorToken, nil)
		suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
		var projection handler.GenericDataListResponse[leveragedControlResponse]
		suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &projection))
		suite.Require().Len(projection.Data, 1)
		return projection.Data[0]
	}

	submitEvidence("not-satisfied", now)
	entry := fetchProjection()
	suite.Equal("not-satisfied", entry.ResponsibilityPosture[uuid.MustParse(respBUUID)])
	// respA was satisfied at subscribe time but has no filter targeting it, so its live
	// posture is "unknown" — independent of the subscribe-time attestation.
	suite.Equal("unknown", entry.ResponsibilityPosture[uuid.MustParse(respAUUID)])

	// Newer evidence for the same stream flips the posture.
	submitEvidence("satisfied", now.Add(time.Hour))
	entry = fetchProjection()
	suite.Equal("satisfied", entry.ResponsibilityPosture[uuid.MustParse(respBUUID)])
}
