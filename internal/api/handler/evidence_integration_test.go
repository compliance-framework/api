//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal"
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	svc "github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	sdktypes "github.com/compliance-framework/api/sdk/types"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"

	"github.com/compliance-framework/api/internal/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestEvidenceApi(t *testing.T) {
	suite.Run(t, new(EvidenceApiIntegrationSuite))
}

type EvidenceApiIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func (suite *EvidenceApiIntegrationSuite) setupServer() *api.Server {
	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	services := &APIServices{}
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	services.EvidenceService = evidenceSvc
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
	return server
}

func (suite *EvidenceApiIntegrationSuite) TestForControlWithScopedOutFiltersKeepsResponseShape() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	visibleSSPID := uuid.New()
	hiddenSSPID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &visibleSSPID}}).Error)
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &hiddenSSPID}}).Error)

	catalog := relational.Catalog{}
	suite.Require().NoError(suite.DB.Create(&catalog).Error)
	control := relational.Control{CatalogID: *catalog.ID, ID: "AC-1", Title: "Access Control 1"}
	filter := relational.Filter{
		Name:  "Hidden SSP Filter",
		SSPID: &hiddenSSPID,
		Filter: datatypes.NewJSONType(labelfilter.Filter{
			Scope: &labelfilter.Scope{
				Condition: &labelfilter.Condition{Label: "provider", Operator: "=", Value: "aws"},
			},
		}),
	}
	suite.Require().NoError(suite.DB.Create(&filter).Error)
	control.Filters = []relational.Filter{filter}
	suite.Require().NoError(suite.DB.Create(&control).Error)

	server := suite.setupServer()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/evidence/for-control/%s?sspId=%s", control.ID, visibleSSPID), nil)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var response map[string]any
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	metadata, ok := response["metadata"].(map[string]any)
	suite.Require().True(ok, rec.Body.String())
	controlMetadata, ok := metadata["control"].(map[string]any)
	suite.Require().True(ok, rec.Body.String())
	suite.Equal("AC-1", controlMetadata["id"])
	data, ok := response["data"].([]any)
	suite.Require().True(ok, rec.Body.String())
	suite.Empty(data)
}

// The per-control evidence badge (compliance-by-control) must count only global +
// same-SSP filters; a filter scoped to another plan is excluded. Without sspId it
// counts every SSP's filters — which is the bug the UI badge exhibited.
func (suite *EvidenceApiIntegrationSuite) TestComplianceByControlScopesToSSP() {
	suite.Require().NoError(suite.Migrator.Refresh())
	now := time.Now().Add(-time.Hour)

	sspA := uuid.New()
	sspB := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspA}}).Error)
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspB}}).Error)

	catalog := relational.Catalog{}
	suite.Require().NoError(suite.DB.Create(&catalog).Error)

	mkFilter := func(name, label string, sspID *uuid.UUID) relational.Filter {
		return relational.Filter{
			Name:  name,
			SSPID: sspID,
			Filter: datatypes.NewJSONType(labelfilter.Filter{
				Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: label, Operator: "=", Value: "1"}},
			}),
		}
	}
	globalF := mkFilter("global", "g", nil)
	aF := mkFilter("plan-a", "a", &sspA)
	bF := mkFilter("plan-b", "b", &sspB)
	suite.Require().NoError(suite.DB.Create(&globalF).Error)
	suite.Require().NoError(suite.DB.Create(&aF).Error)
	suite.Require().NoError(suite.DB.Create(&bF).Error)

	control := relational.Control{CatalogID: *catalog.ID, ID: "AC-1", Title: "Access Control 1"}
	control.Filters = []relational.Filter{globalF, aF, bF}
	suite.Require().NoError(suite.DB.Create(&control).Error)

	mkEvidence := func(label, state string) relational.Evidence {
		return relational.Evidence{
			UUID:   uuid.New(),
			Title:  label,
			Start:  now,
			End:    now.Add(time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: state}),
			Labels: []relational.Labels{{Name: label, Value: "1"}},
		}
	}
	evidence := []relational.Evidence{
		mkEvidence("g", "satisfied"),     // matches the global filter
		mkEvidence("a", "satisfied"),     // matches plan A's filter
		mkEvidence("b", "not-satisfied"), // matches plan B's filter
	}
	suite.Require().NoError(suite.DB.Create(&evidence).Error)

	server := suite.setupServer()
	countsFor := func(query string) map[string]int64 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/evidence/compliance-by-control/%s%s", control.ID, query), nil)
		server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
		var response struct {
			Data []struct {
				Count  int64  `json:"count"`
				Status string `json:"status"`
			} `json:"data"`
		}
		suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
		out := map[string]int64{}
		for _, s := range response.Data {
			out[s.Status] = s.Count
		}
		return out
	}

	// Scoped to plan A: global + A's evidence count; plan B's not-satisfied is excluded.
	scoped := countsFor("?sspId=" + sspA.String())
	suite.Equal(int64(2), scoped["satisfied"], "global + plan A")
	suite.Equal(int64(0), scoped["not-satisfied"], "plan B's filter must be scoped out")

	// No sspId: every plan's filter is counted — the leak the UI badge must avoid.
	unscoped := countsFor("")
	suite.Equal(int64(2), unscoped["satisfied"])
	suite.Equal(int64(1), unscoped["not-satisfied"])
}

func (suite *EvidenceApiIntegrationSuite) TestCreate() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	// Create two catalogs with the same group ID structure
	evidence := EvidenceCreateRequest{
		UUID:    uuid.New(),
		Title:   "Some piece of evidence",
		Start:   time.Now().Add(-time.Hour),
		End:     time.Now().Add(-time.Hour).Add(time.Minute),
		Expires: internal.Pointer(time.Now().Add(30 * 24 * time.Hour)),
		Labels: map[string]string{
			"provider": "aws",
			"service":  "EC2",
			"instance": "i-12345",
		},
		Activities: []EvidenceActivity{
			{
				UUID:  uuid.New(),
				Title: "Collect evidence",
				Steps: []EvidenceActivityStep{
					{
						UUID:  uuid.New(),
						Title: "Run CLI to collect configuration",
					},
					{
						UUID:  uuid.New(),
						Title: "Convert to JSON object",
					},
				},
			},
			{
				UUID:  uuid.New(),
				Title: "Evaluate compliance to policies",
				Steps: []EvidenceActivityStep{
					{
						UUID:  uuid.New(),
						Title: "Pass JSON configuration into policy engine",
					},
					{
						UUID:  uuid.New(),
						Title: "Evaluate policy and generate results",
					},
				},
			},
		},
		InventoryItems: []EvidenceInventoryItem{
			{
				Identifier: "web-server/ec2/i-12345",
				Type:       "web-server",
				Title:      "EC2 Instance - i-12345",
				Props:      nil,
				Links:      nil,
				ImplementedComponents: []struct {
					Identifier string
				}{
					{
						Identifier: "components/common/ssh",
					},
					{
						Identifier: "components/common/ubuntu-22",
					},
				},
			},
		},
		Components: []EvidenceComponent{
			{
				Identifier:  "components/common/ssh",
				Type:        "software",
				Title:       "Secure Shell (SSH)",
				Description: "SSH is used to manage remote access to virtual and hardware servers.",
				Protocols: []oscalTypes_1_1_3.Protocol{
					{
						UUID:  "3480C9EC-BC6B-4851-B248-BA78D83ECECE",
						Title: "SSH",
						Name:  "SSH",
						PortRanges: &[]oscalTypes_1_1_3.PortRange{
							{
								End:       22,
								Start:     22,
								Transport: "TCP",
							},
						},
					},
				},
			},
			{
				Identifier:  "components/common/ubuntu-22.04",
				Type:        "operating-system",
				Title:       "Ubuntu Server v22.04",
				Description: "Ubuntu is a free, open-source Linux distribution maintained by Canonical that pairs a user-friendly desktop and server experience with regular, predictable releases. It comes with extensive repositories, strong security defaults, and long-term support options that make it popular for personal use, cloud deployments, and enterprise environments.",
			},
			{
				Identifier:  "components/common/aws/ec2",
				Type:        "service",
				Title:       "Amazon Elastic Compute Cloud (EC2)",
				Description: "Amazon Elastic Compute Cloud (EC2) is a web service that lets you quickly provision resizable virtual servers in AWS’s global cloud, paying only for the compute you use. It offers a choice of instance types, networking and storage options, and automation features that allow everything from burst-scale web apps to enterprise workloads to run securely and on demand.",
			},
		},
		Subjects: []EvidenceSubject{
			{
				Identifier: "web-server/ec2/i-12345",
				Type:       "inventory-item",
			},
			{
				Identifier: "components/common/ssh",
				Type:       "component",
			},
			{
				Identifier: "components/common/aws/ec2",
				Type:       "component",
			},
		},
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			Reason:  "fail", // "pass" | "fail" | "other"
			Remarks: "Policy evaluation failed as password authentication is enabled. SSH password authentication should be disabled.",
			State:   "not-satisfied", // "satisfied" | "not-satisfied"
		},
	}

	server := suite.setupServer()
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(evidence)
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	var count int64
	// Counting users with specific names
	suite.DB.Model(&relational.Evidence{}).Count(&count)
	suite.Equal(int64(1), count)
}

// TestCreateFromSDKShapedJSON posts the wire format agents actually send
// (marshalled from sdk/types.Evidence, i.e. kebab-case keys) rather than the
// handler struct, so multi-word fields that fail to bind are caught.
func (suite *EvidenceApiIntegrationSuite) TestCreateFromSDKShapedJSON() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	evidence := sdktypes.Evidence{
		UUID:  uuid.New(),
		Title: "SDK-shaped evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		BackMatter: &oscalTypes_1_1_3.BackMatter{
			Resources: &[]oscalTypes_1_1_3.Resource{
				{UUID: uuid.NewString(), Title: "Raw scan output"},
			},
		},
		InventoryItems: []sdktypes.InventoryItem{
			{
				Identifier:  "web-server/ec2/i-12345",
				Type:        "web-server",
				Title:       "EC2 Instance - i-12345",
				Description: "Web server under test",
				ImplementedComponents: []sdktypes.ComponentIdentifier{
					{Identifier: "components/common/ssh"},
					{Identifier: "components/common/ubuntu-22"},
					{Identifier: "components/common/ssh"}, // repeated: must be collapsed, not rejected
				},
			},
		},
		Components: []sdktypes.Component{
			{Identifier: "components/common/ssh", Type: "software", Title: "Secure Shell (SSH)"},
		},
		Status: sdktypes.ObjectiveStatus{State: relational.EvidenceStatusSatisfied},
	}

	reqBody, err := json.Marshal(evidence)
	suite.Require().NoError(err)
	suite.Require().Contains(string(reqBody), `"inventory-items"`)
	suite.Require().Contains(string(reqBody), `"implemented-components"`)

	server := suite.setupServer()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	itemID, err := internal.SeededUUID(map[string]string{"identifier": "web-server/ec2/i-12345"})
	suite.Require().NoError(err)
	sshID, err := internal.SeededUUID(map[string]string{"identifier": "components/common/ssh"})
	suite.Require().NoError(err)
	ubuntuID, err := internal.SeededUUID(map[string]string{"identifier": "components/common/ubuntu-22"})
	suite.Require().NoError(err)

	// Stored: the inventory item is linked to the evidence with both implemented components.
	var stored relational.Evidence
	suite.Require().NoError(suite.DB.
		Preload("InventoryItems.ImplementedComponents").
		First(&stored, "uuid = ?", evidence.UUID).Error)
	suite.Require().Len(stored.InventoryItems, 1)
	suite.Equal(itemID, *stored.InventoryItems[0].ID)
	suite.Equal("Web server under test", stored.InventoryItems[0].Description)
	storedComponentIDs := []uuid.UUID{}
	for _, ic := range stored.InventoryItems[0].ImplementedComponents {
		storedComponentIDs = append(storedComponentIDs, ic.ComponentID)
	}
	suite.ElementsMatch([]uuid.UUID{sshID, ubuntuID}, storedComponentIDs)

	// Returned: GET exposes the inventory item, its implemented components and the back-matter.
	getRec := httptest.NewRecorder()
	getReq := httptest.NewRequest(http.MethodGet, "/api/evidence/"+stored.ID.String(), nil)
	server.E().ServeHTTP(getRec, getReq)
	suite.Require().Equal(http.StatusOK, getRec.Code, getRec.Body.String())

	var getResp GenericDataResponse[PublicEvidenceResponse]
	suite.Require().NoError(json.Unmarshal(getRec.Body.Bytes(), &getResp))
	suite.Require().Len(getResp.Data.InventoryItems, 1)
	returned := getResp.Data.InventoryItems[0]
	suite.Equal(itemID.String(), returned.UUID)
	suite.Require().NotNil(returned.ImplementedComponents)
	returnedComponentIDs := []string{}
	for _, ic := range *returned.ImplementedComponents {
		returnedComponentIDs = append(returnedComponentIDs, ic.ComponentUuid)
	}
	suite.ElementsMatch([]string{sshID.String(), ubuntuID.String()}, returnedComponentIDs)

	suite.Require().NotNil(getResp.Data.BackMatter)
	suite.Require().NotNil(getResp.Data.BackMatter.Resources)
	suite.Require().Len(*getResp.Data.BackMatter.Resources, 1)
	suite.Equal("Raw scan output", (*getResp.Data.BackMatter.Resources)[0].Title)

	// Resubmitting the same stream (as agents do every cycle) must not duplicate
	// the inventory item or its implemented-component links.
	evidence.Start = time.Now().Add(-30 * time.Minute)
	evidence.End = time.Now().Add(-time.Second)
	reqBody, err = json.Marshal(evidence)
	suite.Require().NoError(err)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	var itemCount, linkCount int64
	suite.Require().NoError(suite.DB.Model(&relational.InventoryItem{}).Count(&itemCount).Error)
	suite.Require().NoError(suite.DB.Model(&relational.ImplementedComponent{}).Count(&linkCount).Error)
	suite.Equal(int64(1), itemCount)
	suite.Equal(int64(2), linkCount)
}

// TestSharedInventoryItemLinksDoNotInvalidateSignatures covers inventory items
// shared across evidence records. Later submissions update the shared item, but
// each record signs, verifies and returns its own snapshot of what it reported.
func (suite *EvidenceApiIntegrationSuite) TestSharedInventoryItemLinksDoNotInvalidateSignatures() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	post := func(description, component string) string {
		reqBody, err := json.Marshal(sdktypes.Evidence{
			UUID:  uuid.New(),
			Title: "Host scan via " + component,
			Start: time.Now().Add(-time.Hour),
			End:   time.Now().Add(-time.Minute),
			InventoryItems: []sdktypes.InventoryItem{{
				Identifier:            "web-server/ec2/i-1",
				Description:           description,
				ImplementedComponents: []sdktypes.ComponentIdentifier{{Identifier: component}},
			}},
			Status: sdktypes.ObjectiveStatus{State: relational.EvidenceStatusSatisfied},
		})
		suite.Require().NoError(err)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
		server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
		var resp GenericDataResponse[CreatedEvidenceResponse]
		suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
		suite.Require().NotNil(resp.Data.Signature, "user-authenticated evidence must be signed")
		return resp.Data.ID.String()
	}
	verify := func(id string) evidencesvc.VerificationResult {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/evidence/"+id+"/verify", nil)
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
		server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
		var resp GenericDataResponse[evidencesvc.VerificationResult]
		suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp.Data
	}
	reported := func(id string) oscalTypes_1_1_3.InventoryItem {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/evidence/"+id, nil)
		server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
		var getResp GenericDataResponse[PublicEvidenceResponse]
		suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &getResp))
		suite.Require().Len(getResp.Data.InventoryItems, 1)
		return getResp.Data.InventoryItems[0]
	}
	componentIDs := func(item oscalTypes_1_1_3.InventoryItem) []string {
		suite.Require().NotNil(item.ImplementedComponents)
		ids := []string{}
		for _, ic := range *item.ImplementedComponents {
			ids = append(ids, ic.ComponentUuid)
		}
		return ids
	}
	sshID, err := internal.SeededUUID(map[string]string{"identifier": "components/common/ssh"})
	suite.Require().NoError(err)
	ubuntuID, err := internal.SeededUUID(map[string]string{"identifier": "components/common/ubuntu-22"})
	suite.Require().NoError(err)

	evidenceA := post("Web server", "components/common/ssh")
	suite.Require().True(verify(evidenceA).IsValid)

	// Another stream reports the same host with a different description and component.
	evidenceB := post("Web server, patched", "components/common/ubuntu-22")

	resultA := verify(evidenceA)
	suite.True(resultA.IsValid, "a later submission for a shared host must not invalidate A: %v", resultA.Errors)
	resultB := verify(evidenceB)
	suite.True(resultB.IsValid, "B must verify: %v", resultB.Errors)

	// Each record returns what it reported.
	itemA := reported(evidenceA)
	suite.Equal("Web server", itemA.Description)
	suite.ElementsMatch([]string{sshID.String()}, componentIDs(itemA))
	itemB := reported(evidenceB)
	suite.Equal("Web server, patched", itemB.Description)
	suite.ElementsMatch([]string{ubuntuID.String()}, componentIDs(itemB))

	// The shared item is the current asset record: latest description, all links seen.
	itemID, err := internal.SeededUUID(map[string]string{"identifier": "web-server/ec2/i-1"})
	suite.Require().NoError(err)
	var shared relational.InventoryItem
	suite.Require().NoError(suite.DB.Preload("ImplementedComponents").First(&shared, "id = ?", itemID).Error)
	suite.Equal("Web server, patched", shared.Description)
	suite.Len(shared.ImplementedComponents, 2)
}

// TestInventoryItemWithoutSnapshotStillVerifies covers evidence signed before
// inventory item versions existed. Until the migration backfills it, it is
// signed and returned from the shared item, with implemented-component links
// unsigned. After the backfill it keeps verifying when the shared item changes.
func (suite *EvidenceApiIntegrationSuite) TestInventoryItemWithoutSnapshotStillVerifies() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	itemID, err := internal.SeededUUID(map[string]string{"identifier": "web-server/ec2/i-legacy"})
	suite.Require().NoError(err)
	sshID, err := internal.SeededUUID(map[string]string{"identifier": "components/common/ssh"})
	suite.Require().NoError(err)
	ubuntuID, err := internal.SeededUUID(map[string]string{"identifier": "components/common/ubuntu-22"})
	suite.Require().NoError(err)

	// Sign legacy evidence the way the service did before snapshots: from the
	// shared item without its links.
	item := relational.InventoryItem{
		UUIDModel:             relational.UUIDModel{ID: &itemID},
		Description:           "Legacy host",
		ImplementedComponents: []relational.ImplementedComponent{{ComponentID: sshID}},
	}
	suite.Require().NoError(suite.DB.Create(&item).Error)
	evidence := relational.Evidence{
		UUID:           uuid.New(),
		Title:          "Legacy evidence",
		Start:          time.Now().Add(-time.Hour).UTC(),
		End:            time.Now().Add(-time.Minute).UTC(),
		Status:         datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: relational.EvidenceStatusSatisfied}),
		InventoryItems: []relational.InventoryItem{item},
	}
	suite.Require().NoError(suite.DB.Omit("InventoryItems.*").Create(&evidence).Error)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, nil, suite.Config, nil)
	persisted, err := evidenceSvc.GetByID(*evidence.ID)
	suite.Require().NoError(err)
	suite.Require().Empty(persisted.InventorySnapshots)
	signer := evidencesvc.NewUserSignerContextFromClaims(&authn.UserClaims{})
	signer.User.Claims.Subject = "legacy@example.com"
	signature, err := evidencesvc.NewSigningService(suite.Config.JWTPrivateKey).SignEvidence(evidencesvc.CreateEvidenceParams{
		Evidence:       *persisted,
		InventoryItems: persisted.InventoryItems,
	}, signer)
	suite.Require().NoError(err)
	suite.Require().NoError(suite.DB.Model(&evidence).Update("signature", signature).Error)

	// A later link on the shared item does not invalidate it.
	suite.Require().NoError(suite.DB.Create(&relational.ImplementedComponent{InventoryItemId: itemID, ComponentID: ubuntuID}).Error)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/evidence/"+evidence.ID.String()+"/verify", nil)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var verifyResp GenericDataResponse[evidencesvc.VerificationResult]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &verifyResp))
	suite.True(verifyResp.Data.IsValid, "legacy evidence must still verify: %v", verifyResp.Data.Errors)

	// GET falls back to the shared item.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/evidence/"+evidence.ID.String(), nil)
	server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var getResp GenericDataResponse[PublicEvidenceResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &getResp))
	suite.Require().Len(getResp.Data.InventoryItems, 1)
	suite.Equal("Legacy host", getResp.Data.InventoryItems[0].Description)
	suite.Require().NotNil(getResp.Data.InventoryItems[0].ImplementedComponents)
	suite.Len(*getResp.Data.InventoryItems[0].ImplementedComponents, 2)

	// The migration pins the legacy row to a version of what it signed. Running
	// it twice is a no-op.
	suite.Require().NoError(svc.MigrateUp(suite.DB))
	suite.Require().NoError(svc.MigrateUp(suite.DB))
	var link relational.EvidenceInventoryItem
	suite.Require().NoError(suite.DB.First(&link, "evidence_id = ?", *evidence.ID).Error)
	suite.Require().NotNil(link.InventoryItemVersionHash)
	var versionCount int64
	suite.Require().NoError(suite.DB.Model(&relational.InventoryItemVersion{}).Count(&versionCount).Error)
	suite.Equal(int64(1), versionCount)

	// Now a later submission can change the shared item without invalidating it.
	reqBody, err := json.Marshal(sdktypes.Evidence{
		UUID:  uuid.New(),
		Title: "Newer scan",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		InventoryItems: []sdktypes.InventoryItem{{
			Identifier:  "web-server/ec2/i-legacy",
			Description: "Rebuilt host",
		}},
		Status: sdktypes.ObjectiveStatus{State: relational.EvidenceStatusSatisfied},
	})
	suite.Require().NoError(err)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/evidence/"+evidence.ID.String()+"/verify", nil)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	verifyResp = GenericDataResponse[evidencesvc.VerificationResult]{}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &verifyResp))
	suite.True(verifyResp.Data.IsValid, "backfilled evidence must survive a shared item change: %v", verifyResp.Data.Errors)

	// GET returns what it signed: the old description and no links.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/evidence/"+evidence.ID.String(), nil)
	server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	getResp = GenericDataResponse[PublicEvidenceResponse]{}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &getResp))
	suite.Require().Len(getResp.Data.InventoryItems, 1)
	suite.Equal("Legacy host", getResp.Data.InventoryItems[0].Description)
	suite.Nil(getResp.Data.InventoryItems[0].ImplementedComponents)
}

// TestInventoryItemTypeAndUpsert checks the reported type is kept as an
// asset-type prop, that resubmitting an item updates the shared row, and that
// only distinct reported states are stored as versions.
func (suite *EvidenceApiIntegrationSuite) TestInventoryItemTypeAndUpsert() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	post := func(description string) {
		reqBody, err := json.Marshal(sdktypes.Evidence{
			UUID:  uuid.New(),
			Title: "Host scan",
			Start: time.Now().Add(-time.Hour),
			End:   time.Now().Add(-time.Minute),
			InventoryItems: []sdktypes.InventoryItem{{
				Identifier:  "web-server/ec2/i-2",
				Type:        "web-server",
				Description: description,
			}},
			Status: sdktypes.ObjectiveStatus{State: relational.EvidenceStatusSatisfied},
		})
		suite.Require().NoError(err)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	}

	itemID, err := internal.SeededUUID(map[string]string{"identifier": "web-server/ec2/i-2"})
	suite.Require().NoError(err)

	post("Before")
	var item relational.InventoryItem
	suite.Require().NoError(suite.DB.First(&item, "id = ?", itemID).Error)
	suite.Equal("Before", item.Description)
	suite.Contains(item.Props, relational.Prop{Name: "asset-type", Value: "web-server"})

	// Reporting the item unchanged reuses its version.
	post("Before")
	var versionCount int64
	suite.Require().NoError(suite.DB.Model(&relational.InventoryItemVersion{}).Count(&versionCount).Error)
	suite.Equal(int64(1), versionCount)

	post("After")
	suite.Require().NoError(suite.DB.Model(&relational.InventoryItemVersion{}).Count(&versionCount).Error)
	suite.Equal(int64(2), versionCount)
	var unversioned int64
	suite.Require().NoError(suite.DB.Model(&relational.EvidenceInventoryItem{}).
		Where("inventory_item_version_hash IS NULL").Count(&unversioned).Error)
	suite.Zero(unversioned)

	item = relational.InventoryItem{}
	suite.Require().NoError(suite.DB.First(&item, "id = ?", itemID).Error)
	suite.Equal("After", item.Description)
	suite.Contains(item.Props, relational.Prop{Name: "asset-type", Value: "web-server"})

	var itemCount int64
	suite.Require().NoError(suite.DB.Model(&relational.InventoryItem{}).Count(&itemCount).Error)
	suite.Equal(int64(1), itemCount)
}

// TestCreatePersistsSubObjectPropsAndLinks captures the overwritten props/links bug
// (CCF Evidence Subjects and Playback design §3, §10.2.1).
//
// Observed: components, inventory items, activities, steps and subjects were all
// persisted with the evidence-level props/links instead of their own, so plugin-supplied
// sub-object links (e.g. a subject's canonical URL) were lost.
// Expected: each sub-object persists its own props/links, independent of the evidence.
func (suite *EvidenceApiIntegrationSuite) TestCreatePersistsSubObjectPropsAndLinks() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	propsFor := func(owner string) []oscalTypes_1_1_3.Property {
		return []oscalTypes_1_1_3.Property{{Name: "owner", Value: owner}}
	}
	linksFor := func(owner string) []oscalTypes_1_1_3.Link {
		return []oscalTypes_1_1_3.Link{{Href: "https://example.com/" + owner, Rel: "canonical"}}
	}

	activityID := uuid.New()
	stepID := uuid.New()
	evidence := EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Evidence with distinct sub-object props and links",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Hour).Add(time.Minute),
		Props: propsFor("evidence"),
		Links: linksFor("evidence"),
		Activities: []EvidenceActivity{
			{
				UUID:  activityID,
				Title: "Collect evidence",
				Props: propsFor("activity"),
				Links: linksFor("activity"),
				Steps: []EvidenceActivityStep{
					{
						UUID:  stepID,
						Title: "Run CLI to collect configuration",
						Props: propsFor("step"),
						Links: linksFor("step"),
					},
				},
			},
		},
		InventoryItems: []EvidenceInventoryItem{
			{
				Identifier: "web-server/ec2/i-props-links",
				Type:       "web-server",
				Title:      "EC2 Instance",
				Props:      propsFor("inventory-item"),
				Links:      linksFor("inventory-item"),
			},
		},
		Components: []EvidenceComponent{
			{
				Identifier: "components/common/props-links",
				Type:       "software",
				Title:      "Component",
				Props:      propsFor("component"),
				Links:      linksFor("component"),
			},
		},
		Subjects: []EvidenceSubject{
			{
				Identifier: "components/common/props-links",
				Type:       "component",
				Props:      propsFor("subject"),
				Links:      linksFor("subject"),
			},
		},
		Status: oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"},
	}

	server := suite.setupServer()
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(evidence)
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	var persisted relational.Evidence
	suite.Require().NoError(suite.DB.
		Preload("Components").
		Preload("InventoryItems").
		Preload("Activities.Steps").
		Preload("Subjects").
		First(&persisted, "uuid = ?", evidence.UUID).Error)

	assertOwn := func(owner string, props datatypes.JSONSlice[relational.Prop], links datatypes.JSONSlice[relational.Link]) {
		suite.Equal(propsFor(owner), *relational.ConvertPropsToOscal(props), "%s props", owner)
		suite.Equal(linksFor(owner), *relational.ConvertLinksToOscal(links), "%s links", owner)
	}

	assertOwn("evidence", persisted.Props, persisted.Links)

	suite.Require().Len(persisted.Components, 1)
	assertOwn("component", persisted.Components[0].Props, persisted.Components[0].Links)

	suite.Require().Len(persisted.InventoryItems, 1)
	assertOwn("inventory-item", persisted.InventoryItems[0].Props, persisted.InventoryItems[0].Links)

	suite.Require().Len(persisted.Activities, 1)
	assertOwn("activity", persisted.Activities[0].Props, persisted.Activities[0].Links)

	suite.Require().Len(persisted.Activities[0].Steps, 1)
	assertOwn("step", persisted.Activities[0].Steps[0].Props, persisted.Activities[0].Steps[0].Links)

	suite.Require().Len(persisted.Subjects, 1)
	assertOwn("subject", persisted.Subjects[0].Props, persisted.Subjects[0].Links)
}

func (suite *EvidenceApiIntegrationSuite) TestCreateRequiresAgentAuthWhenUnsafeDisabled() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = true

	server := suite.setupServer()
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusUnauthorized, rec.Code)
}

func (suite *EvidenceApiIntegrationSuite) TestCreateWithAgentTokenWhenUnsafeDisabled() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = true

	server := suite.setupServer()
	agent, err := suite.CreateAgent("evidence-agent")
	suite.Require().NoError(err)
	key, _, err := suite.CreateAgentKey(agent, "evidence-key")
	suite.Require().NoError(err)
	token, err := suite.GetAgentToken(agent, key)
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	suite.Require().NotNil(evidence.Signature)
	suite.Equal(relational.AgentAuthMethodServiceAccount, evidence.Signature.Data().Claims.AuthMethod)
}

func (suite *EvidenceApiIntegrationSuite) TestCreateRejectsExpiredAgentKeyWhenUnsafeDisabled() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = true

	server := suite.setupServer()
	agent, err := suite.CreateAgent("expired-evidence-agent")
	suite.Require().NoError(err)
	key, _, err := suite.CreateAgentKey(agent, "expired-evidence-key")
	suite.Require().NoError(err)
	expiresAt := time.Now().UTC().Add(-time.Minute)
	key.ExpiresAt = &expiresAt
	suite.Require().NoError(suite.DB.Save(key).Error)
	token, err := suite.GetAgentToken(agent, key)
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusForbidden, rec.Code)
}

func (suite *EvidenceApiIntegrationSuite) TestCreateWithUserTokenSignsEvidenceAndReturnsSignature() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Signed Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	suite.Require().NotNil(evidence.Signature)
	suite.Equal("dummy@example.com", evidence.Signature.Data().Claims.Subject)

	var response map[string]any
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	data, ok := response["data"].(map[string]any)
	suite.Require().True(ok)
	suite.NotNil(data["signature"])
}

func (suite *EvidenceApiIntegrationSuite) TestCreatePublicLeavesEvidenceUnsigned() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Unsigned Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	suite.Nil(evidence.Signature)
}

func (suite *EvidenceApiIntegrationSuite) TestCreatePublicIgnoresInvalidUserCookie() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Unsigned Evidence With Invalid Cookie",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.AddCookie(&http.Cookie{
		Name:  "ccf_auth_token",
		Value: "invalid-token",
	})
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	suite.Nil(evidence.Signature)
}

func (suite *EvidenceApiIntegrationSuite) TestSignatureEndpointsRequireUserAuth() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	createRec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Signed Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	createReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	createReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)

	signatureReq := httptest.NewRequest(http.MethodGet, "/api/evidence/"+evidence.ID.String()+"/signature", nil)
	signatureRec := httptest.NewRecorder()
	server.E().ServeHTTP(signatureRec, signatureReq)
	suite.Equal(http.StatusUnauthorized, signatureRec.Code)

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/evidence/"+evidence.ID.String()+"/verify", nil)
	verifyRec := httptest.NewRecorder()
	server.E().ServeHTTP(verifyRec, verifyReq)
	suite.Equal(http.StatusUnauthorized, verifyRec.Code)
}

func (suite *EvidenceApiIntegrationSuite) TestSignatureEndpointsWithUserAuth() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	createRec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Signed Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		},
		Props: []oscalTypes_1_1_3.Property{{Name: "check", Value: "baseline"}},
		Labels: map[string]string{
			"env": "prod",
		},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	createReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	createReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)

	signatureReq := httptest.NewRequest(http.MethodGet, "/api/evidence/"+evidence.ID.String()+"/signature", nil)
	signatureReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	signatureRec := httptest.NewRecorder()
	server.E().ServeHTTP(signatureRec, signatureReq)
	suite.Equal(http.StatusOK, signatureRec.Code)

	var signatureResp EvidenceSignatureResponse
	suite.Require().NoError(json.Unmarshal(signatureRec.Body.Bytes(), &signatureResp))
	suite.Require().NotNil(signatureResp.Data)
	suite.Equal(evidencesvc.SignatureStatusSigned, signatureResp.Data.Status)
	suite.Require().NotNil(signatureResp.Data.Signature)
	suite.NotEmpty(signatureResp.Data.Signature.JWS)
	suite.Equal("dummy@example.com", signatureResp.Data.Signature.Claims.Subject)

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/evidence/"+evidence.ID.String()+"/verify", nil)
	verifyReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	verifyRec := httptest.NewRecorder()
	server.E().ServeHTTP(verifyRec, verifyReq)
	suite.Equal(http.StatusOK, verifyRec.Code)

	var verifyResp EvidenceSignatureVerificationResponse
	suite.Require().NoError(json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp))
	suite.Require().NotNil(verifyResp.Data)
	suite.Equal(evidencesvc.SignatureStatusSigned, verifyResp.Data.Status)
	suite.Require().NotNil(verifyResp.Data.Signature)
	suite.True(verifyResp.Data.IsValid)

	suite.Require().NoError(
		suite.DB.Model(&relational.Evidence{}).
			Where("id = ?", evidence.ID).
			Update("status", datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: relational.EvidenceStatusNotSatisfied})).Error,
	)

	verifyReq = httptest.NewRequest(http.MethodPost, "/api/evidence/"+evidence.ID.String()+"/verify", nil)
	verifyReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	verifyRec = httptest.NewRecorder()
	server.E().ServeHTTP(verifyRec, verifyReq)
	suite.Equal(http.StatusOK, verifyRec.Code)

	suite.Require().NoError(json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp))
	suite.Require().NotNil(verifyResp.Data)
	suite.False(verifyResp.Data.IsValid)
	suite.False(verifyResp.Data.Checks.HashMatch)
	suite.False(verifyResp.Data.Checks.SignedContentMatches)
}

func (suite *EvidenceApiIntegrationSuite) TestPublicEvidenceReadsDoNotExposeSignature() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	createRec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Signed Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	createReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	createReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	suite.Require().NotNil(evidence.Signature)

	getReq := httptest.NewRequest(http.MethodGet, "/api/evidence/"+evidence.ID.String(), nil)
	getRec := httptest.NewRecorder()
	server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusOK, getRec.Code)

	var getResp map[string]any
	suite.Require().NoError(json.Unmarshal(getRec.Body.Bytes(), &getResp))
	getData, ok := getResp["data"].(map[string]any)
	suite.Require().True(ok)
	suite.NotContains(getData, "signature")

	historyReq := httptest.NewRequest(http.MethodGet, "/api/evidence/history/"+evidence.UUID.String(), nil)
	historyRec := httptest.NewRecorder()
	server.E().ServeHTTP(historyRec, historyReq)
	suite.Equal(http.StatusOK, historyRec.Code)

	var historyResp map[string]any
	suite.Require().NoError(json.Unmarshal(historyRec.Body.Bytes(), &historyResp))
	historyData, ok := historyResp["data"].([]any)
	suite.Require().True(ok)
	suite.Require().Len(historyData, 1)
	firstItem, ok := historyData[0].(map[string]any)
	suite.Require().True(ok)
	suite.NotContains(firstItem, "signature")
}

func (suite *EvidenceApiIntegrationSuite) TestVerifyUnsignedEvidenceReturnsFailureResult() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	userToken, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	createRec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Unsigned Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	createReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/evidence/"+evidence.ID.String()+"/verify", nil)
	verifyReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *userToken))
	verifyRec := httptest.NewRecorder()
	server.E().ServeHTTP(verifyRec, verifyReq)
	suite.Equal(http.StatusOK, verifyRec.Code)

	var verifyResp EvidenceSignatureVerificationResponse
	suite.Require().NoError(json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp))
	suite.Require().NotNil(verifyResp.Data)
	suite.Equal(evidencesvc.SignatureStatusUnsigned, verifyResp.Data.Status)
	suite.Nil(verifyResp.Data.Signature)
	suite.False(verifyResp.Data.IsValid)
	suite.Empty(verifyResp.Data.Errors)

	signatureReq := httptest.NewRequest(http.MethodGet, "/api/evidence/"+evidence.ID.String()+"/signature", nil)
	signatureReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *userToken))
	signatureRec := httptest.NewRecorder()
	server.E().ServeHTTP(signatureRec, signatureReq)
	suite.Equal(http.StatusOK, signatureRec.Code)

	var signatureResp EvidenceSignatureResponse
	suite.Require().NoError(json.Unmarshal(signatureRec.Body.Bytes(), &signatureResp))
	suite.Require().NotNil(signatureResp.Data)
	suite.Equal(evidencesvc.SignatureStatusUnsigned, signatureResp.Data.Status)
	suite.Nil(signatureResp.Data.Signature)
}

func (suite *EvidenceApiIntegrationSuite) TestVerifyAgentCreatedEvidenceWithUserAuth() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = true

	server := suite.setupServer()
	userToken, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	agent, err := suite.CreateAgent("verify-agent")
	suite.Require().NoError(err)
	key, _, err := suite.CreateAgentKey(agent, "verify-key")
	suite.Require().NoError(err)
	agentToken, err := suite.GetAgentToken(agent, key)
	suite.Require().NoError(err)

	createRec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Agent Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	createReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	createReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *agentToken))
	server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/evidence/"+evidence.ID.String()+"/verify", nil)
	verifyReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *userToken))
	verifyRec := httptest.NewRecorder()
	server.E().ServeHTTP(verifyRec, verifyReq)
	suite.Equal(http.StatusOK, verifyRec.Code)

	var verifyResp EvidenceSignatureVerificationResponse
	suite.Require().NoError(json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp))
	suite.Require().NotNil(verifyResp.Data)
	suite.Equal(evidencesvc.SignatureStatusSigned, verifyResp.Data.Status)
	suite.Require().NotNil(verifyResp.Data.Signature)
	suite.True(verifyResp.Data.IsValid)
	suite.Equal(authn.TokenKindAgent, verifyResp.Data.Signer.Type)
}

func (suite *EvidenceApiIntegrationSuite) TestSignatureEndpointsReturnNotFoundForMissingEvidence() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := suite.setupServer()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	missingID := uuid.New()

	signatureReq := httptest.NewRequest(http.MethodGet, "/api/evidence/"+missingID.String()+"/signature", nil)
	signatureReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	signatureRec := httptest.NewRecorder()
	server.E().ServeHTTP(signatureRec, signatureReq)
	suite.Equal(http.StatusNotFound, signatureRec.Code)

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/evidence/"+missingID.String()+"/verify", nil)
	verifyReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	verifyRec := httptest.NewRecorder()
	server.E().ServeHTTP(verifyRec, verifyReq)
	suite.Equal(http.StatusNotFound, verifyRec.Code)
}

func (suite *EvidenceApiIntegrationSuite) TestSearch() {
	suite.Run("Returns the single latest evidence for a stream", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		stream := uuid.New()

		// Create two catalogs with the same group ID structure
		evidence := []relational.Evidence{
			{
				UUID:  stream,
				Title: "New",
				Start: time.Now().Add(-time.Hour),
				End:   time.Now().Add(-time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
				},
			},
			{
				UUID:  stream,
				Title: "Old",
				Start: time.Now().Add(-2 * time.Hour),
				End:   time.Now().Add(-2 * time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
				},
			},
		}
		suite.NoError(suite.DB.Create(&evidence).Error)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(struct {
			Filter labelfilter.Filter
		}{})
		req := httptest.NewRequest(http.MethodPost, "/api/evidence/search", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		response := &svc.ListResponse[PublicEvidenceResponse]{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err)

		suite.Len(response.Data, 1)
	})

	suite.Run("Returns the single latest evidence for two streams", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Create two catalogs with the same group ID structure
		evidence := []relational.Evidence{
			{
				UUID:  uuid.New(),
				Title: "New",
				Start: time.Now().Add(-time.Hour),
				End:   time.Now().Add(-time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
				},
			},
			{
				UUID:  uuid.New(),
				Title: "Old",
				Start: time.Now().Add(-2 * time.Hour),
				End:   time.Now().Add(-2 * time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
				},
			},
		}
		suite.NoError(suite.DB.Create(&evidence).Error)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(struct {
			Filter labelfilter.Filter
		}{})
		req := httptest.NewRequest(http.MethodPost, "/api/evidence/search", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		response := &svc.ListResponse[PublicEvidenceResponse]{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err)

		suite.Len(response.Data, 2)
	})

	suite.Run("Can filter streams - simple", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Create two catalogs with the same group ID structure
		evidence := []relational.Evidence{
			{
				UUID:  uuid.New(),
				Title: "New",
				Start: time.Now().Add(-time.Hour),
				End:   time.Now().Add(-time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
				},
			},
			{
				UUID:  uuid.New(),
				Title: "Old",
				Start: time.Now().Add(-2 * time.Hour),
				End:   time.Now().Add(-2 * time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "Github",
					},
				},
			},
		}
		suite.NoError(suite.DB.Create(&evidence).Error)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		var reqBody, _ = json.Marshal(struct {
			Filter labelfilter.Filter
		}{
			Filter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "provider",
						Operator: "=",
						Value:    "aws",
					},
				},
			},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/evidence/search", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		response := &svc.ListResponse[PublicEvidenceResponse]{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err)

		suite.Len(response.Data, 1)
		suite.Equal(response.Data[0].Title, "New")
	})

	suite.Run("Can filter streams - negation", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Create two catalogs with the same group ID structure
		evidence := []relational.Evidence{
			{
				UUID:  uuid.New(),
				Title: "AWS",
				Start: time.Now().Add(-time.Hour),
				End:   time.Now().Add(-time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
				},
			},
			{
				UUID:  uuid.New(),
				Title: "Github",
				Start: time.Now().Add(-2 * time.Hour),
				End:   time.Now().Add(-2 * time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "Github",
					},
				},
			},
		}
		suite.NoError(suite.DB.Create(&evidence).Error)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		var reqBody, _ = json.Marshal(struct {
			Filter labelfilter.Filter
		}{
			Filter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "provider",
						Operator: "!=",
						Value:    "aws",
					},
				},
			},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/evidence/search", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		response := &svc.ListResponse[PublicEvidenceResponse]{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err)

		suite.Len(response.Data, 1)
		suite.Equal("Github", response.Data[0].Title)
	})

	suite.Run("Can filter streams - complex subquery", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Create two catalogs with the same group ID structure
		evidence := []relational.Evidence{
			{
				UUID:  uuid.New(),
				Title: "AWS-1",
				Start: time.Now().Add(-time.Hour),
				End:   time.Now().Add(-time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
					{
						Name:  "instance",
						Value: "i-1",
					},
				},
			},
			{
				UUID:  uuid.New(),
				Title: "AWS-2",
				Start: time.Now().Add(-time.Hour),
				End:   time.Now().Add(-time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
					{
						Name:  "instance",
						Value: "i-2",
					},
				},
			},
		}
		suite.NoError(suite.DB.Create(&evidence).Error)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		var reqBody, _ = json.Marshal(struct {
			Filter labelfilter.Filter
		}{
			Filter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Query: &labelfilter.Query{
						Operator: "and",
						Scopes: []labelfilter.Scope{
							{
								Condition: &labelfilter.Condition{
									Label:    "provider",
									Operator: "=",
									Value:    "aws",
								},
							},
							{
								Query: &labelfilter.Query{
									Operator: "or",
									Scopes: []labelfilter.Scope{
										{
											Condition: &labelfilter.Condition{
												Label:    "instance",
												Operator: "=",
												Value:    "i-1",
											},
										},
										{
											Condition: &labelfilter.Condition{
												Label:    "instance",
												Operator: "=",
												Value:    "i-3",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/evidence/search", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		response := &svc.ListResponse[PublicEvidenceResponse]{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err)

		suite.Len(response.Data, 1)
		suite.Equal(response.Data[0].Title, "AWS-1")
	})
}

func (suite *EvidenceApiIntegrationSuite) TestHistoryPagination() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	streamUUID := uuid.New()
	now := time.Now().UTC()
	evidences := []relational.Evidence{
		{
			UUID:  streamUUID,
			Title: "Newest",
			Start: now.Add(-2 * time.Minute),
			End:   now.Add(-1 * time.Minute),
		},
		{
			UUID:  streamUUID,
			Title: "Middle",
			Start: now.Add(-12 * time.Minute),
			End:   now.Add(-10 * time.Minute),
		},
		{
			UUID:  streamUUID,
			Title: "Oldest",
			Start: now.Add(-22 * time.Minute),
			End:   now.Add(-20 * time.Minute),
		},
	}
	suite.Require().NoError(suite.DB.Create(&evidences).Error)

	server := suite.setupServer()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/evidence/history/"+streamUUID.String()+"?page=1&limit=2", nil)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	var response struct {
		Data       []PublicEvidenceResponse `json:"data"`
		Total      int64                    `json:"total"`
		Page       int                      `json:"page"`
		Limit      int                      `json:"limit"`
		TotalPages int                      `json:"totalPages"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Len(response.Data, 2)
	suite.Equal(int64(3), response.Total)
	suite.Equal(1, response.Page)
	suite.Equal(2, response.Limit)
	suite.Equal(2, response.TotalPages)
	suite.Equal("Newest", response.Data[0].Title)
	suite.Equal("Middle", response.Data[1].Title)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/evidence/history/"+streamUUID.String()+"?page=2&limit=2", nil)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Len(response.Data, 1)
	suite.Equal(2, response.Page)
	suite.Equal("Oldest", response.Data[0].Title)
}

func (suite *EvidenceApiIntegrationSuite) TestHistoryPaginationRejectsInvalidParams() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := suite.setupServer()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/evidence/history/"+uuid.New().String()+"?page=0&limit=10", nil)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/evidence/history/"+uuid.New().String()+"?page=1&limit=0", nil)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

func (suite *EvidenceApiIntegrationSuite) TestSearchPagination() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	now := time.Now().UTC()
	evidences := []relational.Evidence{
		{
			UUID:  uuid.New(),
			Title: "Newest",
			Start: now.Add(-2 * time.Minute),
			End:   now.Add(-1 * time.Minute),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
		{
			UUID:  uuid.New(),
			Title: "Middle",
			Start: now.Add(-12 * time.Minute),
			End:   now.Add(-10 * time.Minute),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
		{
			UUID:  uuid.New(),
			Title: "Oldest",
			Start: now.Add(-22 * time.Minute),
			End:   now.Add(-20 * time.Minute),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
	}
	suite.Require().NoError(suite.DB.Create(&evidences).Error)

	server := suite.setupServer()

	reqBody, _ := json.Marshal(struct {
		Filter labelfilter.Filter
	}{
		Filter: labelfilter.Filter{
			Scope: &labelfilter.Scope{
				Condition: &labelfilter.Condition{
					Label:    "provider",
					Operator: "=",
					Value:    "aws",
				},
			},
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/evidence/search?page=1&limit=2", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	var response svc.ListResponse[PublicEvidenceResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Len(response.Data, 2)
	suite.Equal(int64(3), response.Total)
	suite.Equal(1, response.Page)
	suite.Equal(2, response.Limit)
	suite.Equal(2, response.TotalPages)
	suite.Equal("Newest", response.Data[0].Title)
	suite.Equal("Middle", response.Data[1].Title)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/evidence/search?page=2&limit=2", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Len(response.Data, 1)
	suite.Equal(2, response.Page)
	suite.Equal("Oldest", response.Data[0].Title)
}

func (suite *EvidenceApiIntegrationSuite) TestSearchPaginationRejectsInvalidParams() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := suite.setupServer()
	reqBody, _ := json.Marshal(struct {
		Filter labelfilter.Filter
	}{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/evidence/search?page=0&limit=10", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/evidence/search?page=1&limit=0", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

func (suite *EvidenceApiIntegrationSuite) TestSearchSortingAndNameFiltering() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	now := time.Now().UTC()
	stream := uuid.MustParse("00000000-0000-0000-0000-000000000003")
	evidences := []relational.Evidence{
		{
			UUID:  stream,
			Title: "Zeta Evidence",
			Start: now.Add(-2 * time.Minute),
			End:   now.Add(-1 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
				State: "satisfied",
			}),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
		{
			UUID:  uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			Title: "Alpha Evidence",
			Start: now.Add(-3 * time.Minute),
			End:   now.Add(-2 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
				State: "not-satisfied",
			}),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
		{
			UUID:  uuid.MustParse("00000000-0000-0000-0000-000000000002"),
			Title: "Beta Evidence",
			Start: now.Add(-4 * time.Minute),
			End:   now.Add(-3 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
				State: "satisfied",
			}),
			Labels: []relational.Labels{
				{Name: "provider", Value: "GCP"},
			},
		},
		{
			UUID:  stream,
			Title: "Old Zeta Evidence",
			Start: now.Add(-11 * time.Minute),
			End:   now.Add(-10 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
				State: "not-satisfied",
			}),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
	}
	suite.Require().NoError(suite.DB.Create(&evidences).Error)

	server := suite.setupServer()
	reqBody, _ := json.Marshal(struct {
		Filter labelfilter.Filter
	}{})

	search := func(path string) svc.ListResponse[PublicEvidenceResponse] {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		var response svc.ListResponse[PublicEvidenceResponse]
		suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
		return response
	}

	response := search("/api/evidence/search")
	suite.Equal(int64(3), response.Total)
	suite.Equal([]string{"Zeta Evidence", "Alpha Evidence", "Beta Evidence"}, evidenceTitles(response.Data))

	response = search("/api/evidence/search?sortBy=lastSeenAt&sortDirection=asc")
	suite.Equal([]string{"Beta Evidence", "Alpha Evidence", "Zeta Evidence"}, evidenceTitles(response.Data))

	response = search("/api/evidence/search?sortBy=name&sortDirection=asc")
	suite.Equal([]string{"Alpha Evidence", "Beta Evidence", "Zeta Evidence"}, evidenceTitles(response.Data))

	response = search("/api/evidence/search?sortBy=status&sortDirection=asc")
	suite.Equal([]string{"Alpha Evidence", "Beta Evidence", "Zeta Evidence"}, evidenceTitles(response.Data))

	response = search("/api/evidence/search?name=alpha")
	suite.Equal(int64(1), response.Total)
	suite.Equal([]string{"Alpha Evidence"}, evidenceTitles(response.Data))
}

func (suite *EvidenceApiIntegrationSuite) TestSearchCombinesLabelAndNameFilters() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	now := time.Now().UTC()
	evidences := []relational.Evidence{
		{
			UUID:  uuid.New(),
			Title: "AWS Evidence",
			Start: now.Add(-2 * time.Minute),
			End:   now.Add(-1 * time.Minute),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
		{
			UUID:  uuid.New(),
			Title: "AWS Evidence",
			Start: now.Add(-3 * time.Minute),
			End:   now.Add(-2 * time.Minute),
			Labels: []relational.Labels{
				{Name: "provider", Value: "GCP"},
			},
		},
	}
	suite.Require().NoError(suite.DB.Create(&evidences).Error)

	server := suite.setupServer()
	reqBody, _ := json.Marshal(struct {
		Filter labelfilter.Filter
	}{
		Filter: labelfilter.Filter{
			Scope: &labelfilter.Scope{
				Condition: &labelfilter.Condition{
					Label:    "provider",
					Operator: "=",
					Value:    "aws",
				},
			},
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/evidence/search?name=aws", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	var response svc.ListResponse[PublicEvidenceResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Equal(int64(1), response.Total)
	suite.Equal([]string{"AWS Evidence"}, evidenceTitles(response.Data))
	suite.Equal("AWS", response.Data[0].Labels[0].Value)
}

func (suite *EvidenceApiIntegrationSuite) TestSearchRejectsInvalidSortParams() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := suite.setupServer()
	reqBody, _ := json.Marshal(struct {
		Filter labelfilter.Filter
	}{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/evidence/search?sortBy=createdAt", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
	suite.Contains(rec.Body.String(), "supported values: lastSeenAt, name, status")

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/evidence/search?sortDirection=sideways", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
	suite.Contains(rec.Body.String(), "supported values: asc, desc")
}

func evidenceTitles(items []PublicEvidenceResponse) []string {
	titles := make([]string, 0, len(items))
	for _, item := range items {
		titles = append(titles, item.Title)
	}
	return titles
}

func (suite *EvidenceApiIntegrationSuite) TestStatusOverTime() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	stream := uuid.New()

	now := time.Now()
	evidence := []relational.Evidence{
		{
			UUID:   stream,
			Title:  "E1",
			Start:  now.Add(-2 * time.Minute),
			End:    now.Add(-1 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
		},
		{
			UUID:   stream,
			Title:  "E2",
			Start:  now.Add(-12 * time.Minute),
			End:    now.Add(-10 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied"}),
		},
		{
			UUID:   stream,
			Title:  "E3",
			Start:  now.Add(-22 * time.Minute),
			End:    now.Add(-20 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
		},
		{
			UUID:   stream,
			Title:  "E4",
			Start:  now.Add(-6 * time.Hour),
			End:    now.Add(-5 * time.Hour),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied"}),
		},
	}
	suite.NoError(suite.DB.Create(&evidence).Error)

	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	services := &APIServices{}
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	services.EvidenceService = evidenceSvc
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(struct {
		Filter labelfilter.Filter
	}{})
	req := httptest.NewRequest(http.MethodPost, "/api/evidence/status-over-time", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)

	response := struct {
		Data []struct {
			Interval time.Time
			Statuses []struct {
				Count  int64
				Status string
			}
		} `json:"data"`
	}{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err)

	suite.Len(response.Data, 7)
	suite.NotContains(rec.Body.String(), `"statuses":null`)

	// verify counts for each interval
	toMap := func(in []struct {
		Count  int64
		Status string
	}) map[string]int64 {
		m := make(map[string]int64)
		for _, s := range in {
			m[s.Status] = s.Count
		}
		return m
	}

	counts := toMap(response.Data[0].Statuses)
	suite.Equal(int64(1), counts["satisfied"])
	suite.Equal(int64(0), counts["not-satisfied"])

	counts = toMap(response.Data[1].Statuses)
	suite.Equal(int64(0), counts["satisfied"])
	suite.Equal(int64(1), counts["not-satisfied"])

	counts = toMap(response.Data[2].Statuses)
	suite.Equal(int64(1), counts["satisfied"])
	suite.Equal(int64(0), counts["not-satisfied"])

	counts = toMap(response.Data[3].Statuses)
	suite.Equal(int64(0), counts["satisfied"])
	suite.Equal(int64(1), counts["not-satisfied"])
}

func (suite *EvidenceApiIntegrationSuite) TestComplianceByFilter() {
	suite.Run("Returns status counts for a filter", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Create a filter
		filter := relational.Filter{
			Name: "Test Filter",
			Filter: datatypes.NewJSONType(labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "provider",
						Operator: "=",
						Value:    "aws",
					},
				},
			}),
		}
		suite.NoError(suite.DB.Create(&filter).Error)

		// Create evidence matching the filter
		evidence := []relational.Evidence{
			{
				UUID:   uuid.New(),
				Title:  "Satisfied Evidence",
				Start:  time.Now().Add(-time.Hour),
				End:    time.Now().Add(-time.Hour).Add(time.Minute),
				Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
				Labels: []relational.Labels{
					{Name: "provider", Value: "aws"},
				},
			},
			{
				UUID:   uuid.New(),
				Title:  "Not Satisfied Evidence",
				Start:  time.Now().Add(-time.Hour),
				End:    time.Now().Add(-time.Hour).Add(time.Minute),
				Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied"}),
				Labels: []relational.Labels{
					{Name: "provider", Value: "aws"},
				},
			},
			{
				UUID:   uuid.New(),
				Title:  "Another Satisfied",
				Start:  time.Now().Add(-time.Hour),
				End:    time.Now().Add(-time.Hour).Add(time.Minute),
				Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
				Labels: []relational.Labels{
					{Name: "provider", Value: "aws"},
				},
			},
			{
				UUID:   uuid.New(),
				Title:  "Non-matching Evidence",
				Start:  time.Now().Add(-time.Hour),
				End:    time.Now().Add(-time.Hour).Add(time.Minute),
				Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
				Labels: []relational.Labels{
					{Name: "provider", Value: "github"},
				},
			},
		}
		suite.NoError(suite.DB.Create(&evidence).Error)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/evidence/compliance-by-filter/%s", filter.ID), nil)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		response := struct {
			Data []struct {
				Count  int64  `json:"count"`
				Status string `json:"status"`
			} `json:"data"`
		}{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err)

		// Should have 2 satisfied and 1 not-satisfied (excluding the github one)
		statusCounts := make(map[string]int64)
		for _, s := range response.Data {
			statusCounts[s.Status] = s.Count
		}
		suite.Equal(int64(2), statusCounts["satisfied"])
		suite.Equal(int64(1), statusCounts["not-satisfied"])
	})

	suite.Run("Returns 404 for non-existent filter", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/evidence/compliance-by-filter/%s", uuid.New()), nil)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusNotFound, rec.Code)
	})

	suite.Run("Returns 400 for invalid UUID", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/evidence/compliance-by-filter/invalid-uuid", nil)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusBadRequest, rec.Code)
	})
}
