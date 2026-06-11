//go:build integration

package oscal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

// ---------------------------------------------------------------------------
// Suite definition
// ---------------------------------------------------------------------------

type SystemComponentSuggestionsIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
}

func TestSystemComponentSuggestionsIntegrationSuite(t *testing.T) {
	suite.Run(t, new(SystemComponentSuggestionsIntegrationSuite))
}

func (suite *SystemComponentSuggestionsIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()

	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(suite.server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) SetupTest() {
	suite.Require().NoError(suite.Migrator.Refresh())
}

// ---------------------------------------------------------------------------
// Request helper
// ---------------------------------------------------------------------------

func (suite *SystemComponentSuggestionsIntegrationSuite) req(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
	var buf []byte
	if body != nil {
		var err error
		buf, err = json.Marshal(body)
		suite.Require().NoError(err)
	}
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(buf))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	return rec, req
}

// ---------------------------------------------------------------------------
// Data-building helpers
// ---------------------------------------------------------------------------

// buildSSP creates and POSTs a minimal SSP with one ImplementedRequirement for the given controlID.
// Returns the created SSP UUID and the ImplementedRequirement UUID.
func (suite *SystemComponentSuggestionsIntegrationSuite) buildSSP(controlID string) (sspID, implReqID string) {
	sspID = uuid.New().String()
	implReqID = uuid.New().String()
	componentUUID := uuid.New().String()
	now := time.Now()

	ssp := &oscalTypes_1_1_3.SystemSecurityPlan{
		UUID: sspID,
		Metadata: oscalTypes_1_1_3.Metadata{
			Title:        "Suggestions Test SSP",
			Version:      "1.0.0",
			OscalVersion: "1.1.3",
			LastModified: now,
		},
		ImportProfile: oscalTypes_1_1_3.ImportProfile{
			Href: "https://example.com/profile",
		},
		SystemCharacteristics: oscalTypes_1_1_3.SystemCharacteristics{
			SystemName:               "Suggestions Test System",
			Description:              "System for suggestion tests",
			SecuritySensitivityLevel: "moderate",
			SystemIds: []oscalTypes_1_1_3.SystemId{
				{IdentifierType: "https://ietf.org/rfc/rfc4122", ID: uuid.New().String()},
			},
			Status: oscalTypes_1_1_3.Status{State: "operational"},
			SystemInformation: oscalTypes_1_1_3.SystemInformation{
				InformationTypes: []oscalTypes_1_1_3.InformationType{
					{UUID: uuid.New().String(), Title: "Test Info", Description: "desc"},
				},
			},
		},
		SystemImplementation: oscalTypes_1_1_3.SystemImplementation{
			Users: []oscalTypes_1_1_3.SystemUser{
				{UUID: uuid.New().String(), Title: "Admin"},
			},
			Components: []oscalTypes_1_1_3.SystemComponent{
				{
					UUID:        componentUUID,
					Type:        "software",
					Title:       "Seed Component",
					Description: "Initial seed",
					Status:      oscalTypes_1_1_3.SystemComponentStatus{State: "operational"},
				},
			},
		},
		ControlImplementation: oscalTypes_1_1_3.ControlImplementation{
			Description: "Test control impl",
			ImplementedRequirements: []oscalTypes_1_1_3.ImplementedRequirement{
				{UUID: implReqID, ControlId: controlID},
			},
		},
	}

	rec, req := suite.req(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusCreated, rec.Code, "failed to create SSP: %s", rec.Body.String())
	return
}

// buildFilterAndEvidence creates the Filter → Evidence → ComponentDefinitionLabel chain
// required for the suggestion engine to match a DefinedComponent to the given controlID.
// It seeds the data directly into the DB, mirroring what SubjectTemplateService does in production.
// Returns the DefinedComponent UUID and ComponentDefinition UUID.
func (suite *SystemComponentSuggestionsIntegrationSuite) buildFilterAndEvidence(controlID string) (string, string) {
	return suite.buildFilterAndEvidenceInCatalog(uuid.Nil, controlID, "test-"+controlID)
}

// buildCatalogWithControl creates a Catalog and a Control row with the given control ID,
// returning the catalog ID. Used to seed the same control ID in multiple catalogs.
func (suite *SystemComponentSuggestionsIntegrationSuite) buildCatalogWithControl(controlID string) uuid.UUID {
	catalog := relational.Catalog{}
	suite.Require().NoError(suite.DB.Create(&catalog).Error)
	control := relational.Control{
		CatalogID: *catalog.ID,
		ID:        controlID,
		Title:     "Control " + controlID,
	}
	suite.Require().NoError(suite.DB.Create(&control).Error)
	return *catalog.ID
}

// linkSSPToProfileWithControls creates a Profile, binds it to the SSP via ssp_profiles,
// and registers each (catalogID, controlID) pair in profile_controls so the SSP's control
// resolution is scoped to that catalog. Returns the profile ID.
func (suite *SystemComponentSuggestionsIntegrationSuite) linkSSPToProfileWithControls(sspID string, catalogID uuid.UUID, controlIDs ...string) uuid.UUID {
	profileID := uuid.New()
	profile := relational.Profile{UUIDModel: relational.UUIDModel{ID: &profileID}}
	suite.Require().NoError(suite.DB.Create(&profile).Error)

	suite.Require().NoError(suite.DB.Exec(
		`INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)`,
		sspID, profileID,
	).Error)

	for _, controlID := range controlIDs {
		suite.Require().NoError(suite.DB.Exec(
			`INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)`,
			profileID, catalogID, controlID,
		).Error)
	}

	return profileID
}

// buildFilterAndEvidenceInCatalog is buildFilterAndEvidence with an explicit catalog scope
// on the filter_controls row and a caller-chosen label value, so the same control ID can be
// seeded in different catalogs with distinguishable components.
func (suite *SystemComponentSuggestionsIntegrationSuite) buildFilterAndEvidenceInCatalog(catalogID uuid.UUID, controlID, labelValue string) (string, string) {
	labelKey := "plugin"

	// 1. Create a Filter with a label condition matching labelKey=labelValue
	lf := labelfilter.Filter{
		Scope: &labelfilter.Scope{
			Condition: &labelfilter.Condition{
				Label:    labelKey,
				Operator: "=",
				Value:    labelValue,
			},
		},
	}
	filter := relational.Filter{
		Name:   "filter-for-" + controlID,
		Filter: datatypes.NewJSONType(lf),
	}
	suite.Require().NoError(suite.DB.Create(&filter).Error)

	// 2. Link the Filter to the (catalogID, controlID) pair via the filter_controls join table
	suite.Require().NoError(suite.DB.Exec(
		`INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)`,
		filter.ID, catalogID, controlID,
	).Error)

	// 3. Create an Evidence record with matching labels
	now := time.Now()
	evidence := relational.Evidence{
		UUID:        uuid.New(),
		Title:       "test evidence for " + controlID,
		Description: "evidence for " + controlID,
		Start:       now,
		End:         now,
	}
	suite.Require().NoError(suite.DB.Create(&evidence).Error)
	suite.Require().NoError(suite.DB.Exec(
		`INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, ?, ?)`,
		evidence.ID, labelKey, labelValue,
	).Error)

	// 4. Create a ComponentDefinition and a matching DefinedComponent
	compDef := relational.ComponentDefinition{}
	suite.Require().NoError(suite.DB.Create(&compDef).Error)
	dc := relational.DefinedComponent{
		Type:                  "software",
		Title:                 "Suggested Component",
		Description:           "A component suggested by the engine",
		ComponentDefinitionID: compDef.ID,
	}
	suite.Require().NoError(suite.DB.Create(&dc).Error)

	// 5. Store label match scoped to the DefinedComponent.
	suite.Require().NoError(suite.DB.Exec(
		`INSERT INTO component_definition_labels (defined_component_id, component_definition_id, key, value) VALUES (?, ?, ?, ?)`,
		dc.ID, compDef.ID, labelKey, labelValue,
	).Error)

	return dc.ID.String(), compDef.ID.String()
}

// buildSSPWithTwoImplReqs creates and POSTs a minimal SSP with two ImplementedRequirements,
// one per given control ID. Returns the SSP UUID and both ImplementedRequirement UUIDs.
func (suite *SystemComponentSuggestionsIntegrationSuite) buildSSPWithTwoImplReqs(controlA, controlB string) (sspID, implReqA, implReqB string) {
	sspID = uuid.New().String()
	implReqA = uuid.New().String()
	implReqB = uuid.New().String()
	now := time.Now()

	ssp := &oscalTypes_1_1_3.SystemSecurityPlan{
		UUID: sspID,
		Metadata: oscalTypes_1_1_3.Metadata{
			Title: "Two-Req SSP", Version: "1.0", OscalVersion: "1.1.3", LastModified: now,
		},
		ImportProfile: oscalTypes_1_1_3.ImportProfile{Href: "https://example.com/profile"},
		SystemCharacteristics: oscalTypes_1_1_3.SystemCharacteristics{
			SystemName: "Two-Req System", Description: "desc", SecuritySensitivityLevel: "moderate",
			SystemIds:         []oscalTypes_1_1_3.SystemId{{IdentifierType: "https://ietf.org/rfc/rfc4122", ID: uuid.New().String()}},
			Status:            oscalTypes_1_1_3.Status{State: "operational"},
			SystemInformation: oscalTypes_1_1_3.SystemInformation{InformationTypes: []oscalTypes_1_1_3.InformationType{{UUID: uuid.New().String(), Title: "t", Description: "d"}}},
		},
		SystemImplementation: oscalTypes_1_1_3.SystemImplementation{
			Users:      []oscalTypes_1_1_3.SystemUser{{UUID: uuid.New().String(), Title: "Admin"}},
			Components: []oscalTypes_1_1_3.SystemComponent{{UUID: uuid.New().String(), Type: "software", Title: "Seed", Description: "d", Status: oscalTypes_1_1_3.SystemComponentStatus{State: "operational"}}},
		},
		ControlImplementation: oscalTypes_1_1_3.ControlImplementation{
			Description: "two-req ctrl",
			ImplementedRequirements: []oscalTypes_1_1_3.ImplementedRequirement{
				{UUID: implReqA, ControlId: controlA},
				{UUID: implReqB, ControlId: controlB},
			},
		},
	}

	rec, req := suite.req(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusCreated, rec.Code, "failed to create SSP: %s", rec.Body.String())
	return
}

// buildSharedFilterAndEvidence creates ONE DefinedComponent whose evidence matches ALL of the
// given control IDs: one Filter per control, all selecting the same labelled Evidence.
// Returns the DefinedComponent UUID and ComponentDefinition UUID.
func (suite *SystemComponentSuggestionsIntegrationSuite) buildSharedFilterAndEvidence(controlIDs ...string) (string, string) {
	labelKey := "plugin"
	labelValue := "shared-" + uuid.New().String()

	lf := labelfilter.Filter{
		Scope: &labelfilter.Scope{
			Condition: &labelfilter.Condition{
				Label:    labelKey,
				Operator: "=",
				Value:    labelValue,
			},
		},
	}
	for _, controlID := range controlIDs {
		filter := relational.Filter{
			Name:   "filter-for-" + controlID,
			Filter: datatypes.NewJSONType(lf),
		}
		suite.Require().NoError(suite.DB.Create(&filter).Error)
		suite.Require().NoError(suite.DB.Exec(
			`INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)`,
			filter.ID, uuid.Nil, controlID,
		).Error)
	}

	now := time.Now()
	evidence := relational.Evidence{
		UUID:        uuid.New(),
		Title:       "shared evidence",
		Description: "evidence matching multiple controls",
		Start:       now,
		End:         now,
	}
	suite.Require().NoError(suite.DB.Create(&evidence).Error)
	suite.Require().NoError(suite.DB.Exec(
		`INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, ?, ?)`,
		evidence.ID, labelKey, labelValue,
	).Error)

	compDef := relational.ComponentDefinition{}
	suite.Require().NoError(suite.DB.Create(&compDef).Error)
	dc := relational.DefinedComponent{
		Type:                  "software",
		Title:                 "Shared Suggested Component",
		Description:           "A component relevant to multiple requirements",
		ComponentDefinitionID: compDef.ID,
	}
	suite.Require().NoError(suite.DB.Create(&dc).Error)
	suite.Require().NoError(suite.DB.Exec(
		`INSERT INTO component_definition_labels (defined_component_id, component_definition_id, key, value) VALUES (?, ?, ?, ?)`,
		dc.ID, compDef.ID, labelKey, labelValue,
	).Error)

	return dc.ID.String(), compDef.ID.String()
}

func (suite *SystemComponentSuggestionsIntegrationSuite) addStatement(implReqID string) string {
	stmtUUID := uuid.New()
	reqUUID := uuid.MustParse(implReqID)
	stmt := relational.Statement{
		UUIDModel:                relational.UUIDModel{ID: &stmtUUID},
		StatementId:              "statement-" + stmtUUID.String(),
		ImplementedRequirementId: reqUUID,
	}
	suite.Require().NoError(suite.DB.Create(&stmt).Error)
	return stmtUUID.String()
}

// ---------------------------------------------------------------------------
// Tests: Create/Update SystemComponent with definedComponentId
// ---------------------------------------------------------------------------

func (suite *SystemComponentSuggestionsIntegrationSuite) TestCreateSystemComponent_WithDefinedComponentID() {
	sspID, _ := suite.buildSSP("ac-1")

	// Get the system implementation
	var ssp relational.SystemSecurityPlan
	suite.Require().NoError(suite.DB.First(&ssp, "id = ?", sspID).Error)
	var si relational.SystemImplementation
	suite.Require().NoError(suite.DB.Where("system_security_plan_id = ?", sspID).First(&si).Error)

	// Create a DefinedComponent directly in DB so we have its ID
	compDef := relational.ComponentDefinition{}
	suite.Require().NoError(suite.DB.Create(&compDef).Error)
	dc := relational.DefinedComponent{
		Type:                  "software",
		Title:                 "Linked Component",
		Description:           "desc",
		ComponentDefinitionID: compDef.ID,
	}
	suite.Require().NoError(suite.DB.Create(&dc).Error)

	// POST a new SystemComponent with definedComponentId
	body := map[string]interface{}{
		"uuid":               uuid.New().String(),
		"type":               "software",
		"title":              "Linked Component",
		"description":        "desc",
		"status":             map[string]string{"state": "operational"},
		"definedComponentId": dc.ID.String(),
	}

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/components", sspID),
		body)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code, rec.Body.String())

	// Verify the DefinedComponentID is persisted
	var saved relational.SystemComponent
	suite.Require().NoError(suite.DB.
		Where("system_implementation_id = ? AND title = ?", si.ID, "Linked Component").
		First(&saved).Error)
	suite.Require().NotNil(saved.DefinedComponentID)
	suite.Equal(*dc.ID, *saved.DefinedComponentID)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestCreateSystemComponent_WithoutDefinedComponentID_BackwardCompat() {
	sspID, _ := suite.buildSSP("ac-1")

	body := map[string]interface{}{
		"uuid":        uuid.New().String(),
		"type":        "software",
		"title":       "Plain Component",
		"description": "No defined component link",
		"status":      map[string]string{"state": "operational"},
	}

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/components", sspID),
		body)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusCreated, rec.Code, rec.Body.String())

	// Verify no DefinedComponentID set
	var saved relational.SystemComponent
	var si relational.SystemImplementation
	suite.Require().NoError(suite.DB.Where("system_security_plan_id = ?", sspID).First(&si).Error)
	suite.Require().NoError(suite.DB.
		Where("system_implementation_id = ? AND title = ?", si.ID, "Plain Component").
		First(&saved).Error)
	suite.Nil(saved.DefinedComponentID)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestUpdateSystemComponent_WithDefinedComponentID() {
	sspID, _ := suite.buildSSP("ac-1")

	// Seed a DefinedComponent
	compDef := relational.ComponentDefinition{}
	suite.Require().NoError(suite.DB.Create(&compDef).Error)
	dc := relational.DefinedComponent{
		Type:                  "software",
		Title:                 "DC for update",
		Description:           "desc",
		ComponentDefinitionID: compDef.ID,
	}
	suite.Require().NoError(suite.DB.Create(&dc).Error)

	// First create a component without a link
	compID := uuid.New().String()
	createBody := map[string]interface{}{
		"uuid":        compID,
		"type":        "software",
		"title":       "To Be Updated",
		"description": "pre-update",
		"status":      map[string]string{"state": "operational"},
	}
	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/components", sspID),
		createBody)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusCreated, rec.Code)

	// Now update with definedComponentId
	updateBody := map[string]interface{}{
		"uuid":               compID,
		"type":               "software",
		"title":              "To Be Updated",
		"description":        "post-update",
		"status":             map[string]string{"state": "operational"},
		"definedComponentId": dc.ID.String(),
	}
	rec, req = suite.req(http.MethodPut,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/system-implementation/components/%s", sspID, compID),
		updateBody)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	// Verify DefinedComponentID was set
	var saved relational.SystemComponent
	suite.Require().NoError(suite.DB.Where("id = ?", compID).First(&saved).Error)
	suite.Require().NotNil(saved.DefinedComponentID)
	suite.Equal(*dc.ID, *saved.DefinedComponentID)
}

// ---------------------------------------------------------------------------
// Tests: SuggestComponents endpoint
// ---------------------------------------------------------------------------

func (suite *SystemComponentSuggestionsIntegrationSuite) TestSuggestComponents_ReturnsMatchingDefinedComponent() {
	const controlID = "ac-2"
	sspID, implReqID := suite.buildSSP(controlID)
	suite.buildFilterAndEvidence(controlID)

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/suggest-components", sspID, implReqID),
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var resp handler.GenericDataListResponse[relational.SystemComponentSuggestion]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	suite.Require().Len(resp.Data, 1)
	suite.Equal("Suggested Component", resp.Data[0].Name)
	suite.Equal("software", resp.Data[0].Type)
	suite.NotEqual(uuid.Nil, resp.Data[0].DefinedComponentID)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestSuggestComponents_NoMatch() {
	const controlID = "ac-3"
	sspID, implReqID := suite.buildSSP(controlID)
	// Build a component definition for a DIFFERENT control
	suite.buildFilterAndEvidence("si-99")

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/suggest-components", sspID, implReqID),
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var resp handler.GenericDataListResponse[relational.SystemComponentSuggestion]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	suite.Empty(resp.Data)
}

// TestSuggestComponents_AmbiguousControlID_ScopedToLinkedCatalog guards catalog-scoped
// control resolution: the same control ID exists in two catalogs, each with its own
// Filter/Evidence/DefinedComponent chain, and the SSP is linked (via ssp_profiles →
// profile_controls) to a profile importing the control from only one catalog. Only the
// linked catalog's component may be suggested.
func (suite *SystemComponentSuggestionsIntegrationSuite) TestSuggestComponents_AmbiguousControlID_ScopedToLinkedCatalog() {
	const controlID = "ac-1"
	catalogA := suite.buildCatalogWithControl(controlID)
	catalogB := suite.buildCatalogWithControl(controlID)

	dcA, _ := suite.buildFilterAndEvidenceInCatalog(catalogA, controlID, "catalog-a-component")
	suite.buildFilterAndEvidenceInCatalog(catalogB, controlID, "catalog-b-component")

	sspID, implReqID := suite.buildSSP(controlID)
	suite.linkSSPToProfileWithControls(sspID, catalogA, controlID)

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/suggest-components", sspID, implReqID),
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var resp handler.GenericDataListResponse[relational.SystemComponentSuggestion]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	suite.Require().Len(resp.Data, 1, "only the component from the SSP's linked catalog should be suggested")
	suite.Equal(dcA, resp.Data[0].DefinedComponentID.String())
}

// TestSuggestComponents_AmbiguousControlID_NoLinkedProfile_GlobalFallback documents the
// fallback: an SSP without linked profiles has no catalog scope, so the same control ID in
// two catalogs resolves against both.
func (suite *SystemComponentSuggestionsIntegrationSuite) TestSuggestComponents_AmbiguousControlID_NoLinkedProfile_GlobalFallback() {
	const controlID = "ac-1"
	catalogA := suite.buildCatalogWithControl(controlID)
	catalogB := suite.buildCatalogWithControl(controlID)

	dcA, _ := suite.buildFilterAndEvidenceInCatalog(catalogA, controlID, "catalog-a-component")
	dcB, _ := suite.buildFilterAndEvidenceInCatalog(catalogB, controlID, "catalog-b-component")

	sspID, implReqID := suite.buildSSP(controlID)

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/suggest-components", sspID, implReqID),
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var resp handler.GenericDataListResponse[relational.SystemComponentSuggestion]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	suite.Require().Len(resp.Data, 2, "without linked profiles both catalogs' components are suggested")
	got := []string{resp.Data[0].DefinedComponentID.String(), resp.Data[1].DefinedComponentID.String()}
	suite.Contains(got, dcA)
	suite.Contains(got, dcB)
}

// TestSuggestComponents_LinkedProfileWithoutControl_NoSuggestions guards strict scoping:
// once the SSP is linked to profiles, a control absent from all of them resolves to nothing,
// even if a global filter for that control ID exists in another catalog.
func (suite *SystemComponentSuggestionsIntegrationSuite) TestSuggestComponents_LinkedProfileWithoutControl_NoSuggestions() {
	const controlID = "ac-1"
	catalogA := suite.buildCatalogWithControl("si-4")
	catalogB := suite.buildCatalogWithControl(controlID)

	suite.buildFilterAndEvidenceInCatalog(catalogB, controlID, "catalog-b-component")

	sspID, implReqID := suite.buildSSP(controlID)
	// The linked profile imports a different control from catalog A; "ac-1" is out of scope.
	suite.linkSSPToProfileWithControls(sspID, catalogA, "si-4")

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/suggest-components", sspID, implReqID),
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var resp handler.GenericDataListResponse[relational.SystemComponentSuggestion]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	suite.Empty(resp.Data, "controls outside the linked profiles' catalogs must not resolve")
}

// TestBulkApply_AmbiguousControlID_ScopedToLinkedCatalog verifies the scoping holds through
// the bulk-apply path, which funnels every ImplementedRequirement through the same resolution.
func (suite *SystemComponentSuggestionsIntegrationSuite) TestBulkApply_AmbiguousControlID_ScopedToLinkedCatalog() {
	const controlID = "ac-1"
	catalogA := suite.buildCatalogWithControl(controlID)
	catalogB := suite.buildCatalogWithControl(controlID)

	dcA, _ := suite.buildFilterAndEvidenceInCatalog(catalogA, controlID, "catalog-a-component")
	suite.buildFilterAndEvidenceInCatalog(catalogB, controlID, "catalog-b-component")

	sspID, _ := suite.buildSSP(controlID)
	suite.linkSSPToProfileWithControls(sspID, catalogA, controlID)

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/bulk-apply-component-suggestions", sspID),
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNoContent, rec.Code, rec.Body.String())

	var si relational.SystemImplementation
	suite.Require().NoError(suite.DB.Where("system_security_plan_id = ?", sspID).First(&si).Error)

	var components []relational.SystemComponent
	suite.Require().NoError(suite.DB.
		Where("system_implementation_id = ? AND defined_component_id IS NOT NULL", si.ID).
		Find(&components).Error)
	suite.Require().Len(components, 1, "bulk apply must only create components from the linked catalog")
	suite.Equal(dcA, components[0].DefinedComponentID.String())
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestSuggestComponents_AlreadyLinkedExcluded() {
	const controlID = "ac-4"
	sspID, implReqID := suite.buildSSP(controlID)
	dcUUID, compDefUUID := suite.buildFilterAndEvidence(controlID)

	// Apply the suggestion first so the component is already in the SSP
	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/apply-suggestion", sspID, implReqID),
		map[string]any{
			"component-definition-id": compDefUUID,
			"defined-component-id":    dcUUID,
		})
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusNoContent, rec.Code)

	// Now suggest — should return empty
	rec, req = suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/suggest-components", sspID, implReqID),
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	var resp handler.GenericDataListResponse[relational.SystemComponentSuggestion]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	suite.Empty(resp.Data, "component %s should no longer appear as suggestion after being applied", dcUUID)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestSuggestComponentsForStatement_ReturnsMatchingDefinedComponent() {
	const controlID = "ac-5"
	sspID, implReqID := suite.buildSSP(controlID)
	stmtID := suite.addStatement(implReqID)
	suite.buildFilterAndEvidence(controlID)

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/statements/%s/suggest-components", sspID, implReqID, stmtID),
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var resp handler.GenericDataListResponse[relational.SystemComponentSuggestion]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	suite.Require().Len(resp.Data, 1)
	suite.Equal("Suggested Component", resp.Data[0].Name)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestSuggestComponents_InvalidSSPID() {
	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/not-a-uuid/control-implementation/implemented-requirements/%s/suggest-components", uuid.New()),
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestSuggestComponents_InvalidReqID() {
	sspID, _ := suite.buildSSP("ac-1")
	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/not-a-uuid/suggest-components", sspID),
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// Tests: ApplySuggestion endpoint
// ---------------------------------------------------------------------------

func (suite *SystemComponentSuggestionsIntegrationSuite) TestApplySuggestion_CreatesSystemComponentAndByComponent() {
	const controlID = "sc-7"
	sspID, implReqID := suite.buildSSP(controlID)
	dcUUID, compDefUUID := suite.buildFilterAndEvidence(controlID)

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/apply-suggestion", sspID, implReqID),
		map[string]any{
			"component-definition-id": compDefUUID,
			"defined-component-id":    dcUUID,
		})
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNoContent, rec.Code, rec.Body.String())

	// Verify a new SystemComponent exists with DefinedComponentID set
	var si relational.SystemImplementation
	suite.Require().NoError(suite.DB.Where("system_security_plan_id = ?", sspID).First(&si).Error)

	var components []relational.SystemComponent
	suite.Require().NoError(suite.DB.
		Where("system_implementation_id = ? AND defined_component_id IS NOT NULL", si.ID).
		Find(&components).Error)
	suite.Require().Len(components, 1, "expected exactly one new component with defined_component_id")
	suite.Equal("Suggested Component", components[0].Title)

	// Verify a ByComponent was created
	var byComponents []relational.ByComponent
	suite.Require().NoError(suite.DB.
		Where("component_uuid = ?", components[0].ID).
		Find(&byComponents).Error)
	suite.Require().Len(byComponents, 1)

	implReqUUID, err := uuid.Parse(implReqID)
	suite.Require().NoError(err)
	suite.Equal(implReqUUID, *byComponents[0].ParentID)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestApplySuggestion_Idempotent() {
	const controlID = "sc-8"
	sspID, implReqID := suite.buildSSP(controlID)
	dcUUID, compDefUUID := suite.buildFilterAndEvidence(controlID)

	path := fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/apply-suggestion", sspID, implReqID)

	// Apply twice
	for i := 0; i < 2; i++ {
		rec, req := suite.req(http.MethodPost, path, map[string]any{
			"component-definition-id": compDefUUID,
			"defined-component-id":    dcUUID,
		})
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusNoContent, rec.Code, "attempt %d: %s", i+1, rec.Body.String())
	}

	// Should have exactly one SystemComponent with DefinedComponentID
	var si relational.SystemImplementation
	suite.Require().NoError(suite.DB.Where("system_security_plan_id = ?", sspID).First(&si).Error)
	var count int64
	suite.DB.Model(&relational.SystemComponent{}).
		Where("system_implementation_id = ? AND defined_component_id IS NOT NULL", si.ID).
		Count(&count)
	suite.Equal(int64(1), count, "duplicate SystemComponents must not be created")
}

// TestApplySuggestion_DoesNotRemoveSuggestionFromOtherRequirement guards the per-requirement
// evaluation granularity: applying a suggestion on requirement A must not exclude the same
// component from requirement B's suggestions when B's evidence also matches it.
func (suite *SystemComponentSuggestionsIntegrationSuite) TestApplySuggestion_DoesNotRemoveSuggestionFromOtherRequirement() {
	const (
		controlA = "pr-1"
		controlB = "pr-2"
	)
	sspID, implReqA, implReqB := suite.buildSSPWithTwoImplReqs(controlA, controlB)
	dcUUID, compDefUUID := suite.buildSharedFilterAndEvidence(controlA, controlB)

	suggestPath := func(reqID string) string {
		return fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/suggest-components", sspID, reqID)
	}

	// Both requirements initially suggest the shared component
	for _, reqID := range []string{implReqA, implReqB} {
		rec, req := suite.req(http.MethodPost, suggestPath(reqID), nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())

		var resp handler.GenericDataListResponse[relational.SystemComponentSuggestion]
		suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
		suite.Require().Len(resp.Data, 1, "requirement %s should initially suggest the shared component", reqID)
	}

	// Apply the suggestion on requirement A
	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/apply-suggestion", sspID, implReqA),
		map[string]any{
			"component-definition-id": compDefUUID,
			"defined-component-id":    dcUUID,
		})
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusNoContent, rec.Code, rec.Body.String())

	// Requirement A no longer suggests it
	rec, req = suite.req(http.MethodPost, suggestPath(implReqA), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)
	var respA handler.GenericDataListResponse[relational.SystemComponentSuggestion]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &respA))
	suite.Empty(respA.Data, "requirement A should not suggest an already-linked component")

	// Requirement B still suggests it
	rec, req = suite.req(http.MethodPost, suggestPath(implReqB), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)
	var respB handler.GenericDataListResponse[relational.SystemComponentSuggestion]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &respB))
	suite.Require().Len(respB.Data, 1, "applying on requirement A must not remove the suggestion from requirement B")
	suite.Equal(dcUUID, respB.Data[0].DefinedComponentID.String())
}

// TestApplySuggestion_SecondRequirementReusesSystemComponent guards the apply path: applying the
// same component on a second requirement must reuse the existing SystemComponent and only add
// the ByComponent link for the second requirement.
func (suite *SystemComponentSuggestionsIntegrationSuite) TestApplySuggestion_SecondRequirementReusesSystemComponent() {
	const (
		controlA = "pr-3"
		controlB = "pr-4"
	)
	sspID, implReqA, implReqB := suite.buildSSPWithTwoImplReqs(controlA, controlB)
	dcUUID, compDefUUID := suite.buildSharedFilterAndEvidence(controlA, controlB)

	// Apply the suggestion on both requirements
	for _, reqID := range []string{implReqA, implReqB} {
		rec, req := suite.req(http.MethodPost,
			fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/apply-suggestion", sspID, reqID),
			map[string]any{
				"component-definition-id": compDefUUID,
				"defined-component-id":    dcUUID,
			})
		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusNoContent, rec.Code, "apply on requirement %s: %s", reqID, rec.Body.String())
	}

	// Exactly one SystemComponent exists for the defined component
	var si relational.SystemImplementation
	suite.Require().NoError(suite.DB.Where("system_security_plan_id = ?", sspID).First(&si).Error)

	var components []relational.SystemComponent
	suite.Require().NoError(suite.DB.
		Where("system_implementation_id = ? AND defined_component_id = ?", si.ID, dcUUID).
		Find(&components).Error)
	suite.Require().Len(components, 1, "applying on a second requirement must not create a duplicate SystemComponent")

	// Two ByComponent links exist, one per requirement
	var byComponents []relational.ByComponent
	suite.Require().NoError(suite.DB.
		Where("component_uuid = ?", components[0].ID).
		Find(&byComponents).Error)
	suite.Require().Len(byComponents, 2, "expected one ByComponent link per requirement")

	parents := map[string]bool{}
	for _, bc := range byComponents {
		suite.Require().NotNil(bc.ParentID)
		parents[bc.ParentID.String()] = true
	}
	suite.True(parents[implReqA], "missing ByComponent link for requirement A")
	suite.True(parents[implReqB], "missing ByComponent link for requirement B")
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestApplySuggestion_SuggestionNotFound() {
	const controlID = "ir-1"
	sspID, implReqID := suite.buildSSP(controlID)
	// Build a component suggestion chain for a different control, so it is not a valid suggestion for this SSP/requirement.
	dcUUID, compDefUUID := suite.buildFilterAndEvidence("ac-22")

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/apply-suggestion", sspID, implReqID),
		map[string]any{
			"component-definition-id": compDefUUID,
			"defined-component-id":    dcUUID,
		})
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNotFound, rec.Code)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestApplySuggestion_MissingPayloadFields() {
	const controlID = "ir-2"
	sspID, implReqID := suite.buildSSP(controlID)

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/apply-suggestion", sspID, implReqID),
		map[string]any{
			"defined-component-id": uuid.New().String(),
		})
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestApplySuggestionForStatement_CreatesByComponentOnStatement() {
	const controlID = "sc-9"
	sspID, implReqID := suite.buildSSP(controlID)
	stmtID := suite.addStatement(implReqID)
	dcUUID, compDefUUID := suite.buildFilterAndEvidence(controlID)

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/statements/%s/apply-suggestion", sspID, implReqID, stmtID),
		map[string]any{
			"component-definition-id": compDefUUID,
			"defined-component-id":    dcUUID,
		})
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNoContent, rec.Code, rec.Body.String())

	stmtUUID := uuid.MustParse(stmtID)
	parentType := "statements"
	var byComponent relational.ByComponent
	suite.Require().NoError(suite.DB.Where("parent_id = ? AND parent_type = ?", stmtUUID, parentType).First(&byComponent).Error)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestApplySuggestionsForStatement_CreatesByComponentOnStatement() {
	const controlID = "sc-10"
	sspID, implReqID := suite.buildSSP(controlID)
	stmtID := suite.addStatement(implReqID)
	suite.buildFilterAndEvidence(controlID)

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements/%s/statements/%s/apply-suggestions", sspID, implReqID, stmtID),
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNoContent, rec.Code, rec.Body.String())

	stmtUUID := uuid.MustParse(stmtID)
	parentType := "statements"
	var byComponent relational.ByComponent
	suite.Require().NoError(suite.DB.Where("parent_id = ? AND parent_type = ?", stmtUUID, parentType).First(&byComponent).Error)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestApplySuggestion_InvalidSSPID() {
	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/not-a-uuid/control-implementation/implemented-requirements/%s/apply-suggestion", uuid.New()),
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// Tests: BulkApplyComponentSuggestions endpoint
// ---------------------------------------------------------------------------

func (suite *SystemComponentSuggestionsIntegrationSuite) TestBulkApply_CreatesComponentsForAllImplReqs() {
	const (
		controlA = "au-1"
		controlB = "au-2"
	)
	// Build an SSP with two ImplementedRequirements via direct DB seeding
	// (we need two impl reqs which the OSCAL POST endpoint supports)
	sspID1 := uuid.New()
	now := time.Now()

	ssp := &oscalTypes_1_1_3.SystemSecurityPlan{
		UUID: sspID1.String(),
		Metadata: oscalTypes_1_1_3.Metadata{
			Title: "Bulk SSP", Version: "1.0", OscalVersion: "1.1.3", LastModified: now,
		},
		ImportProfile: oscalTypes_1_1_3.ImportProfile{Href: "https://example.com/p"},
		SystemCharacteristics: oscalTypes_1_1_3.SystemCharacteristics{
			SystemName: "Bulk System", Description: "bulk", SecuritySensitivityLevel: "low",
			SystemIds:         []oscalTypes_1_1_3.SystemId{{IdentifierType: "https://ietf.org/rfc/rfc4122", ID: uuid.New().String()}},
			Status:            oscalTypes_1_1_3.Status{State: "operational"},
			SystemInformation: oscalTypes_1_1_3.SystemInformation{InformationTypes: []oscalTypes_1_1_3.InformationType{{UUID: uuid.New().String(), Title: "t", Description: "d"}}},
		},
		SystemImplementation: oscalTypes_1_1_3.SystemImplementation{
			Users:      []oscalTypes_1_1_3.SystemUser{{UUID: uuid.New().String(), Title: "Admin"}},
			Components: []oscalTypes_1_1_3.SystemComponent{{UUID: uuid.New().String(), Type: "software", Title: "Seed", Description: "d", Status: oscalTypes_1_1_3.SystemComponentStatus{State: "operational"}}},
		},
		ControlImplementation: oscalTypes_1_1_3.ControlImplementation{
			Description: "bulk ctrl",
			ImplementedRequirements: []oscalTypes_1_1_3.ImplementedRequirement{
				{UUID: uuid.New().String(), ControlId: controlA},
				{UUID: uuid.New().String(), ControlId: controlB},
			},
		},
	}
	rec, req := suite.req(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusCreated, rec.Code)

	// Seed DefinedComponents for both controls
	suite.buildFilterAndEvidence(controlA)
	suite.buildFilterAndEvidence(controlB)

	// Bulk apply
	rec, req = suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/bulk-apply-component-suggestions", sspID1),
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNoContent, rec.Code, rec.Body.String())

	// Expect one new SystemComponent per control
	var si relational.SystemImplementation
	suite.Require().NoError(suite.DB.Where("system_security_plan_id = ?", sspID1).First(&si).Error)
	var count int64
	suite.DB.Model(&relational.SystemComponent{}).
		Where("system_implementation_id = ? AND defined_component_id IS NOT NULL", si.ID).
		Count(&count)
	suite.Equal(int64(2), count)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestBulkApply_Idempotent() {
	const controlID = "cm-6"
	sspID, _ := suite.buildSSP(controlID)
	suite.buildFilterAndEvidence(controlID)

	path := fmt.Sprintf("/api/oscal/system-security-plans/%s/bulk-apply-component-suggestions", sspID)
	for i := 0; i < 2; i++ {
		rec, req := suite.req(http.MethodPost, path, nil)
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusNoContent, rec.Code, "attempt %d: %s", i+1, rec.Body.String())
	}

	var si relational.SystemImplementation
	suite.Require().NoError(suite.DB.Where("system_security_plan_id = ?", sspID).First(&si).Error)
	var count int64
	suite.DB.Model(&relational.SystemComponent{}).
		Where("system_implementation_id = ? AND defined_component_id IS NOT NULL", si.ID).
		Count(&count)
	suite.Equal(int64(1), count)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestBulkApply_InvalidSSPID() {
	rec, req := suite.req(http.MethodPost,
		"/api/oscal/system-security-plans/not-a-uuid/bulk-apply-component-suggestions",
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

func (suite *SystemComponentSuggestionsIntegrationSuite) TestBulkApply_Unauthorized() {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/bulk-apply-component-suggestions", uuid.New()),
		nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusUnauthorized, rec.Code)
}
