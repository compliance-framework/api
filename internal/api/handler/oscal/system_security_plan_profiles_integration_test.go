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
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Suite definition
// ---------------------------------------------------------------------------

type SSPProfilesIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
}

func TestSSPProfilesIntegrationSuite(t *testing.T) {
	suite.Run(t, new(SSPProfilesIntegrationSuite))
}

func (suite *SSPProfilesIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()

	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(suite.server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)
}

func (suite *SSPProfilesIntegrationSuite) SetupTest() {
	suite.Require().NoError(suite.Migrator.Refresh())
}

// ---------------------------------------------------------------------------
// Request helper
// ---------------------------------------------------------------------------

func (suite *SSPProfilesIntegrationSuite) req(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
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

// createSSP creates and POSTs a minimal SSP. Returns its UUID.
func (suite *SSPProfilesIntegrationSuite) createSSP() string {
	sspID := uuid.New().String()
	now := time.Now()

	ssp := &oscalTypes_1_1_3.SystemSecurityPlan{
		UUID: sspID,
		Metadata: oscalTypes_1_1_3.Metadata{
			Title:        "Multi-Profile Test SSP",
			Version:      "1.0.0",
			OscalVersion: "1.1.3",
			LastModified: now,
		},
		ImportProfile: oscalTypes_1_1_3.ImportProfile{
			Href: "https://example.com/profile",
		},
		SystemCharacteristics: oscalTypes_1_1_3.SystemCharacteristics{
			SystemName:               "Multi-Profile Test System",
			Description:              "System for multi-profile tests",
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
					UUID:        uuid.New().String(),
					Type:        "software",
					Title:       "Seed Component",
					Description: "Initial seed",
					Status:      oscalTypes_1_1_3.SystemComponentStatus{State: "operational"},
				},
			},
		},
		ControlImplementation: oscalTypes_1_1_3.ControlImplementation{
			Description: "Test control impl",
		},
	}

	rec, req := suite.req(http.MethodPost, "/api/oscal/system-security-plans", ssp)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusCreated, rec.Code, "failed to create SSP: %s", rec.Body.String())
	return sspID
}

// createProfile seeds a profile with distinct controls directly in the DB.
// It creates a catalog with the given controls, then associates them with the
// profile via the GORM many2many relationship so that the composite FK
// (control_id, control_catalog_id) is populated correctly.
// Returns the profile UUID.
func (suite *SSPProfilesIntegrationSuite) createProfile(title string, controlIDs []string) uuid.UUID {
	// Create a catalog to hold the controls (Control has a composite PK: CatalogID + ID).
	catalogID := uuid.New()
	controls := make([]relational.Control, 0, len(controlIDs))
	for _, cid := range controlIDs {
		controls = append(controls, relational.Control{
			CatalogID: catalogID,
			ID:        cid,
			Title:     cid,
		})
	}
	catalog := relational.Catalog{
		UUIDModel: relational.UUIDModel{ID: &catalogID},
		Metadata: relational.Metadata{
			Title:        title + " Catalog",
			Version:      "1.0.0",
			OscalVersion: "1.1.3",
		},
		Controls: controls,
	}
	suite.Require().NoError(suite.DB.Create(&catalog).Error)

	// Create the profile and associate the controls via GORM.
	profileID := uuid.New()
	profile := relational.Profile{
		UUIDModel: relational.UUIDModel{ID: &profileID},
		Metadata: relational.Metadata{
			Title:        title,
			Version:      "1.0.0",
			OscalVersion: "1.1.3",
		},
		Controls: controls,
	}
	suite.Require().NoError(suite.DB.Create(&profile).Error)

	return profileID
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func (suite *SSPProfilesIntegrationSuite) TestAddListRemoveProfiles() {
	sspID := suite.createSSP()
	p1 := suite.createProfile("Profile A", []string{"ac-1", "ac-2"})
	p2 := suite.createProfile("Profile B", []string{"ac-3", "ac-4"})

	// --- Add first profile ---
	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/profiles", sspID),
		addProfileRequest{ProfileID: p1.String()})
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, "add first profile: %s", rec.Body.String())

	// --- Add second profile ---
	rec, req = suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/profiles", sspID),
		addProfileRequest{ProfileID: p2.String()})
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, "add second profile: %s", rec.Body.String())

	// --- List profiles — expect both ---
	rec, req = suite.req(http.MethodGet,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/profiles", sspID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	var listResp handler.GenericDataListResponse[profileSummary]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &listResp))
	suite.Require().Len(listResp.Data, 2, "expected two bound profiles")

	ids := map[string]bool{}
	for _, ps := range listResp.Data {
		ids[ps.ID] = true
	}
	suite.True(ids[p1.String()], "profile A should be listed")
	suite.True(ids[p2.String()], "profile B should be listed")

	// --- Duplicate add returns 409 ---
	rec, req = suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/profiles", sspID),
		addProfileRequest{ProfileID: p1.String()})
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusConflict, rec.Code, "duplicate add should return 409")

	// --- Remove first profile ---
	rec, req = suite.req(http.MethodDelete,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/profiles/%s", sspID, p1.String()), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, "remove profile: %s", rec.Body.String())

	// --- List again — expect one ---
	rec, req = suite.req(http.MethodGet,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/profiles", sspID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &listResp))
	suite.Require().Len(listResp.Data, 1, "expected one bound profile after removal")
	suite.Equal(p2.String(), listResp.Data[0].ID)
}

func (suite *SSPProfilesIntegrationSuite) TestGetProfile_LegacyEndpoint_ConflictOnMultiple() {
	sspID := suite.createSSP()
	p1 := suite.createProfile("Profile A", []string{"ac-1"})
	p2 := suite.createProfile("Profile B", []string{"ac-2"})

	// Add two profiles
	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/profiles", sspID),
		addProfileRequest{ProfileID: p1.String()})
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code)

	rec, req = suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/profiles", sspID),
		addProfileRequest{ProfileID: p2.String()})
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code)

	// Legacy GET /profile should return 409 Conflict when multiple profiles are bound
	rec, req = suite.req(http.MethodGet,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/profile", sspID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusConflict, rec.Code, "legacy endpoint should 409 with multiple profiles")
}

func (suite *SSPProfilesIntegrationSuite) TestImplementedRequirements_MultiProfileControlUnion() {
	sspID := suite.createSSP()

	// Profile A has controls ac-1 and ac-2
	p1 := suite.createProfile("Profile A", []string{"ac-1", "ac-2"})
	// Profile B has controls ac-2 (overlap) and ac-3 (unique)
	p2 := suite.createProfile("Profile B", []string{"ac-2", "ac-3"})

	// Bind both profiles
	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/profiles", sspID),
		addProfileRequest{ProfileID: p1.String()})
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code)

	rec, req = suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/profiles", sspID),
		addProfileRequest{ProfileID: p2.String()})
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code)

	// GET implemented-requirements — should include union of {ac-1, ac-2, ac-3}
	rec, req = suite.req(http.MethodGet,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements", sspID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, "get implemented-requirements: %s", rec.Body.String())

	var resp handler.GenericDataListResponse[oscalTypes_1_1_3.ImplementedRequirement]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))

	controlSet := map[string]bool{}
	for _, ir := range resp.Data {
		controlSet[ir.ControlId] = true
	}

	suite.True(controlSet["ac-1"], "union should include ac-1 from profile A")
	suite.True(controlSet["ac-2"], "union should include ac-2 (shared)")
	suite.True(controlSet["ac-3"], "union should include ac-3 from profile B")
}

// TestImplementedRequirements_PreserveCanonicalCasing guards the casing fix:
// when a profile's controls use canonical (mixed-case) IDs, the implemented
// requirements auto-created on profile attach must store that exact casing —
// not a lowercased copy — so downstream catalog/profile resolution by exact
// string keeps matching. It also covers the direct-create hardening: a control
// ID supplied with the "wrong" casing is canonicalized against the bound
// profile's controls before being persisted.
func (suite *SSPProfilesIntegrationSuite) TestImplementedRequirements_PreserveCanonicalCasing() {
	sspID := suite.createSSP()
	// Profile controls use the catalog-canonical casing.
	p1 := suite.createProfile("Canonical Profile", []string{"GD.Sec.C08", "GD.Conf.C01"})

	rec, req := suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/profiles", sspID),
		addProfileRequest{ProfileID: p1.String()})
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code, "add profile: %s", rec.Body.String())

	// The auto-created implemented requirements must keep the canonical casing.
	rec, req = suite.req(http.MethodGet,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements", sspID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code, "get implemented-requirements: %s", rec.Body.String())

	var resp handler.GenericDataListResponse[oscalTypes_1_1_3.ImplementedRequirement]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))

	controlSet := map[string]bool{}
	for _, ir := range resp.Data {
		controlSet[ir.ControlId] = true
	}
	suite.True(controlSet["GD.Sec.C08"], "auto-created IR should preserve canonical casing GD.Sec.C08, got: %v", controlSet)
	suite.True(controlSet["GD.Conf.C01"], "auto-created IR should preserve canonical casing GD.Conf.C01, got: %v", controlSet)
	suite.False(controlSet["gd.sec.c08"], "auto-created IR must not be lowercased")

	// Direct create with mismatched casing is canonicalized against the bound
	// profile's controls: "gd.conf.c01" must be stored as "GD.Conf.C01".
	newReq := oscalTypes_1_1_3.ImplementedRequirement{
		UUID:      uuid.New().String(),
		ControlId: "gd.conf.c01",
	}
	rec, req = suite.req(http.MethodPost,
		fmt.Sprintf("/api/oscal/system-security-plans/%s/control-implementation/implemented-requirements", sspID),
		newReq)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusCreated, rec.Code, "create IR: %s", rec.Body.String())

	var createResp handler.GenericDataResponse[oscalTypes_1_1_3.ImplementedRequirement]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &createResp))
	suite.Equal("GD.Conf.C01", createResp.Data.ControlId,
		"directly-created IR should be canonicalized to the catalog casing")
}
