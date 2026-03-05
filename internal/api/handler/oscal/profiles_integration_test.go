//go:build integration

package oscal

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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

var (
	blankProfile = &oscalTypes_1_1_3.Profile{
		UUID: uuid.New().String(),
		Metadata: oscalTypes_1_1_3.Metadata{
			Title:        "Blank Profile",
			Version:      "1.0.0",
			OscalVersion: "1.1.3",
			LastModified: time.Now(),
		},
		Imports: []oscalTypes_1_1_3.Import{},
		Merge:   &oscalTypes_1_1_3.Merge{},
		BackMatter: &oscalTypes_1_1_3.BackMatter{
			Resources: &[]oscalTypes_1_1_3.Resource{},
		},
	}

	sp800_53_profile     = &oscalTypes_1_1_3.Profile{}
	sp800_53_import_href = "#051a77c1-b61d-4995-8275-dacfe688d510"
)

func TestOscalProfileApi(t *testing.T) {
	suite.Run(t, new(ProfileIntegrationSuite))
}

type ProfileIntegrationSuite struct {
	tests.IntegrationTestSuite
	logger *zap.SugaredLogger
	server *api.Server
}

func (suite *ProfileIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()

	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()
	suite.logger = logger.Sugar()
	metrics := api.NewMetricsHandler(context.Background(), suite.logger)
	suite.server = api.NewServer(context.Background(), suite.logger, suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(suite.server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc)

	profileFp, err := os.Open("../../../../testdata/profile_fedramp_low.json")
	suite.Require().NoError(err, "Failed to open profile file")
	defer profileFp.Close()

	oscalProfile := struct {
		Profile oscalTypes_1_1_3.Profile `json:"profile"`
	}{}

	err = json.NewDecoder(profileFp).Decode(&oscalProfile)
	suite.Require().NoError(err, "Failed to unmarshal profile data")

	sp800_53_profile = &oscalProfile.Profile
}

// SeedDatabase seeds the database with a sample OSCAL profile (SP800-53) for testing purposes.
func (suite *ProfileIntegrationSuite) SeedDatabase() {

	profile := &relational.Profile{}
	profile.UnmarshalOscal(*sp800_53_profile)

	err := suite.DB.Create(profile).Error
	suite.Require().NoError(err, "Failed to seed profile into database")
}

func (suite *ProfileIntegrationSuite) TestCreateProfile() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	payload, err := json.Marshal(blankProfile)
	suite.Require().NoError(err, "Failed to marshal profile payload")

	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/oscal/profiles", bytes.NewReader(payload))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)

	suite.Require().Equal(http.StatusCreated, rec.Code, "Expected status code 201 Created")

	var profile *relational.Profile
	err = suite.DB.Find(&profile, "id = ?", blankProfile.UUID).Error
	suite.Require().NoError(err, "Failed to find created profile")

	suite.Require().Equal(blankProfile.UUID, profile.UUIDModel.ID.String(), "Expected profile UUID to match")
}

func (suite *ProfileIntegrationSuite) TestDuplicateCreate() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	payload, err := json.Marshal(blankProfile)
	suite.Require().NoError(err, "Failed to marshal profile payload")

	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/oscal/profiles", bytes.NewReader(payload))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)

	suite.Require().Equal(http.StatusCreated, rec.Code, "Expected status code 201 Created")

	// Attempt to create the same profile again
	rec = httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)

	suite.Require().Equal(http.StatusBadRequest, rec.Code, "Expected status code 400 Bad Request")
}

func (suite *ProfileIntegrationSuite) TestListProfile() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	suite.SeedDatabase()

	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/oscal/profiles", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

	suite.server.E().ServeHTTP(rec, req)

	suite.Require().Equal(http.StatusOK, rec.Code, "Expected status code 200 OK")

	var response handler.GenericDataResponse[[]*relational.Profile]
	err = json.NewDecoder(rec.Body).Decode(&response)
	suite.Require().NoError(err, "Failed to decode response body")
	suite.Require().NotEmpty(response.Data, "Expected profiles to be returned")
	suite.Require().Len(response.Data, 1, "Expected one profile to be returned")
}

func (suite *ProfileIntegrationSuite) TestGetProfile() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	suite.SeedDatabase()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	sp800_uuid := sp800_53_profile.UUID

	suite.Run("Get existing profile", func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/oscal/profiles/"+sp800_uuid, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusOK, rec.Code, "Expected status code 200 OK")

		response := handler.GenericDataResponse[struct {
			UUID     uuid.UUID                 `json:"uuid"`
			Metadata oscalTypes_1_1_3.Metadata `json:"metadata"`
		}]{}
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response body")
		suite.Require().NotNil(response.Data.UUID, "Expected UUID data to be returned")
		suite.Require().NotNil(response.Data.Metadata, "Expected metadata to be returned")
		suite.Require().Equal(sp800_uuid, response.Data.UUID.String(), "Expected profile UUID to match")
	})

	suite.Run("Get non-existing profile", func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/oscal/profiles/df497cf2-c84b-4486-bb40-6100efe734fc", nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusNotFound, rec.Code, "Expected status code 404 Not Found")
	})

	suite.Run("Get profile with invalid UUID", func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/oscal/profiles/invalid-uuid", nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusBadRequest, rec.Code, "Expected status code 400 Bad Request")
		suite.Require().Contains(rec.Body.String(), "invalid UUID length", "Expected error message for invalid UUID")
	})
}

func (suite *ProfileIntegrationSuite) TestListImports() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	suite.SeedDatabase()

	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	sp800_uuid := sp800_53_profile.UUID

	suite.Run("List imports for existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_uuid + "/imports"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusOK, rec.Code, "Expected status code 200 OK")

		var response handler.GenericDataListResponse[oscalTypes_1_1_3.Import]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response body")
		// No strict assertion on length, as testdata may vary, but should be a slice
		suite.Require().NotNil(response.Data, "Expected imports to be returned")
	})

	suite.Run("List imports for non-existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/df497cf2-c84b-4486-bb40-6100efe734fc/imports"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusNotFound, rec.Code, "Expected status code 404 Not Found")
	})

	suite.Run("List imports with invalid UUID", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/invalid-uuid/imports"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusBadRequest, rec.Code, "Expected status code 400 Bad Request")
		suite.Require().Contains(rec.Body.String(), "invalid UUID length", "Expected error message for invalid UUID")
	})
}

func (suite *ProfileIntegrationSuite) TestGetBackmatter() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	suite.SeedDatabase()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	sp800_uuid := sp800_53_profile.UUID

	suite.Run("Get backmatter for existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_uuid + "/back-matter"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusOK, rec.Code, "Expected status code 200 OK")

		var response handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response body")
		// BackMatter may be empty, but should be present
		suite.Require().NotNil(response.Data, "Expected backmatter to be returned")
	})

	suite.Run("Get backmatter for non-existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/df497cf2-c84b-4486-bb40-6100efe734fc/back-matter"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusNotFound, rec.Code, "Expected status code 404 Not Found")
	})

	suite.Run("Get backmatter with invalid UUID", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/invalid-uuid/back-matter"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusBadRequest, rec.Code, "Expected status code 500 Internal Server Error")
		suite.Require().Contains(rec.Body.String(), "invalid UUID length", "Expected error message for invalid UUID")
	})
}

func (suite *ProfileIntegrationSuite) TestGetModify() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	suite.SeedDatabase()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	sp800_uuid := sp800_53_profile.UUID

	suite.Run("Get modify for existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_uuid + "/modify"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusOK, rec.Code, "Expected status code 200 OK")

		var response handler.GenericDataResponse[oscalTypes_1_1_3.Modify]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response body")
		// Modify may be empty, but should be present
		suite.Require().NotNil(response.Data, "Expected modify to be returned")
	})

	suite.Run("Get modify for non-existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/df497cf2-c84b-4486-bb40-6100efe734fc/modify"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusNotFound, rec.Code, "Expected status code 404 Not Found")
	})

	suite.Run("Get modify with invalid UUID", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/invalid-uuid/modify"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusBadRequest, rec.Code, "Expected status code 500 Internal Server Error")
		suite.Require().Contains(rec.Body.String(), "invalid UUID length", "Expected error message for invalid UUID")
	})
}

func (suite *ProfileIntegrationSuite) TestGetMerge() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	suite.SeedDatabase()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	sp800_uuid := sp800_53_profile.UUID

	suite.Run("Get merge for existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_uuid + "/merge"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusOK, rec.Code, "Expected status code 200 OK")

		var response handler.GenericDataResponse[oscalTypes_1_1_3.Merge]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response body")
		// Merge may be empty, but should be present
		suite.Require().NotNil(response.Data, "Expected merge to be returned")
	})

	suite.Run("Get merge for non-existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/df497cf2-c84b-4486-bb40-6100efe734fc/merge"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusNotFound, rec.Code, "Expected status code 404 Not Found")
	})

	suite.Run("Get merge with invalid UUID", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/invalid-uuid/merge"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusBadRequest, rec.Code, "Expected status code 500 Internal Server Error")
		suite.Require().Contains(rec.Body.String(), "invalid UUID length", "Expected error message for invalid UUID")
	})
}

func (suite *ProfileIntegrationSuite) TestGetImport() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	suite.SeedDatabase()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	sp800_uuid := sp800_53_profile.UUID

	suite.Run("Get import for existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_uuid + "/imports/" + sp800_53_import_href
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusOK, rec.Code, "Expected status code 200 OK")

		var response handler.GenericDataResponse[oscalTypes_1_1_3.Import]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response body")
		suite.Require().NotNil(response.Data, "Expected import data to be returned")
	})

	suite.Run("Get import for non-existing href", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_uuid + "/imports/test-href"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusNotFound, rec.Code, "Expected status code 404 Not Found")
	})

	suite.Run("Get import with invalid UUID", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/invalid-uuid/imports/" + sp800_53_import_href
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusBadRequest, rec.Code, "Expected status code 400 Bad Request")
		suite.Require().Contains(rec.Body.String(), "invalid UUID length", "Expected error message for invalid UUID")
	})
}

func (suite *ProfileIntegrationSuite) TestAddImport() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	suite.SeedDatabase()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	suite.Run("Try to add an already existing catalog", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_53_profile.UUID + "/imports/add"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`{
			"type": "catalog",
			"uuid": "9b0c9c43-2722-4bbb-b132-13d34fb94d45"
		}`)))

		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusConflict, rec.Code, "Expected status code 409 Conflict")
		suite.Require().Contains(rec.Body.String(), "import already exists", "Expected error message for existing import")
	})

	suite.Run("Add a new import with unknown catalog UUID", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_53_profile.UUID + "/imports/add"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`{
			"type": "catalog",
			"uuid": "00000000-0000-0000-0000-000000000000"
		}`)))

		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusNotFound, rec.Code, "Expected status code 404 Not Found")
		suite.Require().Contains(rec.Body.String(), "record not found", "Expected error message for non-existing catalog")
	})

	suite.Run("Add a new import with valid catalog UUID", func() {
		catalog := &relational.Catalog{
			Metadata: relational.Metadata{
				Title: "Test Catalog",
			},
		}

		if err := suite.DB.Create(catalog).Error; err != nil {
			suite.T().Fatalf("Failed to create test catalog: %v", err)
		}

		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_53_profile.UUID + "/imports/add"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`{
			"type": "catalog",
			"uuid": "`+catalog.UUIDModel.ID.String()+`"
		}`)))

		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusCreated, rec.Code, "Expected status code 201 Created")

		var response handler.GenericDataResponse[oscalTypes_1_1_3.Import]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response body")
	})
}

func (suite *ProfileIntegrationSuite) TestUpdateImport() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	suite.SeedDatabase()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	sp800_uuid := sp800_53_profile.UUID
	import_href := sp800_53_import_href

	suite.Run("Update import for existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_uuid + "/imports/" + import_href
		updateBody := `{"href": "` + import_href + `", "include-controls": [{"with-ids": ["ac-1"]}], "exclude-controls": []}`
		req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader([]byte(updateBody)))
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusOK, rec.Code, "Expected status code 200 OK")
		var response handler.GenericDataResponse[oscalTypes_1_1_3.Import]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response body")
		suite.Require().Equal(import_href, response.Data.Href, "Expected href to match")
	})

	suite.Run("Update import with mismatched href", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_uuid + "/imports/" + import_href
		updateBody := `{"href": "wrong-href", "include-controls": [], "exclude-controls": []}`
		req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader([]byte(updateBody)))
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusBadRequest, rec.Code, "Expected status code 400 Bad Request")
		suite.Require().Contains(rec.Body.String(), "href in request body does not match URL parameter")
	})

	suite.Run("Update import for non-existing href", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_uuid + "/imports/non-existent-href"
		updateBody := `{"href": "non-existent-href", "include-controls": [], "exclude-controls": []}`
		req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader([]byte(updateBody)))
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusNotFound, rec.Code, "Expected status code 404 Not Found")
	})
}

func (suite *ProfileIntegrationSuite) TestBuildByPropsCreatesImportAndControls() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	// Seed a minimal catalog with one technical control
	catID := uuid.New()
	catalog := &relational.Catalog{
		UUIDModel: relational.UUIDModel{ID: &catID},
		Metadata:  relational.Metadata{Title: "Prop Match Test Catalog"},
		Controls: []relational.Control{
			{
				ID:        "ac-1",
				Title:     "Access Control 1",
				CatalogID: catID,
				Props:     []relational.Prop{{Name: "class", Value: "technical"}},
			},
		},
	}
	err = suite.DB.Create(catalog).Error
	suite.Require().NoError(err, "Failed to seed test catalog")

	// Build profile by props targeting the seeded catalog and rule
	body := map[string]any{
		"catalog-id":     catID.String(),
		"match-strategy": "all",
		"rules": []map[string]string{
			{"name": "class", "operator": "equals", "value": "technical"},
		},
		"title":   "Prop-Matched Profile",
		"version": "1.0.0",
	}
	payload, _ := json.Marshal(body)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/oscal/profiles/build-props", bytes.NewReader(payload))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusCreated, rec.Code, "Expected 201 from build-by-props")

	var response handler.GenericDataResponse[struct {
		ProfileID  uuid.UUID                `json:"profile-id"`
		ControlIDs []string                 `json:"control-ids"`
		Profile    oscalTypes_1_1_3.Profile `json:"profile"`
	}]
	err = json.NewDecoder(rec.Body).Decode(&response)
	suite.Require().NoError(err, "Failed to decode build-by-props response")
	suite.Require().Len(response.Data.ControlIDs, 1, "Expected one matched control")
	suite.Require().Equal("ac-1", response.Data.ControlIDs[0], "Expected matched control to be ac-1")

	// Verify persisted import/back-matter can be listed
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/oscal/profiles/"+response.Data.ProfileID.String()+"/imports", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code, "Expected 200 listing imports")
	var list handler.GenericDataListResponse[oscalTypes_1_1_3.Import]
	err = json.NewDecoder(rec.Body).Decode(&list)
	suite.Require().NoError(err)
	suite.Require().Len(list.Data, 1, "Expected a single import")
}

func (suite *ProfileIntegrationSuite) TestBuildByPropsOperators() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	// Seed a catalog with multiple controls with different props
	catID := uuid.New()
	catalog := &relational.Catalog{
		UUIDModel: relational.UUIDModel{ID: &catID},
		Metadata:  relational.Metadata{Title: "Operator Test Catalog"},
		Controls: []relational.Control{
			{
				ID:        "ac-1",
				Title:     "Access Control 1",
				CatalogID: catID,
				Props: []relational.Prop{
					{Name: "class", Value: "technical"},
					{Name: "priority", Value: "P1"},
				},
			},
			{
				ID:        "ac-2",
				Title:     "Access Control 2",
				CatalogID: catID,
				Props: []relational.Prop{
					{Name: "class", Value: "operational"},
					{Name: "priority", Value: "P2"},
				},
			},
			{
				ID:        "ac-3",
				Title:     "Access Control 3",
				CatalogID: catID,
				Props: []relational.Prop{
					{Name: "class", Value: "management"},
					{Name: "priority", Value: "P1-critical"},
				},
			},
			{
				ID:        "sc-1",
				Title:     "System and Communications Protection 1",
				CatalogID: catID,
				Props: []relational.Prop{
					{Name: "class", Value: "technical"},
					{Name: "family", Value: "SC"},
				},
			},
		},
	}
	err = suite.DB.Create(catalog).Error
	suite.Require().NoError(err, "Failed to seed test catalog")

	suite.Run("Regex operator - match controls with priority starting with P1", func() {
		body := map[string]any{
			"catalog-id":     catID.String(),
			"match-strategy": "any",
			"rules": []map[string]string{
				{"name": "priority", "operator": "regex", "value": "^P1"},
			},
			"title":   "Regex Test Profile",
			"version": "1.0.0",
		}
		payload, _ := json.Marshal(body)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/oscal/profiles/build-props", bytes.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusCreated, rec.Code, "Expected 201 from build-by-props")

		var response handler.GenericDataResponse[struct {
			ProfileID  uuid.UUID                `json:"profile-id"`
			ControlIDs []string                 `json:"control-ids"`
			Profile    oscalTypes_1_1_3.Profile `json:"profile"`
		}]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response")
		suite.Require().Len(response.Data.ControlIDs, 2, "Expected two matched controls (ac-1, ac-3)")
		suite.Require().Contains(response.Data.ControlIDs, "ac-1")
		suite.Require().Contains(response.Data.ControlIDs, "ac-3")
	})

	suite.Run("In operator - match controls with class in list", func() {
		body := map[string]any{
			"catalog-id":     catID.String(),
			"match-strategy": "any",
			"rules": []map[string]string{
				{"name": "class", "operator": "in", "value": "technical,operational"},
			},
			"title":   "In Operator Test Profile",
			"version": "1.0.0",
		}
		payload, _ := json.Marshal(body)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/oscal/profiles/build-props", bytes.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusCreated, rec.Code, "Expected 201 from build-by-props")

		var response handler.GenericDataResponse[struct {
			ProfileID  uuid.UUID                `json:"profile-id"`
			ControlIDs []string                 `json:"control-ids"`
			Profile    oscalTypes_1_1_3.Profile `json:"profile"`
		}]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response")
		suite.Require().Len(response.Data.ControlIDs, 3, "Expected three matched controls (ac-1, ac-2, sc-1)")
		suite.Require().Contains(response.Data.ControlIDs, "ac-1")
		suite.Require().Contains(response.Data.ControlIDs, "ac-2")
		suite.Require().Contains(response.Data.ControlIDs, "sc-1")
	})

	suite.Run("Contains operator - match controls with class containing 'tech'", func() {
		body := map[string]any{
			"catalog-id":     catID.String(),
			"match-strategy": "any",
			"rules": []map[string]string{
				{"name": "class", "operator": "contains", "value": "tech"},
			},
			"title":   "Contains Operator Test Profile",
			"version": "1.0.0",
		}
		payload, _ := json.Marshal(body)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/oscal/profiles/build-props", bytes.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusCreated, rec.Code, "Expected 201 from build-by-props")

		var response handler.GenericDataResponse[struct {
			ProfileID  uuid.UUID                `json:"profile-id"`
			ControlIDs []string                 `json:"control-ids"`
			Profile    oscalTypes_1_1_3.Profile `json:"profile"`
		}]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response")
		suite.Require().Len(response.Data.ControlIDs, 2, "Expected two matched controls (ac-1, sc-1)")
		suite.Require().Contains(response.Data.ControlIDs, "ac-1")
		suite.Require().Contains(response.Data.ControlIDs, "sc-1")
	})

	suite.Run("Invalid regex pattern returns 400", func() {
		body := map[string]any{
			"catalog-id":     catID.String(),
			"match-strategy": "any",
			"rules": []map[string]string{
				{"name": "priority", "operator": "regex", "value": "[invalid(regex"},
			},
			"title":   "Invalid Regex Test",
			"version": "1.0.0",
		}
		payload, _ := json.Marshal(body)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/oscal/profiles/build-props", bytes.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusBadRequest, rec.Code, "Expected 400 for invalid regex")
		suite.Require().Contains(rec.Body.String(), "invalid regex pattern")
	})

	suite.Run("Match strategy 'all' requires all rules to match", func() {
		body := map[string]any{
			"catalog-id":     catID.String(),
			"match-strategy": "all",
			"rules": []map[string]string{
				{"name": "class", "operator": "equals", "value": "technical"},
				{"name": "priority", "operator": "equals", "value": "P1"},
			},
			"title":   "Match All Strategy Test",
			"version": "1.0.0",
		}
		payload, _ := json.Marshal(body)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/oscal/profiles/build-props", bytes.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusCreated, rec.Code, "Expected 201 from build-by-props")

		var response handler.GenericDataResponse[struct {
			ProfileID  uuid.UUID                `json:"profile-id"`
			ControlIDs []string                 `json:"control-ids"`
			Profile    oscalTypes_1_1_3.Profile `json:"profile"`
		}]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response")
		suite.Require().Len(response.Data.ControlIDs, 1, "Expected only one control matching both rules (ac-1)")
		suite.Require().Equal("ac-1", response.Data.ControlIDs[0])
	})

	suite.Run("Match strategy 'any' matches if any rule matches", func() {
		body := map[string]any{
			"catalog-id":     catID.String(),
			"match-strategy": "any",
			"rules": []map[string]string{
				{"name": "class", "operator": "equals", "value": "technical"},
				{"name": "family", "operator": "equals", "value": "SC"},
			},
			"title":   "Match Any Strategy Test",
			"version": "1.0.0",
		}
		payload, _ := json.Marshal(body)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/oscal/profiles/build-props", bytes.NewReader(payload))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusCreated, rec.Code, "Expected 201 from build-by-props")

		var response handler.GenericDataResponse[struct {
			ProfileID  uuid.UUID                `json:"profile-id"`
			ControlIDs []string                 `json:"control-ids"`
			Profile    oscalTypes_1_1_3.Profile `json:"profile"`
		}]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response")
		suite.Require().Len(response.Data.ControlIDs, 2, "Expected two controls (ac-1 and sc-1)")
		suite.Require().Contains(response.Data.ControlIDs, "ac-1")
		suite.Require().Contains(response.Data.ControlIDs, "sc-1")
	})
}

func (suite *ProfileIntegrationSuite) TestDeleteImport() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	suite.SeedDatabase()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	sp800_uuid := sp800_53_profile.UUID
	import_href := sp800_53_import_href

	suite.Run("Delete import for existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_uuid + "/imports/" + import_href
		req := httptest.NewRequest(http.MethodDelete, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusNoContent, rec.Code, "Expected status code 204 No Content")
	})

	suite.Run("Delete import for non-existing href", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_uuid + "/imports/non-existent-href"
		req := httptest.NewRequest(http.MethodDelete, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusNotFound, rec.Code, "Expected status code 404 Not Found")
	})
}

func (suite *ProfileIntegrationSuite) TestUpdateMerge() {
	suite.IntegrationTestSuite.Migrator.Refresh()
	suite.SeedDatabase()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	sp800_uuid := sp800_53_profile.UUID

	suite.Run("Update merge for existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + sp800_uuid + "/merge"
		updateBody := `{"strategy": "keep", "as-is": true}`
		req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader([]byte(updateBody)))
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusOK, rec.Code, "Expected status code 200 OK")
		var response handler.GenericDataResponse[oscalTypes_1_1_3.Merge]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response body")
		// Remove any assertion on response.Data.Strategy, as the Merge struct does not have a Strategy field. Only assert on fields that exist, such as AsIs, Combine, or Flat.
	})

	suite.Run("Update merge for non-existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/df497cf2-c84b-4486-bb40-6100efe734fc/merge"
		updateBody := `{"strategy": "keep", "as-is": true}`
		req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader([]byte(updateBody)))
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusNotFound, rec.Code, "Expected status code 404 Not Found")
	})
}

func (suite *ProfileIntegrationSuite) TestResolved() {
	suite.IntegrationTestSuite.Migrator.Refresh()

	// 1. Create a Catalog with some controls
	catalog := &relational.Catalog{
		Metadata: relational.Metadata{
			Title: "Test Catalog for Resolution",
		},
	}
	suite.Require().NoError(suite.DB.Create(catalog).Error)

	control1 := relational.Control{
		ID:        "CNTL-1",
		CatalogID: *catalog.UUIDModel.ID,
		Title:     "Control 1",
	}
	control2 := relational.Control{
		ID:        "CNTL-2",
		CatalogID: *catalog.UUIDModel.ID,
		Title:     "Control 2",
	}
	suite.Require().NoError(suite.DB.Create(&control1).Error)
	suite.Require().NoError(suite.DB.Create(&control2).Error)

	// 2. Create a Profile and link controls
	profile := &relational.Profile{
		Metadata: relational.Metadata{
			Title: "Resolved Profile",
		},
		Controls: []relational.Control{control1, control2},
	}
	suite.Require().NoError(suite.DB.Create(profile).Error)

	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	suite.Run("Get resolved profile as catalog", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + profile.UUIDModel.ID.String() + "/resolved"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)

		suite.Require().Equal(http.StatusOK, rec.Code, "Expected status code 200 OK")

		var response handler.GenericDataResponse[oscalTypes_1_1_3.Catalog]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response body")

		suite.Require().NotNil(response.Data.Metadata, "Expected metadata in resolved catalog")
		suite.Require().Equal("Resolved Profile", response.Data.Metadata.Title, "Expected title to match profile title")
		suite.Require().NotNil(response.Data.Controls, "Expected controls in resolved catalog")
		suite.Require().Len(*response.Data.Controls, 2, "Expected 2 controls in resolved catalog")

		controlIDs := []string{(*response.Data.Controls)[0].ID, (*response.Data.Controls)[1].ID}
		suite.Require().Contains(controlIDs, "CNTL-1")
		suite.Require().Contains(controlIDs, "CNTL-2")
	})

	suite.Run("Resolved with non-existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + uuid.New().String() + "/resolved"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusNotFound, rec.Code, "Expected status code 404 Not Found")
	})

	suite.Run("Resolved with invalid UUID", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/invalid-uuid/resolved"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusBadRequest, rec.Code, "Expected status code 400 Bad Request")
	})
}

func (suite *ProfileIntegrationSuite) TestComplianceProgress() {
	suite.IntegrationTestSuite.Migrator.Refresh()

	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	catalog := &relational.Catalog{
		Metadata: relational.Metadata{Title: "Compliance Progress Catalog"},
	}
	suite.Require().NoError(suite.DB.Create(catalog).Error)

	controlSatisfied := relational.Control{ID: "CTRL-SAT", CatalogID: *catalog.ID, Title: "Satisfied Control"}
	controlNotSatisfied := relational.Control{ID: "CTRL-NS", CatalogID: *catalog.ID, Title: "Not Satisfied Control"}
	controlUnknown := relational.Control{ID: "CTRL-UNK", CatalogID: *catalog.ID, Title: "Unknown Control"}

	suite.Require().NoError(suite.DB.Create(&controlSatisfied).Error)
	suite.Require().NoError(suite.DB.Create(&controlNotSatisfied).Error)
	suite.Require().NoError(suite.DB.Create(&controlUnknown).Error)

	filterSatisfied := relational.Filter{
		Name: "Satisfied Filter",
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

	filterNotSatisfied := relational.Filter{
		Name: "Not Satisfied Filter",
		Filter: datatypes.NewJSONType(labelfilter.Filter{
			Scope: &labelfilter.Scope{
				Condition: &labelfilter.Condition{
					Label:    "provider",
					Operator: "=",
					Value:    "gcp",
				},
			},
		}),
	}

	suite.Require().NoError(suite.DB.Create(&filterSatisfied).Error)
	suite.Require().NoError(suite.DB.Create(&filterNotSatisfied).Error)
	suite.Require().NoError(suite.DB.Model(&controlSatisfied).Association("Filters").Append(&filterSatisfied))
	suite.Require().NoError(suite.DB.Model(&controlNotSatisfied).Association("Filters").Append(&filterNotSatisfied))

	profile := &relational.Profile{
		Metadata: relational.Metadata{Title: "Compliance Progress Profile"},
		Controls: []relational.Control{controlSatisfied, controlNotSatisfied, controlUnknown},
	}
	suite.Require().NoError(suite.DB.Create(profile).Error)

	now := time.Now().UTC()
	evidenceRecords := []relational.Evidence{
		{
			UUID:   uuid.New(),
			Title:  "AWS satisfied evidence",
			Start:  now.Add(-time.Hour),
			End:    now.Add(-time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
			Labels: []relational.Labels{{Name: "provider", Value: "aws"}},
		},
		{
			UUID:   uuid.New(),
			Title:  "GCP not satisfied evidence",
			Start:  now.Add(-time.Hour),
			End:    now.Add(-time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied"}),
			Labels: []relational.Labels{{Name: "provider", Value: "gcp"}},
		},
		{
			UUID:   uuid.New(),
			Title:  "Non-matching evidence",
			Start:  now.Add(-time.Hour),
			End:    now.Add(-time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
			Labels: []relational.Labels{{Name: "provider", Value: "azure"}},
		},
	}
	suite.Require().NoError(suite.DB.Create(&evidenceRecords).Error)

	suite.Run("Returns aggregated compliance progress", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + profile.ID.String() + "/compliance-progress"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusOK, rec.Code, "Expected status code 200 OK")

		var response handler.GenericDataResponse[ProfileComplianceProgress]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response body")

		suite.Require().Equal(profile.ID.String(), response.Data.Scope.ID.String())
		suite.Require().Equal("profile", response.Data.Scope.Type)
		suite.Require().Equal("Compliance Progress Profile", response.Data.Scope.Title)

		suite.Require().Equal(3, response.Data.Summary.TotalControls)
		suite.Require().Equal(1, response.Data.Summary.Satisfied)
		suite.Require().Equal(1, response.Data.Summary.NotSatisfied)
		suite.Require().Equal(1, response.Data.Summary.Unknown)
		suite.Require().Equal(33, response.Data.Summary.CompliancePct)
		suite.Require().Equal(67, response.Data.Summary.AssessedPct)

		suite.Require().Len(response.Data.Groups, 0)
		suite.Require().Len(response.Data.Controls, 3)

		controlsByID := make(map[string]ProfileComplianceControl, len(response.Data.Controls))
		for _, control := range response.Data.Controls {
			controlsByID[control.ControlID] = control
		}

		suite.Require().Equal("satisfied", controlsByID["CTRL-SAT"].ComputedStatus)
		suite.Require().Equal("not-satisfied", controlsByID["CTRL-NS"].ComputedStatus)
		suite.Require().Equal("unknown", controlsByID["CTRL-UNK"].ComputedStatus)
	})

	suite.Run("Allows omitting controls from response", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + profile.ID.String() + "/compliance-progress?includeControls=false"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusOK, rec.Code, "Expected status code 200 OK")

		var response handler.GenericDataResponse[ProfileComplianceProgress]
		err = json.NewDecoder(rec.Body).Decode(&response)
		suite.Require().NoError(err, "Failed to decode response body")
		suite.Require().Len(response.Data.Controls, 0)
		suite.Require().Equal(3, response.Data.Summary.TotalControls)
	})

	suite.Run("Returns 404 for non-existing profile", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + uuid.New().String() + "/compliance-progress"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusNotFound, rec.Code, "Expected status code 404 Not Found")
	})

	suite.Run("Returns 400 for invalid profile UUID", func() {
		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/invalid-uuid/compliance-progress"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusBadRequest, rec.Code, "Expected status code 400 Bad Request")
	})
}

func (suite *ProfileIntegrationSuite) TestComplianceProgressEdgeCases() {
	suite.IntegrationTestSuite.Migrator.Refresh()

	token, err := suite.GetAuthToken()
	suite.Require().NoError(err, "Failed to get auth token")

	suite.Run("Profile with zero controls returns empty summary", func() {
		emptyProfile := &relational.Profile{
			Metadata: relational.Metadata{Title: "Empty Profile"},
		}
		suite.Require().NoError(suite.DB.Create(emptyProfile).Error)

		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + emptyProfile.ID.String() + "/compliance-progress"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusOK, rec.Code)

		var response handler.GenericDataResponse[ProfileComplianceProgress]
		suite.Require().NoError(json.NewDecoder(rec.Body).Decode(&response))

		suite.Require().Equal(0, response.Data.Summary.TotalControls)
		suite.Require().Equal(0, response.Data.Summary.Satisfied)
		suite.Require().Equal(0, response.Data.Summary.NotSatisfied)
		suite.Require().Equal(0, response.Data.Summary.Unknown)
		suite.Require().Equal(0, response.Data.Summary.CompliancePct)
		suite.Require().Nil(response.Data.Summary.ImplementedTotal, "implementedControls should be absent when no sspId requested")
		suite.Require().Len(response.Data.Controls, 0)
		suite.Require().Len(response.Data.Groups, 0)
	})

	suite.Run("Control with no linked filters reports unknown status", func() {
		cat := &relational.Catalog{Metadata: relational.Metadata{Title: "Unfiltered Catalog"}}
		suite.Require().NoError(suite.DB.Create(cat).Error)

		ctrl := relational.Control{ID: "CTRL-NOFILTER", CatalogID: *cat.ID, Title: "No Filter Control"}
		suite.Require().NoError(suite.DB.Create(&ctrl).Error)

		p := &relational.Profile{
			Metadata: relational.Metadata{Title: "No Filter Profile"},
			Controls: []relational.Control{ctrl},
		}
		suite.Require().NoError(suite.DB.Create(p).Error)

		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + p.ID.String() + "/compliance-progress"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusOK, rec.Code)

		var response handler.GenericDataResponse[ProfileComplianceProgress]
		suite.Require().NoError(json.NewDecoder(rec.Body).Decode(&response))

		suite.Require().Equal(1, response.Data.Summary.TotalControls)
		suite.Require().Equal(0, response.Data.Summary.Satisfied)
		suite.Require().Equal(0, response.Data.Summary.NotSatisfied)
		suite.Require().Equal(1, response.Data.Summary.Unknown)
		suite.Require().Len(response.Data.Controls, 1)
		suite.Require().Equal("unknown", response.Data.Controls[0].ComputedStatus)
	})

	suite.Run("Duplicate control IDs across different catalogs are tracked separately", func() {
		catA := &relational.Catalog{Metadata: relational.Metadata{Title: "Catalog A"}}
		catB := &relational.Catalog{Metadata: relational.Metadata{Title: "Catalog B"}}
		suite.Require().NoError(suite.DB.Create(catA).Error)
		suite.Require().NoError(suite.DB.Create(catB).Error)

		ctrlA := relational.Control{ID: "CTRL-SHARED", CatalogID: *catA.ID, Title: "Shared Control from A"}
		ctrlB := relational.Control{ID: "CTRL-SHARED", CatalogID: *catB.ID, Title: "Shared Control from B"}
		suite.Require().NoError(suite.DB.Create(&ctrlA).Error)
		suite.Require().NoError(suite.DB.Create(&ctrlB).Error)

		p := &relational.Profile{
			Metadata: relational.Metadata{Title: "Cross-Catalog Profile"},
			Controls: []relational.Control{ctrlA, ctrlB},
		}
		suite.Require().NoError(suite.DB.Create(p).Error)

		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + p.ID.String() + "/compliance-progress"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusOK, rec.Code)

		var response handler.GenericDataResponse[ProfileComplianceProgress]
		suite.Require().NoError(json.NewDecoder(rec.Body).Decode(&response))

		// Both controls have the same controlId but different catalogIds — they must each be counted
		suite.Require().Equal(2, response.Data.Summary.TotalControls, "Controls with same ID but different catalogs must be counted separately")
		suite.Require().Len(response.Data.Controls, 2)

		catalogIDs := make(map[string]struct{}, 2)
		for _, c := range response.Data.Controls {
			suite.Require().Equal("CTRL-SHARED", c.ControlID)
			catalogIDs[c.CatalogID.String()] = struct{}{}
		}
		suite.Require().Len(catalogIDs, 2, "Each entry must have a distinct catalogId")
	})

	suite.Run("sspId scope reports implemented and unimplemented controls", func() {
		cat := &relational.Catalog{Metadata: relational.Metadata{Title: "SSP Catalog"}}
		suite.Require().NoError(suite.DB.Create(cat).Error)

		ctrlImpl := relational.Control{ID: "CTRL-IMPL", CatalogID: *cat.ID, Title: "Implemented Control"}
		ctrlUnimpl := relational.Control{ID: "CTRL-UNIMPL", CatalogID: *cat.ID, Title: "Unimplemented Control"}
		suite.Require().NoError(suite.DB.Create(&ctrlImpl).Error)
		suite.Require().NoError(suite.DB.Create(&ctrlUnimpl).Error)

		p := &relational.Profile{
			Metadata: relational.Metadata{Title: "SSP Profile"},
			Controls: []relational.Control{ctrlImpl, ctrlUnimpl},
		}
		suite.Require().NoError(suite.DB.Create(p).Error)

		ssp := &relational.SystemSecurityPlan{
			Metadata: relational.Metadata{Title: "Test SSP"},
			ControlImplementation: relational.ControlImplementation{
				ImplementedRequirements: []relational.ImplementedRequirement{
					{
						ControlId: "CTRL-IMPL",
						Statements: []relational.Statement{
							{StatementId: "CTRL-IMPL_smt.a"},
						},
					},
				},
			},
		}
		suite.Require().NoError(suite.DB.Create(ssp).Error)

		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + p.ID.String() + "/compliance-progress?sspId=" + ssp.ID.String()
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusOK, rec.Code)

		var response handler.GenericDataResponse[ProfileComplianceProgress]
		suite.Require().NoError(json.NewDecoder(rec.Body).Decode(&response))

		suite.Require().Equal(2, response.Data.Summary.TotalControls)
		suite.Require().NotNil(response.Data.Summary.ImplementedTotal, "implementedControls must be present when sspId provided")
		suite.Require().Equal(1, *response.Data.Summary.ImplementedTotal)

		suite.Require().NotNil(response.Data.Implementation)
		suite.Require().Equal(1, response.Data.Implementation.ImplementedControls)
		suite.Require().Equal(1, response.Data.Implementation.UnimplementedControls)
		suite.Require().Equal(50, response.Data.Implementation.ImplementationPct)

		implByID := make(map[string]bool, 2)
		for _, c := range response.Data.Controls {
			if c.Implemented != nil {
				implByID[c.ControlID] = *c.Implemented
			}
		}
		suite.Require().True(implByID["CTRL-IMPL"], "CTRL-IMPL should be implemented")
		suite.Require().False(implByID["CTRL-UNIMPL"], "CTRL-UNIMPL should not be implemented")
	})

	suite.Run("Non-existent sspId returns 404", func() {
		cat := &relational.Catalog{Metadata: relational.Metadata{Title: "404 SSP Catalog"}}
		suite.Require().NoError(suite.DB.Create(cat).Error)

		ctrl := relational.Control{ID: "CTRL-ANY", CatalogID: *cat.ID, Title: "Any Control"}
		suite.Require().NoError(suite.DB.Create(&ctrl).Error)

		p := &relational.Profile{
			Metadata: relational.Metadata{Title: "404 SSP Profile"},
			Controls: []relational.Control{ctrl},
		}
		suite.Require().NoError(suite.DB.Create(p).Error)

		rec := httptest.NewRecorder()
		url := "/api/oscal/profiles/" + p.ID.String() + "/compliance-progress?sspId=" + uuid.New().String()
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+*token)

		suite.server.E().ServeHTTP(rec, req)
		suite.Require().Equal(http.StatusNotFound, rec.Code)
	})
}

func (suite *ProfileIntegrationSuite) TestGetControlCatalogFromBuiltProfile() {
	suite.IntegrationTestSuite.Migrator.Refresh()

	// 1. Setup a complex catalog structure: Group -> Subgroup -> Control -> Subcontrol
	catalog := &relational.Catalog{
		Metadata: relational.Metadata{Title: "Complex Catalog"},
	}
	suite.Require().NoError(suite.DB.Create(catalog).Error)

	group := relational.Group{
		ID:        "GRP-1",
		CatalogID: *catalog.UUIDModel.ID,
		Title:     "Root Group",
	}
	suite.Require().NoError(suite.DB.Create(&group).Error)

	subgroup := relational.Group{
		ID:         "SUBGRP-1",
		CatalogID:  *catalog.UUIDModel.ID,
		Title:      "Subgroup",
		ParentID:   &group.ID,
		ParentType: func() *string { s := "groups"; return &s }(),
	}
	suite.Require().NoError(suite.DB.Create(&subgroup).Error)

	control := relational.Control{
		ID:         "CTRL-1",
		CatalogID:  *catalog.UUIDModel.ID,
		Title:      "Parent Control",
		ParentID:   &subgroup.ID,
		ParentType: func() *string { s := "groups"; return &s }(),
	}
	suite.Require().NoError(suite.DB.Create(&control).Error)

	subcontrol := relational.Control{
		ID:         "SUBCTRL-1",
		CatalogID:  *catalog.UUIDModel.ID,
		Title:      "Sub-control",
		ParentID:   &control.ID,
		ParentType: func() *string { s := "controls"; return &s }(),
	}
	suite.Require().NoError(suite.DB.Create(&subcontrol).Error)

	// 2. Create a Profile that only selects the subcontrol
	profile := &relational.Profile{
		Metadata: relational.Metadata{Title: "Profile selecting subcontrol"},
		Controls: []relational.Control{subcontrol},
	}
	suite.Require().NoError(suite.DB.Create(profile).Error)

	// 3. Test resolution
	resolvedCatalog, err := GetControlCatalogFromBuiltProfile(profile, suite.DB)
	suite.Require().NoError(err)
	suite.Require().NotNil(resolvedCatalog)

	// Verify that the hierarchy was rolled up correctly to the root group
	suite.Require().Len(resolvedCatalog.Groups, 1, "Should have 1 root group")
	suite.Require().Equal("GRP-1", resolvedCatalog.Groups[0].ID)
	suite.Require().Len(resolvedCatalog.Groups[0].Groups, 1, "Root group should contain the subgroup")
	suite.Require().Equal("SUBGRP-1", resolvedCatalog.Groups[0].Groups[0].ID)
	suite.Require().Len(resolvedCatalog.Groups[0].Groups[0].Controls, 1, "Subgroup should contain the parent control")
	suite.Require().Equal("CTRL-1", resolvedCatalog.Groups[0].Groups[0].Controls[0].ID)
	suite.Require().Len(resolvedCatalog.Groups[0].Groups[0].Controls[0].Controls, 1, "Parent control should contain the subcontrol")
	suite.Require().Equal("SUBCTRL-1", resolvedCatalog.Groups[0].Groups[0].Controls[0].Controls[0].ID)
}
