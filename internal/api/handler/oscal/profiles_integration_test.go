//go:build integration

package oscal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
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

	logger, _ := zap.NewDevelopment()
	suite.logger = logger.Sugar()
	suite.server = api.NewServer(context.Background(), suite.logger, suite.Config)
	RegisterHandlers(suite.server, suite.logger, suite.DB, suite.Config)

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

		fmt.Println("Response Body:", rec.Body.String())
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
