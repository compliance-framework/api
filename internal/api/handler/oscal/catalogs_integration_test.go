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

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/compliance-framework/api/internal/tests"
	oscaltypes "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"gorm.io/datatypes"

	"github.com/stretchr/testify/suite"
)

func TestOscalCatalogApi(t *testing.T) {
	suite.Run(t, new(CatalogApiIntegrationSuite))
}

type CatalogApiIntegrationSuite struct {
	tests.IntegrationTestSuite
}

// TestDuplicateCatalogGroupID ensures that when multiple catalogs have group children with the same ID,
// their children endpoints only returned the relevant groups.
// This is to prevent a future regression where searching for child groups in a catalog, would return all the groups
// with a matching ID, rather than only the ones which belong to a catalog.
func (suite *CatalogApiIntegrationSuite) TestDuplicateCatalogGroupID() {
	logger, _ := zap.NewDevelopment()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create two catalogs with the same group ID structure
	catalogs := []oscaltypes.Catalog{
		{
			UUID: "D20DB907-B87D-4D12-8760-D36FDB7A1B31",
			Metadata: oscaltypes.Metadata{
				Title: "Catalog 1",
			},
			Groups: &[]oscaltypes.Group{
				{
					ID:    "G-1",
					Title: "Group 1",
					Groups: &[]oscaltypes.Group{
						{
							ID:    "G-1.1",
							Title: "Group 1.1",
						},
					},
				},
			},
		},
		{
			UUID: "D20DB907-B87D-4D12-8760-D36FDB7A1B32",
			Metadata: oscaltypes.Metadata{
				Title: "Catalog 2",
			},
			Groups: &[]oscaltypes.Group{
				{
					ID:    "G-1",
					Title: "Group 2",
					Groups: &[]oscaltypes.Group{
						{
							ID:    "G-1.1",
							Title: "Group 2.1",
						},
					},
				},
			},
		},
	}
	for _, catalog := range catalogs {
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(catalog)
		req := httptest.NewRequest(http.MethodPost, "/api/oscal/catalogs", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusCreated, rec.Code)
		response := &handler.GenericDataResponse[oscaltypes.Catalog]{}
		err = json.Unmarshal(rec.Body.Bytes(), response)
		suite.Require().NoError(err)
	}

	// Now if we call to check the children for each catalogs' first group, we should only see 1 item

	// The first catalog's group should have the Title Group 1
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/oscal/catalogs/D20DB907-B87D-4D12-8760-D36FDB7A1B31/groups/G-1/groups", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	response := &handler.GenericDataListResponse[oscaltypes.Group]{}
	err = json.Unmarshal(rec.Body.Bytes(), response)
	suite.Require().NoError(err)
	suite.Len(response.Data, 1)
	suite.Equal(response.Data[0].Title, "Group 1.1")

	// The second catalog's group should have the Title Group 1
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/oscal/catalogs/D20DB907-B87D-4D12-8760-D36FDB7A1B32/groups/G-1/groups", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	response = &handler.GenericDataListResponse[oscaltypes.Group]{}
	err = json.Unmarshal(rec.Body.Bytes(), response)
	suite.Require().NoError(err)
	suite.Len(response.Data, 1)
	suite.Equal(response.Data[0].Title, "Group 2.1")
}

// TestDuplicateCatalogControlID ensures that when multiple catalogs have control children with the same ID,
// their children endpoints only returned the relevant controls.
// This is to prevent a future regression where searching for child controls in a catalog, would return all the controls
// with a matching ID, rather than only the ones which belong to a catalog.
func (suite *CatalogApiIntegrationSuite) TestDuplicateCatalogControlID() {
	logger, _ := zap.NewDevelopment()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create two catalogs with the same group ID structure
	catalogs := []oscaltypes.Catalog{
		{
			UUID: "D20DB907-B87D-4D12-8760-D36FDB7A1B31",
			Metadata: oscaltypes.Metadata{
				Title: "Catalog 1",
			},
			Groups: &[]oscaltypes.Group{
				{
					ID:    "G-1",
					Title: "Group 1",
					Controls: &[]oscaltypes.Control{
						{
							ID:    "G-1.1",
							Title: "Control 1.1",
						},
					},
				},
			},
		},
		{
			UUID: "D20DB907-B87D-4D12-8760-D36FDB7A1B32",
			Metadata: oscaltypes.Metadata{
				Title: "Catalog 2",
			},
			Groups: &[]oscaltypes.Group{
				{
					ID:    "G-1",
					Title: "Group 1",
					Controls: &[]oscaltypes.Control{
						{
							ID:    "G-1.1",
							Title: "Control 2.1",
						},
					},
				},
			},
		},
	}
	for _, catalog := range catalogs {
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(catalog)
		req := httptest.NewRequest(http.MethodPost, "/api/oscal/catalogs", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusCreated, rec.Code)
		response := &handler.GenericDataResponse[oscaltypes.Catalog]{}
		err = json.Unmarshal(rec.Body.Bytes(), response)
		suite.Require().NoError(err)
	}

	// Now if we call to check the children for each catalogs' first group, we should only see 1 item

	// The first catalog's group should have the Title Group 1
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/oscal/catalogs/D20DB907-B87D-4D12-8760-D36FDB7A1B31/groups/G-1/controls", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	response := &handler.GenericDataListResponse[oscaltypes.Control]{}
	err = json.Unmarshal(rec.Body.Bytes(), response)
	suite.Require().NoError(err)
	suite.Len(response.Data, 1)
	suite.Equal(response.Data[0].Title, "Control 1.1")

	// The second catalog's group should have the Title Group 1
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/oscal/catalogs/D20DB907-B87D-4D12-8760-D36FDB7A1B32/groups/G-1/controls", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	response = &handler.GenericDataListResponse[oscaltypes.Control]{}
	err = json.Unmarshal(rec.Body.Bytes(), response)
	suite.Require().NoError(err)
	suite.Len(response.Data, 1)
	suite.Equal(response.Data[0].Title, "Control 2.1")
}

// TestDuplicateCatalogChildControlID ensures that when multiple catalogs have control children with the same ID,
// their children endpoints only returned the relevant controls.
// This is to prevent a future regression where searching for child controls in a catalog, would return all the controls
// with a matching ID, rather than only the ones which belong to a catalog.
func (suite *CatalogApiIntegrationSuite) TestDuplicateCatalogChildControlID() {
	logger, _ := zap.NewDevelopment()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create two catalogs with the same group ID structure
	catalogs := []oscaltypes.Catalog{
		{
			UUID: "D20DB907-B87D-4D12-8760-D36FDB7A1B31",
			Metadata: oscaltypes.Metadata{
				Title: "Catalog 1",
			},
			Controls: &[]oscaltypes.Control{
				{
					ID:    "G-1",
					Title: "Group 1",
					Controls: &[]oscaltypes.Control{
						{
							ID:    "G-1.1",
							Title: "Control 1.1",
						},
					},
				},
			},
		},
		{
			UUID: "D20DB907-B87D-4D12-8760-D36FDB7A1B32",
			Metadata: oscaltypes.Metadata{
				Title: "Catalog 2",
			},
			Controls: &[]oscaltypes.Control{
				{
					ID:    "G-1",
					Title: "Group 1",
					Controls: &[]oscaltypes.Control{
						{
							ID:    "G-1.1",
							Title: "Control 2.1",
						},
					},
				},
			},
		},
	}
	for _, catalog := range catalogs {
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(catalog)
		req := httptest.NewRequest(http.MethodPost, "/api/oscal/catalogs", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusCreated, rec.Code)
		response := &handler.GenericDataResponse[oscaltypes.Catalog]{}
		err = json.Unmarshal(rec.Body.Bytes(), response)
		suite.Require().NoError(err)
	}

	// Now if we call to check the children for each catalogs' first group, we should only see 1 item

	// The first catalog's group should have the Title Group 1
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/oscal/catalogs/D20DB907-B87D-4D12-8760-D36FDB7A1B31/controls/G-1/controls", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	response := &handler.GenericDataListResponse[oscaltypes.Control]{}
	err = json.Unmarshal(rec.Body.Bytes(), response)
	suite.Require().NoError(err)
	suite.Len(response.Data, 1)
	suite.Equal(response.Data[0].Title, "Control 1.1")

	// The second catalog's group should have the Title Group 1
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/oscal/catalogs/D20DB907-B87D-4D12-8760-D36FDB7A1B32/controls/G-1/controls", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	response = &handler.GenericDataListResponse[oscaltypes.Control]{}
	err = json.Unmarshal(rec.Body.Bytes(), response)
	suite.Require().NoError(err)
	suite.Len(response.Data, 1)
	suite.Equal(response.Data[0].Title, "Control 2.1")
}

// TestRootGroup ensures that when calling for the root groups on a catalog, only the root groups are returned.
func (suite *CatalogApiIntegrationSuite) TestRootGroup() {
	logger, _ := zap.NewDevelopment()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create two catalogs with the same group ID structure
	catalog := oscaltypes.Catalog{
		UUID: "D20DB907-B87D-4D12-8760-D36FDB7A1B31",
		Metadata: oscaltypes.Metadata{
			Title: "Catalog 1",
		},
		Groups: &[]oscaltypes.Group{
			{
				ID:    "G-1",
				Title: "Group 1",
				Groups: &[]oscaltypes.Group{
					{
						ID:    "G-1.1",
						Title: "Group 1.1",
					},
				},
			},
		},
	}

	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(catalog)
	req := httptest.NewRequest(http.MethodPost, "/api/oscal/catalogs", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	response := &handler.GenericDataResponse[oscaltypes.Catalog]{}
	err = json.Unmarshal(rec.Body.Bytes(), response)
	suite.Require().NoError(err)

	// Now if we call to check the children for each catalogs' first group, we should only see 1 item

	// The first catalog's group should have the Title Group 1
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/oscal/catalogs/D20DB907-B87D-4D12-8760-D36FDB7A1B31/groups", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	listResponse := &handler.GenericDataListResponse[oscaltypes.Group]{}
	err = json.Unmarshal(rec.Body.Bytes(), listResponse)
	suite.Require().NoError(err)

	// Make sure only one groups came back and it's the correct one.
	suite.Len(listResponse.Data, 1)
	suite.Equal(listResponse.Data[0].Title, "Group 1")
}

// TestRootControl ensures that when calling for the root groups on a catalog, only the root groups are returned.
func (suite *CatalogApiIntegrationSuite) TestRootControl() {
	logger, _ := zap.NewDevelopment()

	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	token, err := suite.GetAuthToken()

	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create two catalogs with the same group ID structure
	catalog := oscaltypes.Catalog{
		UUID: "D20DB907-B87D-4D12-8760-D36FDB7A1B31",
		Metadata: oscaltypes.Metadata{
			Title: "Catalog 1",
		},
		Controls: &[]oscaltypes.Control{
			{
				ID:    "C-1",
				Title: "Control 1",
				Controls: &[]oscaltypes.Control{
					{
						ID:    "C-1.1",
						Title: "Control 1.1",
					},
				},
			},
		},
	}

	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(catalog)
	req := httptest.NewRequest(http.MethodPost, "/api/oscal/catalogs", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	response := &handler.GenericDataResponse[oscaltypes.Catalog]{}
	err = json.Unmarshal(rec.Body.Bytes(), response)
	suite.Require().NoError(err)

	// Now if we call to check the children for each catalogs' first group, we should only see 1 item

	// The first catalog's group should have the Title Group 1
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/oscal/catalogs/D20DB907-B87D-4D12-8760-D36FDB7A1B31/controls", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)
	listResponse := &handler.GenericDataListResponse[oscaltypes.Control]{}
	err = json.Unmarshal(rec.Body.Bytes(), listResponse)
	suite.Require().NoError(err)

	// Make sure only one groups came back and it's the correct one.
	suite.Len(listResponse.Data, 1)
	suite.Equal(listResponse.Data[0].Title, "Control 1")
}

// TestCascadeDeleteGroupRemovesControls verifies that deleting a group cascades to its controls and subgroups
func (suite *CatalogApiIntegrationSuite) TestCascadeDeleteGroupRemovesControls() {
	logger, _ := zap.NewDevelopment()
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	catalog := oscaltypes.Catalog{
		UUID: "D5A6E1FF-7F21-4B3C-A2B7-998877665544",
		Metadata: oscaltypes.Metadata{
			Title: "Cascade Verify",
		},
		Groups: &[]oscaltypes.Group{
			{
				ID:    "G-1",
				Title: "Group 1",
				Controls: &[]oscaltypes.Control{
					{
						ID:    "C-1",
						Title: "Control 1",
						Controls: &[]oscaltypes.Control{
							{
								ID:    "C-1.1",
								Title: "Subcontrol",
							},
						},
					},
				},
				Groups: &[]oscaltypes.Group{
					{
						ID:    "G-1.1",
						Title: "Group 1.1",
					},
				},
			},
		},
		Controls: &[]oscaltypes.Control{
			{
				ID:    "X-1",
				Title: "Top Control",
			},
		},
	}
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(catalog)
	req := httptest.NewRequest(http.MethodPost, "/api/oscal/catalogs", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	// Delete the group and verify cascades
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/oscal/catalogs/D5A6E1FF-7F21-4B3C-A2B7-998877665544/groups/G-1", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNoContent, rec.Code)

	// Group gone
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/oscal/catalogs/D5A6E1FF-7F21-4B3C-A2B7-998877665544/groups/G-1", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNotFound, rec.Code)

	// Controls under group gone
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/oscal/catalogs/D5A6E1FF-7F21-4B3C-A2B7-998877665544/controls/C-1", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNotFound, rec.Code)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/oscal/catalogs/D5A6E1FF-7F21-4B3C-A2B7-998877665544/controls/C-1.1", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNotFound, rec.Code)
}

// TestCascadeDeleteControlRemovesChildren verifies that deleting a control cascades to its child controls
func (suite *CatalogApiIntegrationSuite) TestCascadeDeleteControlRemovesChildren() {
	logger, _ := zap.NewDevelopment()
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	catalog := oscaltypes.Catalog{
		UUID: "A1B2C3D4-E5F6-4711-8899-112233445566",
		Metadata: oscaltypes.Metadata{
			Title: "Cascade Control Verify",
		},
		Controls: &[]oscaltypes.Control{
			{
				ID:    "X-1",
				Title: "Top Control",
				Controls: &[]oscaltypes.Control{
					{
						ID:    "X-1.1",
						Title: "Child of X1",
					},
				},
			},
		},
	}
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(catalog)
	req := httptest.NewRequest(http.MethodPost, "/api/oscal/catalogs", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	// Delete the control and verify cascades
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/oscal/catalogs/A1B2C3D4-E5F6-4711-8899-112233445566/controls/X-1", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNoContent, rec.Code)

	// Control gone
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/oscal/catalogs/A1B2C3D4-E5F6-4711-8899-112233445566/controls/X-1", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNotFound, rec.Code)

	// Child control gone
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/oscal/catalogs/A1B2C3D4-E5F6-4711-8899-112233445566/controls/X-1.1", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNotFound, rec.Code)
}

// TestCascadeDeleteCatalogRemovesEverything verifies that deleting a catalog removes all associated data
func (suite *CatalogApiIntegrationSuite) TestCascadeDeleteCatalogRemovesEverything() {
	logger, _ := zap.NewDevelopment()
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	catalog := oscaltypes.Catalog{
		UUID: "F0E1D2C3-B4A5-6789-ABCD-001122334455",
		Metadata: oscaltypes.Metadata{
			Title: "Delete Whole Catalog",
		},
		Groups: &[]oscaltypes.Group{
			{
				ID:    "G-1",
				Title: "Group 1",
				Controls: &[]oscaltypes.Control{
					{
						ID:    "C-1",
						Title: "Control 1",
					},
				},
			},
		},
		Controls: &[]oscaltypes.Control{
			{
				ID:    "X-1",
				Title: "Top Control",
			},
		},
	}
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(catalog)
	req := httptest.NewRequest(http.MethodPost, "/api/oscal/catalogs", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	// Delete the catalog
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/oscal/catalogs/F0E1D2C3-B4A5-6789-ABCD-001122334455", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNoContent, rec.Code)

	// Catalog gone
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/oscal/catalogs/F0E1D2C3-B4A5-6789-ABCD-001122334455", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNotFound, rec.Code)
}

// TestFilterControlsCatalogScopedDelete ensures filter_controls rows are removed only for the targeted catalog
func (suite *CatalogApiIntegrationSuite) TestFilterControlsCatalogScopedDelete() {
	// NOTE: Currently, the many2many join table "filter_controls" uses a foreign key on control_id only,
	// which causes ON DELETE CASCADE to remove rows across catalogs when control IDs collide.
	// This test documents the intended behavior (catalog-scoped deletes) and will be enabled
	// after the schema change to include catalog_id in the FK or remove the cascade.
	suite.T().Skip("Pending schema update: ensure filter_controls FK includes catalog_id to avoid cross-catalog cascades")
	logger, _ := zap.NewDevelopment()
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, evidenceSvc, nil)

	// Create two catalogs with the same control ID
	catA := oscaltypes.Catalog{
		UUID: "AAAABBBB-CCCC-DDDD-EEEE-111122223333",
		Metadata: oscaltypes.Metadata{
			Title: "Catalog A",
		},
		Controls: &[]oscaltypes.Control{
			{
				ID:    "DUP-1",
				Title: "Duplicate Control",
			},
		},
	}
	catB := oscaltypes.Catalog{
		UUID: "BBBBCCCC-DDDD-EEEE-FFFF-444455556666",
		Metadata: oscaltypes.Metadata{
			Title: "Catalog B",
		},
		Controls: &[]oscaltypes.Control{
			{
				ID:    "DUP-1",
				Title: "Duplicate Control (B)",
			},
		},
	}
	for _, catalog := range []oscaltypes.Catalog{catA, catB} {
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(catalog)
		req := httptest.NewRequest(http.MethodPost, "/api/oscal/catalogs", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	}

	// Create a filter and associate both controls (same id across two catalogs)
	filter := relational.Filter{
		Name:   "Scoped Delete Test",
		Filter: datatypes.NewJSONType(labelfilter.Filter{}),
	}
	suite.Require().NoError(suite.DB.Create(&filter).Error)
	suite.Require().NotNil(filter.ID)

	// Insert join rows manually to avoid ambiguous control lookups
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO filter_controls (filter_id, control_id, control_catalog_id) VALUES (?, ?, ?), (?, ?, ?)",
		*filter.ID, "DUP-1", catA.UUID,
		*filter.ID, "DUP-1", catB.UUID,
	).Error)

	// Delete control from Catalog A
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/oscal/catalogs/"+catA.UUID+"/controls/DUP-1", bytes.NewReader([]byte{}))
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusNoContent, rec.Code)

	// Verify filter_controls rows: A is gone, B remains
	var countA int64
	suite.Require().NoError(suite.DB.Raw(
		"SELECT COUNT(*) FROM filter_controls WHERE control_id = ? AND control_catalog_id = ?",
		"DUP-1", catA.UUID,
	).Scan(&countA).Error)
	assert.Equal(suite.T(), int64(0), countA)

	var countB int64
	suite.Require().NoError(suite.DB.Raw(
		"SELECT COUNT(*) FROM filter_controls WHERE control_id = ? AND control_catalog_id = ?",
		"DUP-1", catB.UUID,
	).Scan(&countB).Error)
	assert.Equal(suite.T(), int64(1), countB)
}
