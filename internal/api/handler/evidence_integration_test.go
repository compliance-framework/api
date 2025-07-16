//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/compliance-framework/api/internal"
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func (suite *EvidenceApiIntegrationSuite) TestCreate() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

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

	logger, _ := zap.NewDevelopment()
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)
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
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(struct {
			Filter labelfilter.Filter
		}{})
		req := httptest.NewRequest(http.MethodPost, "/api/evidence/search", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		response := &GenericDataListResponse[relational.Evidence]{}
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
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(struct {
			Filter labelfilter.Filter
		}{})
		req := httptest.NewRequest(http.MethodPost, "/api/evidence/search", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		response := &GenericDataListResponse[relational.Evidence]{}
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
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)
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

		response := &GenericDataListResponse[relational.Evidence]{}
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
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)
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

		response := &GenericDataListResponse[relational.Evidence]{}
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
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)
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

		response := &GenericDataListResponse[relational.Evidence]{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err)

		suite.Len(response.Data, 1)
		suite.Equal(response.Data[0].Title, "AWS-1")
	})
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
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)
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
