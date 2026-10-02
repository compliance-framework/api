//go:build integration

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/compliance-framework/api/internal"
	"github.com/compliance-framework/api/internal/api"
	svc "github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/compliance-framework/api/internal/service/relational/subjects"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/gorm/clause"
)

func TestSubjectsApi(t *testing.T) {
	suite.Run(t, new(SubjectsApiIntegrationSuite))
}

type SubjectsApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
	sspID  uuid.UUID
	// definedComponentID is linked from the Payments Platform SSP's system component.
	definedComponentID uuid.UUID
	partyID            uuid.UUID
	// otherSSPID has a system component too, to check the ssp filter.
	otherSSPID uuid.UUID
}

func (suite *SubjectsApiIntegrationSuite) SetupTest() {
	suite.Require().NoError(suite.Migrator.Refresh())

	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	RegisterHandlers(suite.server, logger.Sugar(), suite.DB, suite.Config, &APIServices{})

	db := suite.DB
	cdID := uuid.New()
	suite.Require().NoError(db.Omit(clause.Associations).Create(&relational.ComponentDefinition{UUIDModel: relational.UUIDModel{ID: &cdID}}).Error)
	suite.Require().NoError(db.Create(&relational.Metadata{
		Title:      "github-settings components",
		ParentID:   internal.Pointer(cdID.String()),
		ParentType: internal.Pointer("component_definitions"),
	}).Error)
	suite.definedComponentID = uuid.New()
	suite.Require().NoError(db.Omit(clause.Associations).Create(&relational.DefinedComponent{
		UUIDModel: relational.UUIDModel{ID: &suite.definedComponentID},
		Title:     "GitHub Organization: acme", Type: "service", ComponentDefinitionID: &cdID,
	}).Error)
	suite.Require().NoError(db.Create(&riskrel.ComponentDefinitionLabel{
		DefinedComponentID: suite.definedComponentID, ComponentDefinitionID: cdID, Key: "organization", Value: "acme",
	}).Error)

	suite.sspID = suite.createSSPWithComponent("Payments Platform", "Perimeter Firewall", &suite.definedComponentID)
	suite.otherSSPID = suite.createSSPWithComponent("Data Platform", "Data Warehouse", nil)

	// A component created from evidence components[] belongs to no SSP and isn't listed.
	suite.Require().NoError(db.Omit(clause.Associations).Create(&relational.SystemComponent{Title: "Evidence-only component", Type: "software"}).Error)

	suite.partyID = uuid.New()
	suite.Require().NoError(db.Omit(clause.Associations).Create(&relational.Party{
		UUIDModel: relational.UUIDModel{ID: &suite.partyID},
		Type:      relational.PartyTypeOrganization,
		Name:      internal.Pointer("Network Team"),
	}).Error)

	for _, user := range []relational.User{
		{Email: "active@example.com", FirstName: "Avery", LastName: "Active", IsActive: true},
		{Email: "locked@example.com", FirstName: "Lee", LastName: "Locked", IsActive: true, IsLocked: true},
	} {
		suite.Require().NoError(db.Create(&user).Error)
	}
	inactive := relational.User{Email: "inactive@example.com", FirstName: "Ivy", LastName: "Inactive"}
	suite.Require().NoError(db.Create(&inactive).Error)
	suite.Require().NoError(db.Model(&inactive).Update("is_active", false).Error)
	deleted := relational.User{Email: "deleted@example.com", FirstName: "Dee", LastName: "Deleted", IsActive: true}
	suite.Require().NoError(db.Create(&deleted).Error)
	suite.Require().NoError(db.Delete(&deleted).Error)
}

func (suite *SubjectsApiIntegrationSuite) createSSPWithComponent(sspTitle, componentTitle string, definedComponentID *uuid.UUID) uuid.UUID {
	db := suite.DB
	sspID := uuid.New()
	suite.Require().NoError(db.Omit(clause.Associations).Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}).Error)
	suite.Require().NoError(db.Create(&relational.Metadata{
		Title:      sspTitle,
		ParentID:   internal.Pointer(sspID.String()),
		ParentType: internal.Pointer("system_security_plans"),
	}).Error)
	implementationID := uuid.New()
	suite.Require().NoError(db.Omit(clause.Associations).Create(&relational.SystemImplementation{
		UUIDModel: relational.UUIDModel{ID: &implementationID}, SystemSecurityPlanId: sspID,
	}).Error)
	suite.Require().NoError(db.Omit(clause.Associations).Create(&relational.SystemComponent{
		Title: componentTitle, Type: "this-system", SystemImplementationId: implementationID,
		DefinedComponentID: definedComponentID,
	}).Error)
	return sspID
}

func (suite *SubjectsApiIntegrationSuite) list(query string) (int, svc.ListResponse[subjects.Summary]) {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/subjects"+query, nil)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	suite.server.E().ServeHTTP(rec, req)

	var body svc.ListResponse[subjects.Summary]
	if rec.Code == http.StatusOK {
		suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &body))
	}
	return rec.Code, body
}

func titles(items []subjects.Summary) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Title)
	}
	return out
}

func (suite *SubjectsApiIntegrationSuite) TestListsEveryKindOrderedByTitle() {
	code, body := suite.list("")
	suite.Require().Equal(http.StatusOK, code)

	// The migrator's "Dummy User" is listed alongside the seeded active user.
	suite.Equal([]string{
		"Avery Active",
		"Data Warehouse",
		"Dummy User",
		"GitHub Organization: acme",
		"Network Team",
		"Perimeter Firewall",
	}, titles(body.Data))
	suite.Equal(int64(6), body.Total)

	byTitle := map[string]subjects.Summary{}
	for _, item := range body.Data {
		byTitle[item.Title] = item
	}
	suite.Equal(subjects.KindDefinedComponent, byTitle["GitHub Organization: acme"].Kind)
	suite.Equal("component", byTitle["GitHub Organization: acme"].Type)
	suite.Equal("github-settings components", *byTitle["GitHub Organization: acme"].Context)
	suite.Equal(subjects.KindSystemComponent, byTitle["Perimeter Firewall"].Kind)
	suite.Equal("Payments Platform", *byTitle["Perimeter Firewall"].Context)
	suite.Equal("party", byTitle["Network Team"].Type)
	suite.Nil(byTitle["Network Team"].Context)
	suite.Equal("user", byTitle["Avery Active"].Type)
}

func (suite *SubjectsApiIntegrationSuite) TestFiltersBySearchKindAndSSP() {
	_, search := suite.list("?search=PERIMETER")
	suite.Equal([]string{"Perimeter Firewall"}, titles(search.Data))

	_, percent := suite.list("?search=%25")
	suite.Empty(percent.Data, "search treats % literally")

	_, kinds := suite.list("?kind=party,user")
	suite.Equal([]string{"Avery Active", "Dummy User", "Network Team"}, titles(kinds.Data))

	_, ssp := suite.list(fmt.Sprintf("?ssp=%s", suite.sspID))
	suite.Contains(titles(ssp.Data), "Perimeter Firewall")
	suite.NotContains(titles(ssp.Data), "Data Warehouse", "ssp narrows system components")
	suite.Contains(titles(ssp.Data), "Network Team", "ssp leaves other kinds alone")
}

func (suite *SubjectsApiIntegrationSuite) TestPages() {
	_, page := suite.list("?limit=2&page=2")
	suite.Equal([]string{"Dummy User", "GitHub Organization: acme"}, titles(page.Data))
	suite.Equal(int64(6), page.Total)
	suite.Equal(3, page.TotalPages)
}

func (suite *SubjectsApiIntegrationSuite) TestRejectsBadParameters() {
	code, _ := suite.list("?kind=resource")
	suite.Equal(http.StatusBadRequest, code)

	code, _ = suite.list("?ssp=not-a-uuid")
	suite.Equal(http.StatusBadRequest, code)
}

func (suite *SubjectsApiIntegrationSuite) TestRequiresLogin() {
	rec := httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/subjects", nil))
	suite.Equal(http.StatusUnauthorized, rec.Code)
}

func (suite *SubjectsApiIntegrationSuite) TestLooksUpSubjectsByID() {
	code, body := suite.list(fmt.Sprintf("?ids=%s,%s", suite.partyID, suite.definedComponentID))
	suite.Require().Equal(http.StatusOK, code)
	suite.Equal([]string{"GitHub Organization: acme", "Network Team"}, titles(body.Data))

	code, _ = suite.list("?ids=not-a-uuid")
	suite.Equal(http.StatusBadRequest, code)

	tooMany := make([]string, 101)
	for i := range tooMany {
		tooMany[i] = uuid.NewString()
	}
	code, _ = suite.list("?ids=" + strings.Join(tooMany, ","))
	suite.Equal(http.StatusBadRequest, code)
}

func (suite *SubjectsApiIntegrationSuite) TestDefinedComponentsCarryIdentityAndLinkedSSPs() {
	_, body := suite.list("")

	byTitle := map[string]subjects.Summary{}
	for _, item := range body.Data {
		byTitle[item.Title] = item
	}

	org := byTitle["GitHub Organization: acme"]
	suite.Equal([]subjects.IdentityLabel{{Key: "organization", Value: "acme"}}, org.Identity)
	suite.Require().Len(org.LinkedSSPs, 1)
	suite.Equal(suite.sspID, org.LinkedSSPs[0].SSPID)
	suite.Equal("Payments Platform", org.LinkedSSPs[0].SSPTitle)
	suite.Equal("Perimeter Firewall", org.LinkedSSPs[0].ComponentTitle)

	suite.Empty(byTitle["Perimeter Firewall"].Identity, "only defined components carry identity")
	suite.Empty(byTitle["Network Team"].LinkedSSPs)
}
