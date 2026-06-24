//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestRoleAssignmentsApi(t *testing.T) {
	suite.Run(t, new(RoleAssignmentsApiIntegrationSuite))
}

type RoleAssignmentsApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
	logger *zap.SugaredLogger
}

func (suite *RoleAssignmentsApiIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()

	logger, _ := zap.NewDevelopment()
	suite.logger = logger.Sugar()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	RegisterHandlers(suite.server, suite.logger, suite.DB, suite.Config, &APIServices{})
}

func (suite *RoleAssignmentsApiIntegrationSuite) SetupTest() {
	suite.Require().NoError(suite.Migrator.Refresh())
}

func (suite *RoleAssignmentsApiIntegrationSuite) do(method, path string, body any) *httptest.ResponseRecorder {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		suite.Require().NoError(err)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Authorization", "Bearer "+*token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)
	return rec
}

func (suite *RoleAssignmentsApiIntegrationSuite) dummyUser() relational.User {
	var user relational.User
	suite.Require().NoError(suite.DB.Where("email = ?", "dummy@example.com").First(&user).Error)
	return user
}

// TestCreateGrantAppearsAsDirect: a manual grant created through the API shows up in the user's
// effective roles as a direct (non-inherited) grant.
func (suite *RoleAssignmentsApiIntegrationSuite) TestCreateGrantAppearsAsDirect() {
	user := suite.dummyUser()

	rec := suite.do("POST", "/api/admin/role-assignments", map[string]string{
		"roleName":     "viewer",
		"assigneeType": "user",
		"assigneeId":   user.Email,
	})
	suite.Require().Equal(201, rec.Code, rec.Body.String())

	roles := suite.userRoles(user.ID.String())
	suite.Require().Len(roles, 1)
	suite.Equal("viewer", roles[0].RoleName)
	suite.Equal(relational.RoleAssignmentSourceManual, roles[0].Source)
	suite.False(roles[0].Inherited)
	suite.Empty(roles[0].ViaGroup)
}

// TestInheritedRoleNamesGroup: a role granted to a group the user belongs to appears as an
// inherited entry naming the granting group.
func (suite *RoleAssignmentsApiIntegrationSuite) TestInheritedRoleNamesGroup() {
	user := suite.dummyUser()

	group := relational.UserGroup{Name: "Auditors"}
	suite.Require().NoError(suite.DB.Create(&group).Error)
	suite.Require().NoError(suite.DB.Create(&relational.UserGroupMembership{
		UserID:  user.ID.String(),
		GroupID: group.ID.String(),
		Source:  relational.MembershipSourceManual,
	}).Error)

	rec := suite.do("POST", "/api/admin/role-assignments", map[string]string{
		"roleName":     "auditor",
		"assigneeType": "group",
		"assigneeId":   group.Name,
	})
	suite.Require().Equal(201, rec.Code, rec.Body.String())

	roles := suite.userRoles(user.ID.String())
	suite.Require().Len(roles, 1)
	suite.Equal("auditor", roles[0].RoleName)
	suite.True(roles[0].Inherited)
	suite.Equal("Auditors", roles[0].ViaGroup)

	// The group's own roles view lists it too.
	grec := suite.do("GET", "/api/admin/groups/"+group.ID.String()+"/roles", nil)
	suite.Require().Equal(200, grec.Code, grec.Body.String())
	var gresp GenericDataListResponse[relational.CCFRoleAssignment]
	suite.Require().NoError(json.Unmarshal(grec.Body.Bytes(), &gresp))
	suite.Require().Len(gresp.Data, 1)
	suite.Equal("auditor", gresp.Data[0].RoleName)
}

// TestDeleteConfigGrantConflicts: a config-sourced grant cannot be deleted through the API (409),
// while a manual grant can (204).
func (suite *RoleAssignmentsApiIntegrationSuite) TestDeleteConfigGrantConflicts() {
	configGrant := relational.CCFRoleAssignment{
		RoleName:     "admin",
		AssigneeType: relational.RoleAssigneeTypeUser,
		AssigneeID:   relational.NormalizeAssigneeID("ops@example.com"),
		Source:       relational.RoleAssignmentSourceConfig,
	}
	suite.Require().NoError(suite.DB.Create(&configGrant).Error)

	rec := suite.do("DELETE", "/api/admin/role-assignments/"+configGrant.ID.String(), nil)
	suite.Equal(409, rec.Code, rec.Body.String())

	// The same row survives.
	var count int64
	suite.Require().NoError(suite.DB.Model(&relational.CCFRoleAssignment{}).Where("id = ?", configGrant.ID.String()).Count(&count).Error)
	suite.Equal(int64(1), count)

	// A manual grant deletes cleanly.
	manual := relational.CCFRoleAssignment{
		RoleName:     "viewer",
		AssigneeType: relational.RoleAssigneeTypeUser,
		AssigneeID:   relational.NormalizeAssigneeID("temp@example.com"),
		Source:       relational.RoleAssignmentSourceManual,
	}
	suite.Require().NoError(suite.DB.Create(&manual).Error)
	drec := suite.do("DELETE", "/api/admin/role-assignments/"+manual.ID.String(), nil)
	suite.Equal(204, drec.Code, drec.Body.String())
}

// TestCreateRejectsUnknownRole: a role the manifest does not declare is rejected at write time.
func (suite *RoleAssignmentsApiIntegrationSuite) TestCreateRejectsUnknownRole() {
	rec := suite.do("POST", "/api/admin/role-assignments", map[string]string{
		"roleName":     "supervisor",
		"assigneeType": "user",
		"assigneeId":   "x@example.com",
	})
	suite.Equal(400, rec.Code, rec.Body.String())
}

// TestCreateDuplicateConflicts: re-granting the same role to the same assignee is a 409, not a
// duplicate row (the unique index on (assignee_type, assignee_id, role_name)).
func (suite *RoleAssignmentsApiIntegrationSuite) TestCreateDuplicateConflicts() {
	body := map[string]string{"roleName": "viewer", "assigneeType": "user", "assigneeId": "Dup@Example.com"}
	suite.Require().Equal(201, suite.do("POST", "/api/admin/role-assignments", body).Code)

	// Same grant, different casing on the email — normalization makes it the same row → 409.
	rec := suite.do("POST", "/api/admin/role-assignments", map[string]string{
		"roleName": "viewer", "assigneeType": "user", "assigneeId": "dup@example.com",
	})
	suite.Equal(409, rec.Code, rec.Body.String())

	var count int64
	suite.Require().NoError(suite.DB.Model(&relational.CCFRoleAssignment{}).
		Where("assignee_id = ? AND role_name = ?", "dup@example.com", "viewer").Count(&count).Error)
	suite.Equal(int64(1), count)
}

// TestEffectiveRolesMatchPDPDecision is the BCH-1333 parity check: the roles GET
// /admin/users/:id/roles displays are exactly the roles an actual cedar PDP decision enforces
// for the same subject — no drift between what we show and what we allow.
func (suite *RoleAssignmentsApiIntegrationSuite) TestEffectiveRolesMatchPDPDecision() {
	user := suite.dummyUser()

	// Direct viewer, plus auditor inherited from a native group the user belongs to.
	group := relational.UserGroup{Name: "audit-team"}
	suite.Require().NoError(suite.DB.Create(&group).Error)
	suite.Require().NoError(suite.DB.Create(&relational.UserGroupMembership{
		UserID: user.ID.String(), GroupID: group.ID.String(), Source: relational.MembershipSourceManual,
	}).Error)
	suite.Require().Equal(201, suite.do("POST", "/api/admin/role-assignments", map[string]string{
		"roleName": "viewer", "assigneeType": "user", "assigneeId": user.Email,
	}).Code)
	suite.Require().Equal(201, suite.do("POST", "/api/admin/role-assignments", map[string]string{
		"roleName": "auditor", "assigneeType": "group", "assigneeId": group.Name,
	}).Code)

	// What the admin endpoint DISPLAYS.
	displayed := map[string]bool{}
	for _, r := range suite.userRoles(user.ID.String()) {
		displayed[r.RoleName] = true
	}
	gotRoles := keys(displayed)
	suite.ElementsMatch([]string{"viewer", "auditor"}, gotRoles)

	// What an actual cedar PDP ENFORCES for the same subject (the table is its source of truth;
	// Open wires the DB role resolver and the group resolver).
	logger, _ := zap.NewDevelopment()
	pdp, err := authz.Open(
		authz.Options{Driver: authz.DriverCedar},
		authz.Deps{DB: suite.DB, Config: suite.Config, Logger: logger.Sugar()},
	)
	suite.Require().NoError(err)

	subj := authz.Subject{Type: "user", ID: user.Email}
	allow := func(action, resource string) bool {
		dec, derr := pdp.Evaluate(context.Background(), subj, action, authz.Resource{Type: resource}, nil)
		suite.Require().NoError(derr)
		return dec.Allow
	}

	// The decision pattern is exactly the union of viewer (read *) and auditor (read *, evidence
	// create) — proving the displayed roles are the enforced roles:
	suite.True(allow(authz.ActionRead, authz.ResourceCatalog), "viewer/auditor read => allow")
	suite.True(allow(authz.ActionCreate, authz.ResourceEvidence), "auditor evidence:create => allow")
	suite.False(allow(authz.ActionCreate, authz.ResourceCatalog), "neither role creates catalog => deny")
	suite.False(allow(authz.ActionManage, authz.ResourceAdmin), "not admin => deny")
}

func (suite *RoleAssignmentsApiIntegrationSuite) userRoles(userID string) []effectiveRole {
	rec := suite.do("GET", "/api/admin/users/"+userID+"/roles", nil)
	suite.Require().Equal(200, rec.Code, rec.Body.String())
	var resp GenericDataListResponse[effectiveRole]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
