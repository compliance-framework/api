//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestGroupsApi(t *testing.T) {
	suite.Run(t, new(GroupsApiIntegrationSuite))
}

type GroupsApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
	logger *zap.SugaredLogger
}

func (suite *GroupsApiIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()

	logger, _ := zap.NewDevelopment()
	suite.logger = logger.Sugar()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	RegisterHandlers(suite.server, suite.logger, suite.DB, suite.Config, &APIServices{})
}

func (suite *GroupsApiIntegrationSuite) SetupTest() {
	suite.Require().NoError(suite.Migrator.Refresh())
}

// do issues an authenticated request and returns the recorder.
func (suite *GroupsApiIntegrationSuite) do(method, path string, body any) *httptest.ResponseRecorder {
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

func (suite *GroupsApiIntegrationSuite) createGroup(name string) string {
	rec := suite.do("POST", "/api/admin/groups", map[string]string{"name": name, "description": "d"})
	suite.Require().Equal(201, rec.Code, rec.Body.String())
	var resp GenericDataResponse[relational.UserGroup]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	suite.Require().NotNil(resp.Data.ID)
	return resp.Data.ID.String()
}

func (suite *GroupsApiIntegrationSuite) dummyUserID() string {
	var user relational.User
	suite.Require().NoError(suite.DB.Where("email = ?", "dummy@example.com").First(&user).Error)
	return user.ID.String()
}

func (suite *GroupsApiIntegrationSuite) TestGroupCRUD() {
	groupID := suite.createGroup("security-team")

	// Duplicate name -> 409.
	dup := suite.do("POST", "/api/admin/groups", map[string]string{"name": "security-team"})
	suite.Equal(409, dup.Code, dup.Body.String())

	// List contains the group.
	list := suite.do("GET", "/api/admin/groups", nil)
	suite.Require().Equal(200, list.Code)
	var listResp GenericDataListResponse[groupResponse]
	suite.Require().NoError(json.Unmarshal(list.Body.Bytes(), &listResp))
	suite.Require().Len(listResp.Data, 1)
	suite.Equal("security-team", listResp.Data[0].Name)
	suite.Equal(0, listResp.Data[0].MemberCount)

	// Update.
	upd := suite.do("PUT", "/api/admin/groups/"+groupID, map[string]string{"name": "sec-team"})
	suite.Require().Equal(200, upd.Code, upd.Body.String())

	// Get reflects the rename.
	get := suite.do("GET", "/api/admin/groups/"+groupID, nil)
	suite.Require().Equal(200, get.Code)
	var getResp GenericDataResponse[groupResponse]
	suite.Require().NoError(json.Unmarshal(get.Body.Bytes(), &getResp))
	suite.Equal("sec-team", getResp.Data.Name)

	// Delete, then 404.
	del := suite.do("DELETE", "/api/admin/groups/"+groupID, nil)
	suite.Require().Equal(204, del.Code)
	gone := suite.do("GET", "/api/admin/groups/"+groupID, nil)
	suite.Equal(404, gone.Code)
}

func (suite *GroupsApiIntegrationSuite) TestMembershipLifecycleAndUserSurfacing() {
	groupID := suite.createGroup("auditors")
	userID := suite.dummyUserID()

	// Add member (idempotent: a second add is still 204).
	add := suite.do("POST", "/api/admin/groups/"+groupID+"/members", map[string]string{"userId": userID})
	suite.Require().Equal(204, add.Code, add.Body.String())
	again := suite.do("POST", "/api/admin/groups/"+groupID+"/members", map[string]string{"userId": userID})
	suite.Require().Equal(204, again.Code)

	// Member list contains the user once.
	members := suite.do("GET", "/api/admin/groups/"+groupID+"/members", nil)
	suite.Require().Equal(200, members.Code)
	var memberResp GenericDataListResponse[groupMemberResponse]
	suite.Require().NoError(json.Unmarshal(members.Body.Bytes(), &memberResp))
	suite.Require().Len(memberResp.Data, 1)
	suite.Equal(userID, memberResp.Data[0].UserID)
	suite.False(memberResp.Data[0].Inherited, "a manually added member is not inherited")

	// Membership surfaces on the admin user view.
	userView := suite.do("GET", "/api/admin/users/"+userID, nil)
	suite.Require().Equal(200, userView.Code)
	var userResp GenericDataResponse[userResponse]
	suite.Require().NoError(json.Unmarshal(userView.Body.Bytes(), &userResp))
	suite.Require().Len(userResp.Data.Groups, 1)
	suite.Equal("auditors", userResp.Data.Groups[0].Name)

	// Member count reflects the membership.
	get := suite.do("GET", "/api/admin/groups/"+groupID, nil)
	var getResp GenericDataResponse[groupResponse]
	suite.Require().NoError(json.Unmarshal(get.Body.Bytes(), &getResp))
	suite.Equal(1, getResp.Data.MemberCount)

	// Remove member.
	rem := suite.do("DELETE", "/api/admin/groups/"+groupID+"/members/"+userID, nil)
	suite.Require().Equal(204, rem.Code)
	empty := suite.do("GET", "/api/admin/groups/"+groupID+"/members", nil)
	var emptyResp GenericDataListResponse[groupMemberResponse]
	suite.Require().NoError(json.Unmarshal(empty.Body.Bytes(), &emptyResp))
	suite.Empty(emptyResp.Data)
}

func (suite *GroupsApiIntegrationSuite) TestAddMemberUnknownUser() {
	groupID := suite.createGroup("team")
	rec := suite.do("POST", "/api/admin/groups/"+groupID+"/members",
		map[string]string{"userId": "00000000-0000-0000-0000-000000000000"})
	suite.Equal(404, rec.Code, rec.Body.String())
}

func (suite *GroupsApiIntegrationSuite) TestDeleteNonEmptyGroupReturns409() {
	groupID := suite.createGroup("doomed")
	userID := suite.dummyUserID()

	add := suite.do("POST", "/api/admin/groups/"+groupID+"/members", map[string]string{"userId": userID})
	suite.Require().Equal(204, add.Code, add.Body.String())

	// A non-empty group cannot be deleted — the operator must empty it first (BCH-1331).
	del := suite.do("DELETE", "/api/admin/groups/"+groupID, nil)
	suite.Require().Equal(409, del.Code, del.Body.String())

	// The group and its member survive the rejected delete.
	var memberRows int64
	suite.Require().NoError(suite.DB.Model(&relational.UserGroupMembership{}).
		Where("group_id = ?", groupID).Count(&memberRows).Error)
	suite.Equal(int64(1), memberRows, "membership must survive a rejected delete")
	get := suite.do("GET", "/api/admin/groups/"+groupID, nil)
	suite.Equal(200, get.Code)
}

func (suite *GroupsApiIntegrationSuite) TestDeleteEmptyGroupCascadesMappings() {
	groupID := suite.createGroup("doomed")

	mapAdd := suite.do("POST", "/api/admin/groups/"+groupID+"/sso-mappings",
		map[string]string{"provider": "okta", "externalGroup": "doomed-idp"})
	suite.Require().Equal(201, mapAdd.Code, mapAdd.Body.String())

	// With no members, deletion succeeds and cascades the SSO mappings.
	del := suite.do("DELETE", "/api/admin/groups/"+groupID, nil)
	suite.Require().Equal(204, del.Code, del.Body.String())

	var mappingRows int64
	suite.Require().NoError(suite.DB.Model(&relational.SSOGroupMapping{}).
		Where("group_id = ?", groupID).Count(&mappingRows).Error)
	suite.Equal(int64(0), mappingRows, "sso mappings should be removed when the group is deleted")

	// The freed name can be re-created: the partial unique index only covers live rows.
	recreate := suite.do("POST", "/api/admin/groups", map[string]string{"name": "doomed"})
	suite.Equal(201, recreate.Code, recreate.Body.String())
}

func (suite *GroupsApiIntegrationSuite) TestRemoveSSOMemberReturns403() {
	groupID := suite.createGroup("idp-owned")
	userID := suite.dummyUserID()

	// An sso-sourced membership is owned by the IdP and cannot be hand-removed (BCH-1331).
	suite.Require().NoError(suite.DB.Create(&relational.UserGroupMembership{
		UserID:  userID,
		GroupID: groupID,
		Source:  relational.MembershipSourceSSO,
	}).Error)

	// The member list flags the sso membership as inherited so the UI can render it read-only
	// instead of offering a Remove action that would 403.
	members := suite.do("GET", "/api/admin/groups/"+groupID+"/members", nil)
	suite.Require().Equal(200, members.Code)
	var memberResp GenericDataListResponse[groupMemberResponse]
	suite.Require().NoError(json.Unmarshal(members.Body.Bytes(), &memberResp))
	suite.Require().Len(memberResp.Data, 1)
	suite.True(memberResp.Data[0].Inherited, "an sso-synced member must be flagged inherited")

	rem := suite.do("DELETE", "/api/admin/groups/"+groupID+"/members/"+userID, nil)
	suite.Require().Equal(403, rem.Code, rem.Body.String())

	// The membership is untouched.
	var rows int64
	suite.Require().NoError(suite.DB.Model(&relational.UserGroupMembership{}).
		Where("group_id = ? AND user_id = ?", groupID, userID).Count(&rows).Error)
	suite.Equal(int64(1), rows, "sso membership must survive a rejected removal")

	// A manual membership in the same group is still removable.
	other := suite.createGroup("admin-owned")
	add := suite.do("POST", "/api/admin/groups/"+other+"/members", map[string]string{"userId": userID})
	suite.Require().Equal(204, add.Code, add.Body.String())
	remManual := suite.do("DELETE", "/api/admin/groups/"+other+"/members/"+userID, nil)
	suite.Require().Equal(204, remManual.Code, remManual.Body.String())
}

func (suite *GroupsApiIntegrationSuite) TestSSOMappingLifecycle() {
	groupID := suite.createGroup("idp-linked")

	add := suite.do("POST", "/api/admin/groups/"+groupID+"/sso-mappings",
		map[string]string{"provider": "okta", "externalGroup": "okta-admins"})
	suite.Require().Equal(201, add.Code, add.Body.String())
	var mapResp GenericDataResponse[relational.SSOGroupMapping]
	suite.Require().NoError(json.Unmarshal(add.Body.Bytes(), &mapResp))
	suite.Require().NotNil(mapResp.Data.ID)
	mappingID := mapResp.Data.ID.String()

	// Duplicate mapping -> 409.
	dup := suite.do("POST", "/api/admin/groups/"+groupID+"/sso-mappings",
		map[string]string{"provider": "okta", "externalGroup": "okta-admins"})
	suite.Equal(409, dup.Code)

	list := suite.do("GET", "/api/admin/groups/"+groupID+"/sso-mappings", nil)
	suite.Require().Equal(200, list.Code)
	var listResp GenericDataListResponse[relational.SSOGroupMapping]
	suite.Require().NoError(json.Unmarshal(list.Body.Bytes(), &listResp))
	suite.Require().Len(listResp.Data, 1)

	del := suite.do("DELETE", "/api/admin/groups/"+groupID+"/sso-mappings/"+mappingID, nil)
	suite.Require().Equal(204, del.Code)
}
