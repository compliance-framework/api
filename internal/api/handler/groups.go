package handler

import (
	"errors"
	"strings"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// GroupsHandler serves the admin CRUD for native CCF user groups and their membership
// (BCH-1328). Native groups give every user — SSO or local — a source-agnostic group set
// that the authz group resolver unions with IdP groups into subject.groups. Routes mount
// under /api/admin/groups behind the same admin gate as the other admin resources.
type GroupsHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

func NewGroupsHandler(sugar *zap.SugaredLogger, db *gorm.DB) *GroupsHandler {
	return &GroupsHandler{sugar: sugar, db: db}
}

func (h *GroupsHandler) Register(api *echo.Group) {
	api.GET("", h.ListGroups)
	api.POST("", h.CreateGroup)
	api.GET("/:id", h.GetGroup)
	api.PUT("/:id", h.UpdateGroup)
	api.DELETE("/:id", h.DeleteGroup)
	api.GET("/:id/members", h.ListMembers)
	api.POST("/:id/members", h.AddMember)
	api.DELETE("/:id/members/:userId", h.RemoveMember)
	api.GET("/:id/sso-mappings", h.ListSSOMappings)
	api.POST("/:id/sso-mappings", h.AddSSOMapping)
	api.DELETE("/:id/sso-mappings/:mappingId", h.RemoveSSOMapping)
}

type groupMemberResponse struct {
	UserID      string `json:"userId"`
	DisplayName string `json:"displayName"`
}

type groupResponse struct {
	relational.UserGroup
	MemberCount int `json:"memberCount"`
}

// ListGroups godoc
//
//	@Summary		List user groups
//	@Description	Lists all native CCF user groups with their member counts
//	@Tags			Groups
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[handler.groupResponse]
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/groups [get]
func (h *GroupsHandler) ListGroups(ctx echo.Context) error {
	var groups []relational.UserGroup
	if err := h.db.Order("name ASC").Find(&groups).Error; err != nil {
		h.sugar.Errorw("Failed to list groups", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	counts, err := h.memberCounts()
	if err != nil {
		h.sugar.Errorw("Failed to count group members", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	responses := make([]groupResponse, len(groups))
	for i, g := range groups {
		responses[i] = groupResponse{UserGroup: g}
		if g.ID != nil {
			responses[i].MemberCount = counts[g.ID.String()]
		}
	}

	return ctx.JSON(200, GenericDataListResponse[groupResponse]{Data: responses})
}

// GetGroup godoc
//
//	@Summary		Get a user group
//	@Description	Get a native CCF user group by ID
//	@Tags			Groups
//	@Produce		json
//	@Param			id	path		string	true	"Group ID"
//	@Success		200	{object}	handler.GenericDataResponse[handler.groupResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/groups/{id} [get]
func (h *GroupsHandler) GetGroup(ctx echo.Context) error {
	group, err := h.loadGroup(ctx.Param("id"))
	if err != nil {
		return h.groupError(ctx, err)
	}

	resp := groupResponse{UserGroup: *group}
	if group.ID != nil {
		count, err := h.memberCount(group.ID.String())
		if err != nil {
			h.sugar.Errorw("Failed to count group members", "error", err)
			return ctx.JSON(500, api.NewError(err))
		}
		resp.MemberCount = count
	}

	return ctx.JSON(200, GenericDataResponse[groupResponse]{Data: resp})
}

// CreateGroup godoc
//
//	@Summary		Create a user group
//	@Description	Creates a native CCF user group
//	@Tags			Groups
//	@Accept			json
//	@Produce		json
//	@Param			group	body		handler.GroupsHandler.CreateGroup.createGroupRequest	true	"Group details"
//	@Success		201		{object}	handler.GenericDataResponse[relational.UserGroup]
//	@Failure		400		{object}	api.Error
//	@Failure		409		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/groups [post]
func (h *GroupsHandler) CreateGroup(ctx echo.Context) error {
	type createGroupRequest struct {
		Name        string `json:"name" validate:"required"`
		Description string `json:"description"`
	}

	var req createGroupRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind create group request", "error", err)
		return ctx.JSON(400, api.NewError(err))
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		return ctx.JSON(400, api.NewError(errors.New("name is required")))
	}

	group := &relational.UserGroup{Name: name, Description: strings.TrimSpace(req.Description)}
	if err := h.db.Create(group).Error; err != nil {
		if isUniqueViolation(err) {
			return ctx.JSON(409, api.NewError(errors.New("group name already exists")))
		}
		h.sugar.Errorw("Failed to create group", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	return ctx.JSON(201, GenericDataResponse[relational.UserGroup]{Data: *group})
}

// UpdateGroup godoc
//
//	@Summary		Update a user group
//	@Description	Updates a native CCF user group's name or description
//	@Tags			Groups
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string													true	"Group ID"
//	@Param			group	body		handler.GroupsHandler.UpdateGroup.updateGroupRequest	true	"Group details"
//	@Success		200		{object}	handler.GenericDataResponse[relational.UserGroup]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		409		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/groups/{id} [put]
func (h *GroupsHandler) UpdateGroup(ctx echo.Context) error {
	type updateGroupRequest struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}

	group, err := h.loadGroup(ctx.Param("id"))
	if err != nil {
		return h.groupError(ctx, err)
	}

	var req updateGroupRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind update group request", "error", err)
		return ctx.JSON(400, api.NewError(err))
	}

	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			return ctx.JSON(400, api.NewError(errors.New("name cannot be empty")))
		}
		group.Name = name
	}
	if req.Description != nil {
		group.Description = strings.TrimSpace(*req.Description)
	}

	if err := h.db.Save(group).Error; err != nil {
		if isUniqueViolation(err) {
			return ctx.JSON(409, api.NewError(errors.New("group name already exists")))
		}
		h.sugar.Errorw("Failed to update group", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	return ctx.JSON(200, GenericDataResponse[relational.UserGroup]{Data: *group})
}

// DeleteGroup godoc
//
//	@Summary		Delete a user group
//	@Description	Soft-deletes an empty native CCF user group and removes its SSO mappings. Returns 409 if the group still has members.
//	@Tags			Groups
//	@Param			id	path		string	true	"Group ID"
//	@Success		204	{object}	nil
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		409	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/groups/{id} [delete]
func (h *GroupsHandler) DeleteGroup(ctx echo.Context) error {
	group, err := h.loadGroup(ctx.Param("id"))
	if err != nil {
		return h.groupError(ctx, err)
	}
	if group.ID == nil {
		return ctx.JSON(500, api.NewError(errors.New("group is missing its id")))
	}
	groupID := group.ID.String()

	// Refuse to delete a group that still has members — the operator must empty it first so the
	// removal is deliberate and visible (BCH-1331). The count and the delete run in one
	// transaction (and DeleteGroup never cascade-deletes memberships), so a membership added
	// concurrently is never silently revoked: it either makes the count non-zero (→ 409) or, if it
	// lands after the snapshot, is simply left in place rather than deleted.
	err = h.db.Transaction(func(tx *gorm.DB) error {
		var memberCount int64
		if err := tx.Model(&relational.UserGroupMembership{}).
			Where("group_id = ?", groupID).
			Count(&memberCount).Error; err != nil {
			return err
		}
		if memberCount > 0 {
			return errGroupNotEmpty
		}
		if err := tx.Where("group_id = ?", groupID).Delete(&relational.SSOGroupMapping{}).Error; err != nil {
			return err
		}
		return tx.Delete(&relational.UserGroup{}, "id = ?", groupID).Error
	})
	if errors.Is(err, errGroupNotEmpty) {
		return ctx.JSON(409, api.NewError(errors.New("group still has members; remove all members before deleting")))
	}
	if err != nil {
		h.sugar.Errorw("Failed to delete group", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	return ctx.NoContent(204)
}

// ListMembers godoc
//
//	@Summary		List group members
//	@Description	Lists the users that belong to a native CCF user group
//	@Tags			Groups
//	@Produce		json
//	@Param			id	path		string	true	"Group ID"
//	@Success		200	{object}	handler.GenericDataListResponse[handler.groupMemberResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/groups/{id}/members [get]
func (h *GroupsHandler) ListMembers(ctx echo.Context) error {
	group, err := h.loadGroup(ctx.Param("id"))
	if err != nil {
		return h.groupError(ctx, err)
	}

	// Two-step lookup (member ids, then the users) avoids a column-to-column uuid = text
	// join between ccf_users.id (uuid) and ccf_user_groups.user_id (text), which Postgres
	// rejects; the string IN clause coerces cleanly on both Postgres and SQLite.
	var memberIDs []string
	if err := h.db.Model(&relational.UserGroupMembership{}).
		Where("group_id = ?", group.ID.String()).
		Pluck("user_id", &memberIDs).Error; err != nil {
		h.sugar.Errorw("Failed to list group member ids", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	var users []relational.User
	if len(memberIDs) > 0 {
		if err := h.db.
			Where("id IN ?", memberIDs).
			Order("first_name ASC, last_name ASC").
			Find(&users).Error; err != nil {
			h.sugar.Errorw("Failed to list group members", "error", err)
			return ctx.JSON(500, api.NewError(err))
		}
	}

	responses := make([]groupMemberResponse, 0, len(users))
	for _, u := range users {
		if u.ID == nil {
			continue
		}
		responses = append(responses, groupMemberResponse{
			UserID:      u.ID.String(),
			DisplayName: UserDisplayName(u),
		})
	}

	return ctx.JSON(200, GenericDataListResponse[groupMemberResponse]{Data: responses})
}

// AddMember godoc
//
//	@Summary		Add a group member
//	@Description	Adds a user to a native CCF user group (idempotent)
//	@Tags			Groups
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string												true	"Group ID"
//	@Param			member	body		handler.GroupsHandler.AddMember.addMemberRequest	true	"Member to add"
//	@Success		204		{object}	nil
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/groups/{id}/members [post]
func (h *GroupsHandler) AddMember(ctx echo.Context) error {
	type addMemberRequest struct {
		UserID string `json:"userId" validate:"required"`
	}

	group, err := h.loadGroup(ctx.Param("id"))
	if err != nil {
		return h.groupError(ctx, err)
	}

	var req addMemberRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind add member request", "error", err)
		return ctx.JSON(400, api.NewError(err))
	}

	userUUID, err := uuid.Parse(strings.TrimSpace(req.UserID))
	if err != nil {
		return ctx.JSON(400, api.NewError(errors.New("invalid user id")))
	}

	// The user must exist so a typo can't create a membership for a non-existent principal.
	var user relational.User
	if err := h.db.First(&user, userUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(404, api.NewError(errors.New("user not found")))
		}
		h.sugar.Errorw("Failed to load user for membership", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	membership := &relational.UserGroupMembership{
		UserID:  userUUID.String(),
		GroupID: group.ID.String(),
		Source:  relational.MembershipSourceManual,
	}
	// Idempotent: a repeated add is a no-op rather than a duplicate-key error. FirstOrCreate
	// is SELECT-then-INSERT, so a concurrent duplicate can still lose the race and surface the
	// unique-index violation — which is also "already a member", so treat it as success.
	if err := h.db.Where("user_id = ? AND group_id = ?", membership.UserID, membership.GroupID).
		FirstOrCreate(membership).Error; err != nil {
		if isUniqueViolation(err) {
			return ctx.NoContent(204)
		}
		h.sugar.Errorw("Failed to add group member", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	return ctx.NoContent(204)
}

// RemoveMember godoc
//
//	@Summary		Remove a group member
//	@Description	Removes a manually-added user from a native CCF user group. Returns 403 for SSO-synced memberships, which are managed by the identity provider.
//	@Tags			Groups
//	@Param			id		path		string	true	"Group ID"
//	@Param			userId	path		string	true	"User ID"
//	@Success		204		{object}	nil
//	@Failure		400		{object}	api.Error
//	@Failure		403		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/groups/{id}/members/{userId} [delete]
func (h *GroupsHandler) RemoveMember(ctx echo.Context) error {
	group, err := h.loadGroup(ctx.Param("id"))
	if err != nil {
		return h.groupError(ctx, err)
	}

	userUUID, err := uuid.Parse(strings.TrimSpace(ctx.Param("userId")))
	if err != nil {
		return ctx.JSON(400, api.NewError(errors.New("invalid user id")))
	}

	// Load the membership so its source gates the removal: an sso membership is owned by the IdP
	// (reconciled at login) and may not be hand-removed; only manual ones can. A missing
	// membership is a no-op, preserving the idempotent 204 the API previously returned.
	var membership relational.UserGroupMembership
	err = h.db.
		Where("user_id = ? AND group_id = ?", userUUID.String(), group.ID.String()).
		First(&membership).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.NoContent(204)
		}
		h.sugar.Errorw("Failed to load group member", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}
	if membership.Source == relational.MembershipSourceSSO {
		return ctx.JSON(403, api.NewError(errors.New("cannot remove an SSO-synced member; membership is managed by the identity provider")))
	}

	if err := h.db.
		Where("user_id = ? AND group_id = ?", userUUID.String(), group.ID.String()).
		Delete(&relational.UserGroupMembership{}).Error; err != nil {
		h.sugar.Errorw("Failed to remove group member", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	return ctx.NoContent(204)
}

// ListSSOMappings godoc
//
//	@Summary		List SSO group mappings
//	@Description	Lists the external IdP groups mapped to a native CCF user group
//	@Tags			Groups
//	@Produce		json
//	@Param			id	path		string	true	"Group ID"
//	@Success		200	{object}	handler.GenericDataListResponse[relational.SSOGroupMapping]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/groups/{id}/sso-mappings [get]
func (h *GroupsHandler) ListSSOMappings(ctx echo.Context) error {
	group, err := h.loadGroup(ctx.Param("id"))
	if err != nil {
		return h.groupError(ctx, err)
	}

	var mappings []relational.SSOGroupMapping
	if err := h.db.
		Where("group_id = ?", group.ID.String()).
		Order("provider ASC, external_group ASC").
		Find(&mappings).Error; err != nil {
		h.sugar.Errorw("Failed to list SSO group mappings", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	return ctx.JSON(200, GenericDataListResponse[relational.SSOGroupMapping]{Data: mappings})
}

// AddSSOMapping godoc
//
//	@Summary		Map an SSO group to a user group
//	@Description	Maps an external IdP group (provider + group name) onto a native CCF user group
//	@Tags			Groups
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string													true	"Group ID"
//	@Param			mapping	body		handler.GroupsHandler.AddSSOMapping.addMappingRequest	true	"SSO mapping"
//	@Success		201		{object}	handler.GenericDataResponse[relational.SSOGroupMapping]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		409		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/groups/{id}/sso-mappings [post]
func (h *GroupsHandler) AddSSOMapping(ctx echo.Context) error {
	type addMappingRequest struct {
		Provider      string `json:"provider" validate:"required"`
		ExternalGroup string `json:"externalGroup" validate:"required"`
	}

	group, err := h.loadGroup(ctx.Param("id"))
	if err != nil {
		return h.groupError(ctx, err)
	}

	var req addMappingRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind add SSO mapping request", "error", err)
		return ctx.JSON(400, api.NewError(err))
	}

	provider := strings.TrimSpace(req.Provider)
	externalGroup := strings.TrimSpace(req.ExternalGroup)
	if provider == "" || externalGroup == "" {
		return ctx.JSON(400, api.NewError(errors.New("provider and externalGroup are required")))
	}

	mapping := &relational.SSOGroupMapping{
		Provider:      provider,
		ExternalGroup: externalGroup,
		GroupID:       group.ID.String(),
	}
	if err := h.db.Create(mapping).Error; err != nil {
		if isUniqueViolation(err) {
			return ctx.JSON(409, api.NewError(errors.New("mapping already exists for this provider group")))
		}
		h.sugar.Errorw("Failed to create SSO group mapping", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	return ctx.JSON(201, GenericDataResponse[relational.SSOGroupMapping]{Data: *mapping})
}

// RemoveSSOMapping godoc
//
//	@Summary		Remove an SSO group mapping
//	@Description	Removes an external IdP group mapping from a native CCF user group
//	@Tags			Groups
//	@Param			id			path		string	true	"Group ID"
//	@Param			mappingId	path		string	true	"Mapping ID"
//	@Success		204			{object}	nil
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/groups/{id}/sso-mappings/{mappingId} [delete]
func (h *GroupsHandler) RemoveSSOMapping(ctx echo.Context) error {
	group, err := h.loadGroup(ctx.Param("id"))
	if err != nil {
		return h.groupError(ctx, err)
	}

	mappingUUID, err := uuid.Parse(strings.TrimSpace(ctx.Param("mappingId")))
	if err != nil {
		return ctx.JSON(400, api.NewError(errors.New("invalid mapping id")))
	}

	if err := h.db.
		Where("id = ? AND group_id = ?", mappingUUID.String(), group.ID.String()).
		Delete(&relational.SSOGroupMapping{}).Error; err != nil {
		h.sugar.Errorw("Failed to remove SSO group mapping", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	return ctx.NoContent(204)
}

// loadGroup fetches a group by its id-param string, returning a 400-worthy error for a
// malformed id and gorm.ErrRecordNotFound for an unknown one (mapped by groupError).
func (h *GroupsHandler) loadGroup(idParam string) (*relational.UserGroup, error) {
	groupUUID, err := uuid.Parse(idParam)
	if err != nil {
		return nil, errInvalidGroupID
	}
	var group relational.UserGroup
	if err := h.db.First(&group, groupUUID).Error; err != nil {
		return nil, err
	}
	return &group, nil
}

var errInvalidGroupID = errors.New("invalid group id")

// errGroupNotEmpty is the sentinel DeleteGroup returns from its transaction so a non-empty group
// maps to 409 rather than 500.
var errGroupNotEmpty = errors.New("group still has members")

// groupError maps a loadGroup error to the right status: 400 for a malformed id, 404 for a
// missing group, 500 otherwise.
func (h *GroupsHandler) groupError(ctx echo.Context, err error) error {
	switch {
	case errors.Is(err, errInvalidGroupID):
		return ctx.JSON(400, api.NewError(err))
	case errors.Is(err, gorm.ErrRecordNotFound):
		return ctx.JSON(404, api.NewError(errors.New("group not found")))
	default:
		h.sugar.Errorw("Failed to load group", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}
}

func (h *GroupsHandler) memberCount(groupID string) (int, error) {
	var count int64
	err := h.db.Model(&relational.UserGroupMembership{}).
		Where("group_id = ?", groupID).
		Count(&count).Error
	return int(count), err
}

// memberCounts returns a groupID -> member-count map in one grouped query.
func (h *GroupsHandler) memberCounts() (map[string]int, error) {
	type row struct {
		GroupID string
		Count   int
	}
	var rows []row
	if err := h.db.Model(&relational.UserGroupMembership{}).
		Select("group_id, COUNT(*) AS count").
		Group("group_id").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]int, len(rows))
	for _, r := range rows {
		out[r.GroupID] = r.Count
	}
	return out, nil
}

// isUniqueViolation reports whether err is a Postgres unique-constraint violation. GORM's
// ErrDuplicatedKey translation is unreliable here (see the user handler), so we inspect the
// driver code directly.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
