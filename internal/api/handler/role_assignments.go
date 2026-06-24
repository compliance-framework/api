package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// RoleAssignmentsHandler serves the admin API for system-level role assignments (BCH-1333):
// granting manifest roles to users and groups, and reading a subject's effective roles. The
// persisted ccf_role_assignments table it manages is the PDP's source of truth for roles (the
// cedar engine reads it via authz.NewDBRoleResolver), so a grant created here takes effect for
// authorization within the resolver's short cache TTL. It is distinct from the workflow
// role-assignment handler, which manages workflow-instance-scoped step personas.
type RoleAssignmentsHandler struct {
	sugar    *zap.SugaredLogger
	db       *gorm.DB
	manifest *authz.Manifest
}

func NewRoleAssignmentsHandler(sugar *zap.SugaredLogger, db *gorm.DB) *RoleAssignmentsHandler {
	// The manifest is parsed and validated once at startup (RegisterHandlers fails fast if it is
	// broken), so a nil here only happens in a misconfigured process; isKnownRole guards against it.
	manifest, _ := authz.DefaultManifest()
	return &RoleAssignmentsHandler{sugar: sugar, db: db, manifest: manifest}
}

// Register mounts the role-assignment CRUD under /admin/role-assignments, gated on the
// role-assignment resource (as the workflow handler is) rather than the admin umbrella.
func (h *RoleAssignmentsHandler) Register(api *echo.Group, guard middleware.ResourceGuard) {
	api.POST("", h.Create, guard.Create())
	api.GET("", h.List, guard.Read())
	api.DELETE("/:id", h.Delete, guard.Delete())
}

// RegisterUserRoles mounts GET /admin/users/:id/roles. It lives in this handler (not the user
// handler) so all role-assignment reads share one guard and one resolution path.
func (h *RoleAssignmentsHandler) RegisterUserRoles(api *echo.Group, guard middleware.ResourceGuard) {
	api.GET("/:id/roles", h.UserRoles, guard.Read())
}

// RegisterGroupRoles mounts GET /admin/groups/:id/roles.
func (h *RoleAssignmentsHandler) RegisterGroupRoles(api *echo.Group, guard middleware.ResourceGuard) {
	api.GET("/:id/roles", h.GroupRoles, guard.Read())
}

type createRoleAssignmentRequest struct {
	RoleName     string `json:"roleName" validate:"required"`
	AssigneeType string `json:"assigneeType" validate:"required"`
	AssigneeID   string `json:"assigneeId" validate:"required"`
}

// effectiveRole is one entry in a subject's effective-role view. A role granted both directly
// and via a group appears once per grant (provenance is preserved), so the UI can show why a
// subject holds a role and whether the grant is config-locked.
type effectiveRole struct {
	AssignmentID string `json:"assignmentId"`
	RoleName     string `json:"roleName"`
	Source       string `json:"source"`             // config (immutable) | manual (deletable)
	Inherited    bool   `json:"inherited"`          // false = a direct grant to the subject
	ViaGroup     string `json:"viaGroup,omitempty"` // the granting group's name, when inherited
}

// Create godoc
//
//	@Summary		Create a role assignment
//	@Description	Grants a manifest role to a user (by email) or group (by name), system-wide. The grant is source=manual and becomes the PDP's source of truth for that subject's role.
//	@Tags			RoleAssignments
//	@Accept			json
//	@Produce		json
//	@Param			assignment	body		handler.createRoleAssignmentRequest	true	"Role assignment"
//	@Success		201			{object}	handler.GenericDataResponse[relational.CCFRoleAssignment]
//	@Failure		400			{object}	api.Error
//	@Failure		409			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/role-assignments [post]
func (h *RoleAssignmentsHandler) Create(ctx echo.Context) error {
	var req createRoleAssignmentRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind create role assignment request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	assigneeType := strings.ToLower(strings.TrimSpace(req.AssigneeType))
	if assigneeType != relational.RoleAssigneeTypeUser && assigneeType != relational.RoleAssigneeTypeGroup {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("assigneeType must be 'user' or 'group'")))
	}

	roleName := strings.TrimSpace(req.RoleName)
	if !h.isKnownRole(roleName) {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("unknown role: "+roleName)))
	}

	assigneeID := relational.NormalizeAssigneeID(req.AssigneeID)
	if assigneeID == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("assigneeId is required")))
	}

	assignment := &relational.CCFRoleAssignment{
		RoleName:     roleName,
		AssigneeType: assigneeType,
		AssigneeID:   assigneeID,
		Source:       relational.RoleAssignmentSourceManual,
	}
	if err := h.db.Create(assignment).Error; err != nil {
		if isUniqueViolation(err) {
			return ctx.JSON(http.StatusConflict, api.NewError(errors.New("this role is already assigned to that assignee")))
		}
		h.sugar.Errorw("Failed to create role assignment", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, GenericDataResponse[relational.CCFRoleAssignment]{Data: *assignment})
}

// List godoc
//
//	@Summary		List role assignments
//	@Description	Lists system-level role assignments, optionally filtered by assignee (type and/or id) or role.
//	@Tags			RoleAssignments
//	@Produce		json
//	@Param			assigneeType	query		string	false	"Filter by assignee type (user|group)"
//	@Param			assigneeId		query		string	false	"Filter by assignee id (email or group name)"
//	@Param			roleName		query		string	false	"Filter by role name"
//	@Success		200				{object}	handler.GenericDataListResponse[relational.CCFRoleAssignment]
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/role-assignments [get]
func (h *RoleAssignmentsHandler) List(ctx echo.Context) error {
	q := h.db.Model(&relational.CCFRoleAssignment{})
	if t := strings.ToLower(strings.TrimSpace(ctx.QueryParam("assigneeType"))); t != "" {
		q = q.Where("assignee_type = ?", t)
	}
	if id := ctx.QueryParam("assigneeId"); strings.TrimSpace(id) != "" {
		q = q.Where("assignee_id = ?", relational.NormalizeAssigneeID(id))
	}
	if role := strings.TrimSpace(ctx.QueryParam("roleName")); role != "" {
		q = q.Where("role_name = ?", role)
	}

	var assignments []relational.CCFRoleAssignment
	if err := q.Order("assignee_type ASC, assignee_id ASC, role_name ASC").Find(&assignments).Error; err != nil {
		h.sugar.Errorw("Failed to list role assignments", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[relational.CCFRoleAssignment]{Data: assignments})
}

// Delete godoc
//
//	@Summary		Delete a role assignment
//	@Description	Deletes a manual role assignment. Config-sourced grants (managed by the boot reconcile) cannot be deleted and return 409.
//	@Tags			RoleAssignments
//	@Param			id	path		string	true	"Role assignment ID"
//	@Success		204	{object}	nil
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		409	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/role-assignments/{id} [delete]
func (h *RoleAssignmentsHandler) Delete(ctx echo.Context) error {
	id, err := uuid.Parse(strings.TrimSpace(ctx.Param("id")))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("invalid role assignment id")))
	}

	var assignment relational.CCFRoleAssignment
	if err := h.db.First(&assignment, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(errors.New("role assignment not found")))
		}
		h.sugar.Errorw("Failed to load role assignment", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Config grants are owned by the boot reconcile (BCH-1334): refuse to delete one so the API
	// and the config file never fight over the same row.
	if assignment.Source == relational.RoleAssignmentSourceConfig {
		return ctx.JSON(http.StatusConflict, api.NewError(errors.New("cannot delete a config-managed role assignment")))
	}

	if err := h.db.Delete(&relational.CCFRoleAssignment{}, id).Error; err != nil {
		h.sugar.Errorw("Failed to delete role assignment", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// UserRoles godoc
//
//	@Summary		Get a user's effective roles
//	@Description	Returns a user's effective roles: direct grants plus roles inherited from the user's native groups (each inherited entry names the granting group). Matches what the PDP enforces.
//	@Tags			RoleAssignments
//	@Produce		json
//	@Param			id	path		string	true	"User ID"
//	@Success		200	{object}	handler.GenericDataListResponse[handler.effectiveRole]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/users/{id}/roles [get]
func (h *RoleAssignmentsHandler) UserRoles(ctx echo.Context) error {
	userUUID, err := uuid.Parse(strings.TrimSpace(ctx.Param("id")))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("invalid user id")))
	}

	var user relational.User
	if err := h.db.First(&user, userUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(errors.New("user not found")))
		}
		h.sugar.Errorw("Failed to load user", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	out := make([]effectiveRole, 0)

	// Direct grants — keyed by the user's email, the subject identifier authz carries.
	var direct []relational.CCFRoleAssignment
	if err := h.db.
		Where("assignee_type = ? AND assignee_id = ?", relational.RoleAssigneeTypeUser, relational.NormalizeAssigneeID(user.Email)).
		Order("role_name ASC").
		Find(&direct).Error; err != nil {
		h.sugar.Errorw("Failed to load direct role assignments", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	for _, a := range direct {
		out = append(out, effectiveRole{AssignmentID: idString(a.ID), RoleName: a.RoleName, Source: a.Source})
	}

	// Inherited grants — one lookup per native group, so each inherited role can name its group.
	// GroupNamesForUser returns the same native memberships the PDP's group resolver feeds into
	// subject.groups, so this view matches what is enforced.
	groups, err := relational.GroupNamesForUser(h.db, user.ID.String())
	if err != nil {
		h.sugar.Errorw("Failed to load user groups", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	for _, groupName := range groups {
		var grants []relational.CCFRoleAssignment
		if err := h.db.
			Where("assignee_type = ? AND assignee_id = ?", relational.RoleAssigneeTypeGroup, relational.NormalizeAssigneeID(groupName)).
			Order("role_name ASC").
			Find(&grants).Error; err != nil {
			h.sugar.Errorw("Failed to load group role assignments", "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
		for _, a := range grants {
			out = append(out, effectiveRole{AssignmentID: idString(a.ID), RoleName: a.RoleName, Source: a.Source, Inherited: true, ViaGroup: groupName})
		}
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[effectiveRole]{Data: out})
}

// GroupRoles godoc
//
//	@Summary		Get a group's roles
//	@Description	Returns the roles assigned directly to a native CCF group.
//	@Tags			RoleAssignments
//	@Produce		json
//	@Param			id	path		string	true	"Group ID"
//	@Success		200	{object}	handler.GenericDataListResponse[relational.CCFRoleAssignment]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/groups/{id}/roles [get]
func (h *RoleAssignmentsHandler) GroupRoles(ctx echo.Context) error {
	groupUUID, err := uuid.Parse(strings.TrimSpace(ctx.Param("id")))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("invalid group id")))
	}

	var group relational.UserGroup
	if err := h.db.First(&group, groupUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(errors.New("group not found")))
		}
		h.sugar.Errorw("Failed to load group", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var grants []relational.CCFRoleAssignment
	if err := h.db.
		Where("assignee_type = ? AND assignee_id = ?", relational.RoleAssigneeTypeGroup, relational.NormalizeAssigneeID(group.Name)).
		Order("role_name ASC").
		Find(&grants).Error; err != nil {
		h.sugar.Errorw("Failed to load group role assignments", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[relational.CCFRoleAssignment]{Data: grants})
}

// isKnownRole reports whether roleName is a role the manifest declares, so a typo is rejected
// at write time rather than silently granting nothing (the file-based path validated the same way).
func (h *RoleAssignmentsHandler) isKnownRole(roleName string) bool {
	if h.manifest == nil || roleName == "" {
		return false
	}
	_, ok := h.manifest.Roles[roleName]
	return ok
}

// idString renders a *uuid.UUID as its canonical string, or "" when nil.
func idString(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
