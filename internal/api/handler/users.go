package handler

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type UserHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

type userResponse struct {
	relational.User
	AuthProvider *string `json:"authProvider,omitempty"`
}

type selectableUserResponse struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type publicUserResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type SubscriptionsResponse struct {
	RiskNotificationsSubscribed bool `json:"riskNotificationsSubscribed"`
	// Notifications maps notification types to delivery channels.
	// Supported types include taskAvailable, evidenceDigest, and taskDailyDigest.
	Notifications map[string][]string `json:"notifications"`
}

type UpdateSubscriptionsRequest struct {
	RiskNotificationsSubscribed *bool `json:"riskNotificationsSubscribed"`
	// Notifications maps notification types to delivery channels.
	// Supported types include taskAvailable, evidenceDigest, and taskDailyDigest.
	Notifications map[string][]string `json:"notifications"`
}

const (
	defaultSelectableUsersLimit = 100
	maxSelectableUsersLimit     = 1000
)

var errInvalidNotificationChannels = errors.New("invalid notification channels")
var errInvalidNotificationTypes = errors.New("invalid notification types")

func NewUserHandler(sugar *zap.SugaredLogger, db *gorm.DB) *UserHandler {
	return &UserHandler{
		sugar: sugar,
		db:    db,
	}
}

func (h *UserHandler) Register(api *echo.Group) {
	api.GET("", h.ListUsers)
	api.GET("/:id", h.GetUser)
	api.POST("", h.CreateUser)
	api.PUT("/:id", h.UpdateUser)
	api.DELETE("/:id", h.DeleteUser)
	api.POST("/:id/change-password", h.ChangePassword)
}

func (h *UserHandler) RegisterSelfRoutes(api *echo.Group) {
	api.GET("", h.GetMe)
	api.POST("/change-password", h.ChangeLoggedInUserPassword)
	api.GET("/subscriptions", h.GetSubscriptions)
	api.PUT("/subscriptions", h.UpdateSubscriptions)
}

func (h *UserHandler) RegisterPublicRoutes(api *echo.Group) {
	api.GET("/select", h.ListSelectableUsers)
	api.GET("/:id", h.GetPublicUser)
}

// ListUsers godoc
//
//	@Summary		List all users
//	@Description	Lists all users in the system
//	@Tags			Users
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[relational.User]
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/users [get]
func (h *UserHandler) ListUsers(ctx echo.Context) error {
	var users []relational.User

	if err := h.db.Find(&users).Error; err != nil {
		h.sugar.Errorw("Failed to list users", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	// Convert to userResponse and attach auth providers
	responses := make([]userResponse, len(users))
	for i, user := range users {
		responses[i] = userResponse{User: user}
		h.attachAuthProvider(&responses[i])
	}

	return ctx.JSON(200, GenericDataListResponse[userResponse]{
		Data: responses,
	})
}

// ListSelectableUsers godoc
//
//	@Summary		List selectable users
//	@Description	Lists users with only id and display name for selection controls
//	@Tags			Users
//	@Produce		json
//	@Param			search	query		string	false	"Filter users by name"
//	@Param			limit	query		int		false	"Maximum users to return"
//	@Param			offset	query		int		false	"Number of users to skip"
//	@Success		200		{object}	handler.GenericDataListResponse[handler.selectableUserResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/users/select [get]
func (h *UserHandler) ListSelectableUsers(ctx echo.Context) error {
	search := strings.TrimSpace(ctx.QueryParam("search"))
	query := h.db.Model(&relational.User{}).
		Select("id", "first_name", "last_name").
		Where("is_active = ? AND is_locked = ?", true, false)

	limit := defaultSelectableUsersLimit
	if rawLimit := strings.TrimSpace(ctx.QueryParam("limit")); rawLimit != "" {
		parsedLimit, err := strconv.Atoi(rawLimit)
		if err != nil || parsedLimit < 1 {
			return ctx.JSON(400, api.NewError(fmt.Errorf("invalid limit parameter")))
		}
		if parsedLimit > maxSelectableUsersLimit {
			parsedLimit = maxSelectableUsersLimit
		}
		limit = parsedLimit
	}

	offset := 0
	if rawOffset := strings.TrimSpace(ctx.QueryParam("offset")); rawOffset != "" {
		parsedOffset, err := strconv.Atoi(rawOffset)
		if err != nil || parsedOffset < 0 {
			return ctx.JSON(400, api.NewError(fmt.Errorf("invalid offset parameter")))
		}
		offset = parsedOffset
	}

	if search != "" {
		pattern := "%" + strings.ToLower(search) + "%"
		query = query.Where(
			"LOWER(COALESCE(first_name, '')) LIKE ? OR LOWER(COALESCE(last_name, '')) LIKE ? OR LOWER(COALESCE(first_name, '')) || ' ' || LOWER(COALESCE(last_name, '')) LIKE ?",
			pattern,
			pattern,
			pattern,
		)
	}

	var users []relational.User
	if err := query.Order("first_name ASC, last_name ASC, id ASC").Limit(limit).Offset(offset).Find(&users).Error; err != nil {
		h.sugar.Errorw("Failed to list selectable users", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	responses := make([]selectableUserResponse, 0, len(users))
	for _, user := range users {
		if user.ID == nil {
			continue
		}

		responses = append(responses, selectableUserResponse{
			ID:          user.ID.String(),
			DisplayName: userDisplayName(user),
		})
	}

	return ctx.JSON(200, GenericDataListResponse[selectableUserResponse]{
		Data: responses,
	})
}

// GetUser godoc
//
//	@Summary		Get user by ID
//	@Description	Get user details by user ID
//	@Tags			Users
//	@Produce		json
//	@Param			id	path		string	true	"User ID"
//	@Success		200	{object}	handler.GenericDataResponse[relational.User]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/users/{id} [get]
func (h *UserHandler) GetUser(ctx echo.Context) error {
	userID := ctx.Param("id")

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		h.sugar.Errorw("Invalid user ID", "error", err)
		return ctx.JSON(400, api.NewError(err))
	}

	var user relational.User
	if err := h.db.First(&user, userUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(404, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get user", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	response := userResponse{
		User: user,
	}

	h.attachAuthProvider(&response)

	return ctx.JSON(200, GenericDataResponse[userResponse]{
		Data: response,
	})
}

// GetPublicUser godoc
//
//	@Summary		Get public user details by ID
//	@Description	Get minimal user details by user ID
//	@Tags			Users
//	@Produce		json
//	@Param			id	path		string	true	"User ID"
//	@Success		200	{object}	handler.GenericDataResponse[handler.publicUserResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/users/{id} [get]
func (h *UserHandler) GetPublicUser(ctx echo.Context) error {
	userID := ctx.Param("id")

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		h.sugar.Warnw("Invalid user ID", "error", err, "user_id", userID)
		return ctx.JSON(400, api.NewError(err))
	}

	var user relational.User
	if err := h.db.First(&user, userUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(404, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get public user", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	return ctx.JSON(200, GenericDataResponse[publicUserResponse]{
		Data: publicUserResponse{
			ID:   user.ID.String(),
			Name: userDisplayName(user),
		},
	})
}

func (h *UserHandler) attachAuthProvider(resp *userResponse) {
	if resp == nil || resp.ID == nil {
		return
	}

	if resp.AuthMethod != "sso" {
		return
	}

	var link relational.SSOUserLink
	if err := h.db.
		Where("user_id = ? AND deleted_at IS NULL", resp.User.ID.String()).
		Order("last_sync DESC").
		First(&link).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Failed to load SSO provider for user", "userID", resp.ID.String(), "error", err)
		}
		return
	}

	resp.AuthProvider = &link.Provider
}

func userDisplayName(user relational.User) string {
	if user.ID == nil {
		return ""
	}

	if displayName := strings.TrimSpace(strings.TrimSpace(user.FirstName) + " " + strings.TrimSpace(user.LastName)); displayName != "" {
		return displayName
	}

	return user.ID.String()
}

// GetMe godoc
//
//	@Summary		Get logged-in user details
//	@Description	Retrieves the details of the currently logged-in user
//	@Tags			Users
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[relational.User]
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/users/me [get]
func (h *UserHandler) GetMe(ctx echo.Context) error {
	userClaims := ctx.Get("user").(*authn.UserClaims)

	email := userClaims.Subject
	var user relational.User
	if err := h.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(404, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get user by email", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	response := userResponse{
		User: user,
	}

	h.attachAuthProvider(&response)

	return ctx.JSON(200, GenericDataResponse[userResponse]{
		Data: response,
	})
}

// CreateUser godoc
//
//	@Summary		Create a new user
//	@Description	Creates a new user in the system
//	@Tags			Users
//	@Accept			json
//	@Produce		json
//	@Param			user	body		handler.UserHandler.CreateUser.createUserRequest	true	"User details"
//	@Success		201		{object}	handler.GenericDataResponse[relational.User]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		409		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/users [post]
func (h *UserHandler) CreateUser(ctx echo.Context) error {
	type createUserRequest struct {
		Email     string `json:"email" validate:"required,email"`
		Password  string `json:"password" validate:"required"`
		FirstName string `json:"firstName" validate:"required"`
		LastName  string `json:"lastName" validate:"required"`
	}

	var req createUserRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind create user request", "error", err)
		return ctx.JSON(400, api.NewError(err))
	}

	user := &relational.User{
		Email:      req.Email,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		AuthMethod: "password",
	}
	if err := user.SetPassword(req.Password); err != nil {
		h.sugar.Errorw("Failed to set user password", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	if err := h.db.Create(user).Error; err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" { // Unique violation, gorm error Translation for 23505/ErrDuplicatedKey doesn't work consistently
			return ctx.JSON(409, api.NewError(errors.New("email already exists")))
		}
		h.sugar.Errorw("Failed to create user", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	return ctx.JSON(201, GenericDataResponse[relational.User]{
		Data: *user,
	})
}

// UpdateUser godoc
//
//	@Summary		Update user details
//	@Description	Updates the details of an existing user
//	@Tags			Users
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string												true	"User ID"
//	@Param			user	body		handler.UserHandler.UpdateUser.updateUserRequest	true	"User details"
//	@Success		200		{object}	handler.GenericDataResponse[relational.User]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/users/{id} [put]
func (h *UserHandler) UpdateUser(ctx echo.Context) error {
	type updateUserRequest struct {
		FirstName    *string `json:"firstName"`
		LastName     *string `json:"lastName"`
		IsActive     *bool   `json:"isActive"`
		IsLocked     *bool   `json:"isLocked"`
		FailedLogins *int    `json:"failedLogins"`
	}

	userID := ctx.Param("id")
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		h.sugar.Errorw("Invalid user ID", "error", err)
		return ctx.JSON(400, api.NewError(err))
	}

	var req updateUserRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind update user request", "error", err)
		return ctx.JSON(400, api.NewError(err))
	}

	var user relational.User
	if err := h.db.First(&user, userUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(404, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get user for update", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	if req.FirstName != nil {
		user.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		user.LastName = *req.LastName
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	if req.IsLocked != nil {
		user.IsLocked = *req.IsLocked
	}
	if req.FailedLogins != nil {
		user.FailedLogins = *req.FailedLogins
	}
	if err := h.db.Save(&user).Error; err != nil {
		h.sugar.Errorw("Failed to update user", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}
	return ctx.JSON(200, GenericDataResponse[relational.User]{
		Data: user,
	})
}

// DeleteUser godoc
//
//	@Summary		Delete a user
//	@Description	Deletes a user from the system
//	@Tags			Users
//	@Param			id	path		string	true	"User ID"
//	@Success		204	{object}	nil
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/users/{id} [delete]
func (h *UserHandler) DeleteUser(ctx echo.Context) error {
	userID := ctx.Param("id")
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		h.sugar.Errorw("Invalid user ID", "error", err)
		return ctx.JSON(400, api.NewError(err))
	}

	if err := h.db.Delete(&relational.User{}, userUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(404, api.NewError(err))
		}
		h.sugar.Errorw("Failed to delete user", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	if err := h.db.Unscoped().
		Where("user_id = ?", userUUID.String()).
		Delete(&relational.SSOUserLink{}).Error; err != nil {
		h.sugar.Warnw("Failed to remove SSO bindings for deleted user", "userID", userUUID.String(), "error", err)
	}
	if err := h.db.Unscoped().
		Where("user_id = ?", userUUID.String()).
		Delete(&relational.SlackUserLink{}).Error; err != nil {
		h.sugar.Warnw("Failed to remove Slack bindings for deleted user", "userID", userUUID.String(), "error", err)
	}
	if err := h.db.Unscoped().
		Where("user_id = ?", userUUID.String()).
		Delete(&relational.SlackLinkAttempt{}).Error; err != nil {
		h.sugar.Warnw("Failed to remove Slack link attempts for deleted user", "userID", userUUID.String(), "error", err)
	}

	return ctx.NoContent(204)
}

// ChangeLoggedInUserPassword godoc
//
//	@Summary		Change password for logged-in user
//	@Description	Changes the password for the currently logged-in user
//	@Tags			Users
//	@Accept			json
//	@Produce		json
//	@Param			changePasswordRequest	body		handler.UserHandler.ChangeLoggedInUserPassword.changePasswordRequest	true	"Change Password Request"
//	@Success		204						{object}	nil
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/users/me/change-password [post]
func (h *UserHandler) ChangeLoggedInUserPassword(ctx echo.Context) error {
	userClaims := ctx.Get("user").(*authn.UserClaims)

	email := userClaims.Subject
	var user relational.User
	if err := h.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(404, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get user by email", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	type changePasswordRequest struct {
		OldPassword string `json:"oldPassword" validate:"required"`
		NewPassword string `json:"newPassword" validate:"required"`
	}
	var req changePasswordRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind change password request", "error", err)
		return ctx.JSON(400, api.NewError(err))
	}

	if !user.CheckPassword(req.OldPassword) {
		h.sugar.Errorw("Old password does not match", "email", email)
		return ctx.JSON(400, api.NewError(errors.New("old password does not match")))
	}

	if err := user.SetPassword(req.NewPassword); err != nil {
		h.sugar.Errorw("Failed to set new password", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}
	if err := h.db.Save(&user).Error; err != nil {
		h.sugar.Errorw("Failed to update user password", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	return ctx.NoContent(204)
}

// GetSubscriptions godoc
//
//	@Summary		Get notification preferences
//	@Description	Gets the current user's digest and workflow notification email preferences
//	@Tags			Users
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[handler.SubscriptionsResponse]
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/users/me/subscriptions [get]
func (h *UserHandler) GetSubscriptions(ctx echo.Context) error {
	userClaims := ctx.Get("user").(*authn.UserClaims)

	email := userClaims.Subject
	var user relational.User
	if err := h.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(404, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get user by email", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	notifications, err := h.loadUserNotificationSubscriptions(ctx.Request().Context(), user.ID.String())
	if err != nil {
		h.sugar.Errorw("Failed to load user notifications", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	return ctx.JSON(200, GenericDataResponse[SubscriptionsResponse]{
		Data: SubscriptionsResponse{
			RiskNotificationsSubscribed: user.RiskNotificationsSubscribed,
			Notifications:               notifications,
		},
	})
}

// UpdateSubscriptions godoc
//
//	@Summary		Update notification preferences
//	@Description	Updates the current user's digest and workflow notification email preferences
//	@Tags			Users
//	@Accept			json
//	@Produce		json
//	@Param			subscription	body		handler.UpdateSubscriptionsRequest	true	"Notification preferences"
//	@Success		200				{object}	handler.GenericDataResponse[handler.SubscriptionsResponse]
//	@Failure		400				{object}	api.Error
//	@Failure		401				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/users/me/subscriptions [put]
func (h *UserHandler) UpdateSubscriptions(ctx echo.Context) error {
	userClaims := ctx.Get("user").(*authn.UserClaims)

	var req UpdateSubscriptionsRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind update subscriptions request", "error", err)
		return ctx.JSON(400, api.NewError(err))
	}

	var normalizedNotifications map[string][]string
	if req.Notifications != nil {
		normalized, err := normalizeNotificationSubscriptions(req.Notifications)
		if err != nil {
			h.sugar.Warnw("Rejected invalid notification channels", "error", err)
			return ctx.JSON(400, api.NewError(err))
		}
		normalizedNotifications = normalized
	}

	email := userClaims.Subject
	var user relational.User
	if err := h.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(404, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get user by email", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	if req.RiskNotificationsSubscribed != nil {
		user.RiskNotificationsSubscribed = *req.RiskNotificationsSubscribed
	}

	if err := h.db.Save(&user).Error; err != nil {
		h.sugar.Errorw("Failed to update user subscriptions", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	if req.Notifications != nil {
		if err := h.replaceUserNotificationSubscriptions(ctx.Request().Context(), user.ID.String(), normalizedNotifications); err != nil {
			h.sugar.Errorw("Failed to update user notifications", "error", err)
			return ctx.JSON(500, api.NewError(err))
		}
	}

	notifications, err := h.loadUserNotificationSubscriptions(ctx.Request().Context(), user.ID.String())
	if err != nil {
		h.sugar.Errorw("Failed to load user notifications", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	h.sugar.Debugw(
		"User subscriptions updated",
		"email", email,
		"riskNotificationsSubscribed", user.RiskNotificationsSubscribed,
		"notifications", notifications,
	)

	return ctx.JSON(200, GenericDataResponse[SubscriptionsResponse]{
		Data: SubscriptionsResponse{
			RiskNotificationsSubscribed: user.RiskNotificationsSubscribed,
			Notifications:               notifications,
		},
	})
}

func (h *UserHandler) loadUserNotificationSubscriptions(ctx context.Context, userID string) (map[string][]string, error) {
	var rows []relational.UserNotificationSubscription
	if err := h.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Find(&rows).Error; err != nil {
		return nil, err
	}

	out := make(map[string][]string, len(rows))
	for i := range rows {
		channels := make([]string, len(rows[i].Channels))
		copy(channels, rows[i].Channels)
		wireType, ok := notification.WireNotificationType(rows[i].NotificationType)
		if !ok {
			wireType = rows[i].NotificationType
		}
		out[wireType] = channels
	}

	return out, nil
}

func normalizeNotificationSubscriptions(notifications map[string][]string) (map[string][]string, error) {
	if notifications == nil {
		return nil, nil
	}

	channelSets := make(map[string]map[string]struct{}, len(notifications))
	for notificationType, channels := range notifications {
		normalizedType, ok := notification.NormalizeNotificationType(notificationType)
		if !ok {
			invalidType := strings.ToLower(strings.TrimSpace(notificationType))
			return nil, fmt.Errorf("%w: %q", errInvalidNotificationTypes, invalidType)
		}

		normalizedChannels, invalidChannels := notification.NormalizeDeliveryChannels(channels)
		if len(invalidChannels) > 0 {
			return nil, fmt.Errorf("%w for %q: %s", errInvalidNotificationChannels, normalizedType, quoteList(invalidChannels))
		}

		if _, exists := channelSets[normalizedType]; !exists {
			channelSets[normalizedType] = make(map[string]struct{}, len(normalizedChannels))
		}
		for _, channel := range normalizedChannels {
			channelSets[normalizedType][channel] = struct{}{}
		}
	}

	out := make(map[string][]string, len(channelSets))
	for normalizedType, set := range channelSets {
		channels := make([]string, 0, len(set))
		for channel := range set {
			channels = append(channels, channel)
		}
		sort.Strings(channels)
		out[normalizedType] = channels
	}

	return out, nil
}

func quoteList(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, strconv.Quote(v))
	}
	return strings.Join(quoted, ", ")
}

func (h *UserHandler) replaceUserNotificationSubscriptions(ctx context.Context, userID string, notifications map[string][]string) error {
	return h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&relational.UserNotificationSubscription{}).Error; err != nil {
			return err
		}

		if len(notifications) == 0 {
			return nil
		}

		types := make([]string, 0, len(notifications))
		for notificationType := range notifications {
			notificationType = strings.TrimSpace(notificationType)
			if notificationType != "" {
				types = append(types, notificationType)
			}
		}
		sort.Strings(types)

		rows := make([]relational.UserNotificationSubscription, 0, len(types))
		for _, notificationType := range types {
			rows = append(rows, relational.UserNotificationSubscription{
				UserID:           userID,
				NotificationType: notificationType,
				Channels:         notifications[notificationType],
			})
		}

		if len(rows) == 0 {
			return nil
		}

		return tx.Create(&rows).Error
	})
}

// ChangePassword godoc
//
//	@Summary		Change password for a specific user
//	@Description	Changes the password for a user by ID
//	@Tags			Users
//	@Accept			json
//	@Produce		json
//	@Param			id						path		string														true	"User ID"
//	@Param			changePasswordRequest	body		handler.UserHandler.ChangePassword.changePasswordRequest	true	"Change Password Request"
//	@Success		204						{object}	nil
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		404						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/users/{id}/change-password [post]
func (h *UserHandler) ChangePassword(ctx echo.Context) error {
	userID := ctx.Param("id")
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		h.sugar.Errorw("Invalid user ID", "error", err)
		return ctx.JSON(400, api.NewError(err))
	}

	var user relational.User
	if err := h.db.First(&user, userUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(404, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get user for update", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	type changePasswordRequest struct {
		NewPassword string `json:"newPassword" validate:"required"`
	}
	var req changePasswordRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind change password request", "error", err)
		return ctx.JSON(400, api.NewError(err))
	}

	if err := user.SetPassword(req.NewPassword); err != nil {
		h.sugar.Errorw("Failed to set new password", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}
	if err := h.db.Save(&user).Error; err != nil {
		h.sugar.Errorw("Failed to update user password", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	return ctx.NoContent(204)
}
