package handler

import (
	"errors"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/authn"
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

type SubscriptionsResponse struct {
	Subscribed                   bool `json:"subscribed"`
	TaskAvailableEmailSubscribed bool `json:"taskAvailableEmailSubscribed"`
	TaskDailyDigestSubscribed    bool `json:"taskDailyDigestSubscribed"`
}

type UpdateSubscriptionsRequest struct {
	Subscribed                   *bool `json:"subscribed"`
	TaskAvailableEmailSubscribed *bool `json:"taskAvailableEmailSubscribed"`
	TaskDailyDigestSubscribed    *bool `json:"taskDailyDigestSubscribed"`
}

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
	api.GET("/me", h.GetMe)
	api.POST("/me/change-password", h.ChangeLoggedInUserPassword)
	api.GET("/me/subscriptions", h.GetSubscriptions)
	api.PUT("/me/subscriptions", h.UpdateSubscriptions)
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

	return ctx.JSON(200, GenericDataResponse[SubscriptionsResponse]{
		Data: SubscriptionsResponse{
			Subscribed:                   user.DigestSubscribed,
			TaskAvailableEmailSubscribed: user.TaskAvailableEmailSubscribed,
			TaskDailyDigestSubscribed:    user.TaskDailyDigestSubscribed,
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

	email := userClaims.Subject
	var user relational.User
	if err := h.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(404, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get user by email", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	if req.Subscribed != nil {
		user.DigestSubscribed = *req.Subscribed
	}
	if req.TaskAvailableEmailSubscribed != nil {
		user.TaskAvailableEmailSubscribed = *req.TaskAvailableEmailSubscribed
	}
	if req.TaskDailyDigestSubscribed != nil {
		user.TaskDailyDigestSubscribed = *req.TaskDailyDigestSubscribed
	}

	if err := h.db.Save(&user).Error; err != nil {
		h.sugar.Errorw("Failed to update user subscriptions", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	h.sugar.Debugw(
		"User subscriptions updated",
		"email", email,
		"subscribed", user.DigestSubscribed,
		"taskAvailableEmailSubscribed", user.TaskAvailableEmailSubscribed,
		"taskDailyDigestSubscribed", user.TaskDailyDigestSubscribed,
	)

	return ctx.JSON(200, GenericDataResponse[SubscriptionsResponse]{
		Data: SubscriptionsResponse{
			Subscribed:                   user.DigestSubscribed,
			TaskAvailableEmailSubscribed: user.TaskAvailableEmailSubscribed,
			TaskDailyDigestSubscribed:    user.TaskDailyDigestSubscribed,
		},
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
