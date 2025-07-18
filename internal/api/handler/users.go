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
	api.POST("/me/change-password", h.ChangeLoggedInUserPassword)
	api.POST("/:id/change-password", h.ChangePassword)
	api.GET("/me", h.GetMe)
}

func (h *UserHandler) ListUsers(ctx echo.Context) error {
	var users []relational.User

	if err := h.db.Find(&users).Error; err != nil {
		h.sugar.Errorw("Failed to list users", "error", err)
		return ctx.JSON(500, api.NewError(err))
	}

	return ctx.JSON(200, GenericDataListResponse[relational.User]{
		Data: users,
	})
}

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

	return ctx.JSON(200, GenericDataResponse[relational.User]{
		Data: user,
	})

}

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

	return ctx.JSON(200, GenericDataResponse[relational.User]{
		Data: user,
	})
}

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
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
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

	return ctx.NoContent(204)
}

func (h *UserHandler) ChangeLoggedInUserPassword(ctx echo.Context) error {
	// This method will be implemented later to change a user's password.
	return ctx.JSON(501, "Not Implemented")
}

func (h *UserHandler) ChangePassword(ctx echo.Context) error {
	// This method will be implemented later to change a user's password.
	return ctx.JSON(501, "Not Implemented")
}
