package handler

import (
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
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
		if err == gorm.ErrRecordNotFound {
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
		if err == gorm.ErrRecordNotFound {
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
	// This method will be implemented later to create a new user.
	return ctx.JSON(501, "Not Implemented")
}

func (h *UserHandler) UpdateUser(ctx echo.Context) error {
	// This method will be implemented later to update an existing user.
	return ctx.JSON(501, "Not Implemented")
}

func (h *UserHandler) DeleteUser(ctx echo.Context) error {
	// This method will be implemented later to delete a user.
	return ctx.JSON(501, "Not Implemented")
}

func (h *UserHandler) ChangeLoggedInUserPassword(ctx echo.Context) error {
	// This method will be implemented later to change a user's password.
	return ctx.JSON(501, "Not Implemented")
}

func (h *UserHandler) ChangePassword(ctx echo.Context) error {
	// This method will be implemented later to change a user's password.
	return ctx.JSON(501, "Not Implemented")
}
