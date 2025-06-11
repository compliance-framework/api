package auth

import (
	"errors"

	"net/http"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/authn"
	"github.com/compliance-framework/configuration-service/internal/config"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type AuthHandler struct {
	sugar  *zap.SugaredLogger
	db     *gorm.DB
	config *config.Config
}

func NewAuthHandler(logger *zap.SugaredLogger, db *gorm.DB, config *config.Config) *AuthHandler {
	return &AuthHandler{
		sugar:  logger,
		db:     db,
		config: config,
	}
}

func (h *AuthHandler) Register(api *echo.Group) {
	api.POST("/login", h.LoginUser)
	api.POST("/token", h.GetOAuth2Token)
	api.GET("/publickey.pub", h.GetPublicKeyPEM)
	api.GET("/publickey", h.GetJWK)
}

// LoginUser godoc
//	@Summary	Login user

func (h *AuthHandler) LoginUser(ctx echo.Context) error {
	type loginRequest struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	type response struct {
		AuthToken string `json:"auth_token"`
	}

	var loginReq loginRequest
	if err := ctx.Bind(&loginReq); err != nil {
		h.sugar.Errorw("Failed to bind login request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var user relational.User
	if err := h.db.Where("email = ?", loginReq.Email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			h.sugar.Warnw("User not found", "email", loginReq.Email)
			return ctx.JSON(http.StatusUnauthorized, api.NewError(errors.New("invalid email or password")))
		}
		h.sugar.Errorw("Failed to query user", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if !user.CheckPassword(loginReq.Password) {
		h.sugar.Warnw("Invalid password attempt", "email", loginReq.Email)
		return ctx.JSON(http.StatusUnauthorized, api.NewError(errors.New("invalid email or password")))
	}

	token, err := authn.GenerateJWTToken(&user, h.config.JWTPrivateKey)
	if err != nil {
		h.sugar.Errorw("Failed to generate JWT token", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	ret := response{
		AuthToken: *token,
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[response]{Data: ret})
}

func (h *AuthHandler) GetOAuth2Token(ctx echo.Context) error {
	type response struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	username := ctx.FormValue("username")
	password := ctx.FormValue("password")

	var user relational.User
	if err := h.db.Where("email = ?", username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			h.sugar.Warnw("User not found", "username", username)
			return ctx.JSON(http.StatusUnauthorized, api.NewError(errors.New("invalid email or password")))
		}
		h.sugar.Errorw("Failed to query user", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if !user.CheckPassword(password) {
		h.sugar.Warnw("Invalid password attempt", "username", username)
		return ctx.JSON(http.StatusUnauthorized, api.NewError(errors.New("invalid email or password")))
	}

	token, err := authn.GenerateJWTToken(&user, h.config.JWTPrivateKey)
	if err != nil {
		h.sugar.Errorw("Failed to generate JWT token", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	ret := &response{
		AccessToken: *token,
		TokenType:   "bearer",
		ExpiresIn:   86400,
	}

	return ctx.JSON(http.StatusOK, ret)
}

func (h *AuthHandler) GetPublicKeyPEM(ctx echo.Context) error {

	pubPem, err := authn.PublicKeyToPEM(h.config.JWTPublicKey)
	if err != nil {
		h.sugar.Errorw("Failed to marshal public key", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.String(http.StatusOK, string(pubPem))
}

func (h *AuthHandler) GetJWK(ctx echo.Context) error {
	jwk := &authn.JWK{}
	jwk, err := jwk.UnmarshalPublicKey(h.config.JWTPublicKey)
	if err != nil {
		h.sugar.Errorw("Failed to unmarshal public key to JWK", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, jwk)
}
