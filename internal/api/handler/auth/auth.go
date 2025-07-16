package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
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
//
//	@Summary		Login user
//	@Description	Login user and returns a JWT token and sets a cookie with the token
//	@Tags			Auth
//	@Accept			json
//	@Produce		json
//	@Param			loginRequest	body		auth.AuthHandler.LoginUser.loginRequest	true	"Login Data"
//	@Success		200				{object}	handler.GenericDataResponse[auth.AuthHandler.LoginUser.response]
//	@Failure		400				{object}	api.Error
//	@Failure		401				{object}	handler.GenericDataResponse[auth.AuthHandler.LoginUser.errorResponse]
//	@Failure		500				{object}	api.Error
//	@Router			/auth/login [post]
func (h *AuthHandler) LoginUser(ctx echo.Context) error {
	type loginRequest struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	type response struct {
		AuthToken string `json:"auth_token"`
	}

	type errorResponse map[string][]string

	var loginReq loginRequest
	if err := ctx.Bind(&loginReq); err != nil {
		h.sugar.Errorw("Failed to bind login request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	incorrectCredentialsValidation := handler.GenericDataResponse[errorResponse]{
		Data: map[string][]string{
			"email": {
				"Invalid email or password",
			},
		},
	}

	user, unauthorized, err := h.CheckUser(loginReq.Email, loginReq.Password)
	if err != nil {
		if unauthorized {
			return ctx.JSON(http.StatusUnauthorized, incorrectCredentialsValidation)
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	token, err := authn.GenerateJWTToken(user, h.config.JWTPrivateKey)
	if err != nil {
		h.sugar.Errorw("Failed to generate JWT token", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	ret := response{
		AuthToken: *token,
	}

	cookie := new(http.Cookie)

	cookie.Name = "ccf_auth_token"
	cookie.Value = *token
	cookie.Expires = time.Now().Add(time.Hour * 24)
	cookie.HttpOnly = true
	cookie.Secure = true
	cookie.Path = "/"
	ctx.SetCookie(cookie)

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[response]{Data: ret})
}

// GetOAuth2Token godoc
//
//	@Summary		Get OAuth2 token
//	@Description	Get OAuth2 token using username and password
//	@Tags			Auth
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Param			username	formData	string	true	"Username (email)"
//	@Param			password	formData	string	true	"Password"
//	@Success		200			{object}	auth.AuthHandler.GetOAuth2Token.response
//	@Failure		400			{object}	api.Error
//	@Failure		401			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/auth/token [post]
func (h *AuthHandler) GetOAuth2Token(ctx echo.Context) error {
	type response struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	username := ctx.FormValue("username")
	password := ctx.FormValue("password")

	user, unauthorized, err := h.CheckUser(username, password)
	if err != nil {
		if unauthorized {
			return ctx.JSON(http.StatusUnauthorized, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	token, err := authn.GenerateJWTToken(user, h.config.JWTPrivateKey)
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

// CheckUser verifies a user's credentials.
//
// It looks up the user by email (username) in the database. If the user is not found,
// it returns (nil, true, error) where the error is a generic invalid credentials error and
// the boolean indicates unauthorized access. If a database error occurs, it returns (nil, false, error).
// If the user is found but the password does not match, it returns (nil, true, error) with the same
// invalid credentials error. If the credentials are valid, it returns the user, false, and nil error.
//
// Parameters:
//   - username: the user's email address
//   - password: the user's password
//
// Returns:
//   - *[relational.User]: the user object if credentials are valid, otherwise nil
//   - bool: true if unauthorized (invalid credentials), false otherwise
//   - error: error if any occurred, or nil
func (h *AuthHandler) CheckUser(username, password string) (*relational.User, bool, error) {
	var user relational.User
	invalidError := errors.New("invalid email or password")
	if err := h.db.Where("email = ?", username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			h.sugar.Warnw("User not found", "username", username)
			return nil, true, invalidError
		}
		h.sugar.Errorw("Failed to query user", "error", err)
		return nil, false, err
	}

	if !user.CheckPassword(password) {
		h.sugar.Warnw("Invalid password attempt", "username", username)
		return nil, true, invalidError
	}

	return &user, false, nil
}

// GetPublicKeyPEM returns a plaintext representation of the JWT public key in PEM format.
func (h *AuthHandler) GetPublicKeyPEM(ctx echo.Context) error {

	pubPem, err := authn.PublicKeyToPEM(h.config.JWTPublicKey)
	if err != nil {
		h.sugar.Errorw("Failed to marshal public key", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.String(http.StatusOK, string(pubPem))
}

// GetJWK godoc
//
//	@Summary		Get JWK
//	@Description	Get JSON Web Key (JWK) representation of the JWT public key
//	@Tags			Auth
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	authn.JWK
//	@Failure		500	{object}	api.Error
//	@Router			/auth/publickey [get]
func (h *AuthHandler) GetJWK(ctx echo.Context) error {
	jwk := &authn.JWK{}
	jwk, err := jwk.UnmarshalPublicKey(h.config.JWTPublicKey)
	if err != nil {
		h.sugar.Errorw("Failed to unmarshal public key to JWK", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, jwk)
}
