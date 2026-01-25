package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email"
	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/worker"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type AuthHandler struct {
	sugar         *zap.SugaredLogger
	db            *gorm.DB
	config        *config.Config
	metrics       *api.PrometheusMetrics
	emailService  *email.Service
	workerService *worker.Service
}

func NewAuthHandler(logger *zap.SugaredLogger, db *gorm.DB, config *config.Config, metrics *api.PrometheusMetrics, emailService *email.Service, workerService *worker.Service) *AuthHandler {
	return &AuthHandler{
		sugar:         logger,
		db:            db,
		config:        config,
		metrics:       metrics,
		emailService:  emailService,
		workerService: workerService,
	}
}

func (h *AuthHandler) Register(api *echo.Group) {
	api.POST("/login", h.LoginUser)
	api.POST("/token", h.GetOAuth2Token)
	api.GET("/publickey.pub", h.GetPublicKeyPEM)
	api.GET("/publickey", h.GetJWK)

	// Password reset endpoints
	api.POST("/forgot-password", h.ForgotPassword)
	api.POST("/password-reset", h.PasswordReset)
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
	cookie.Path = "/"
	cookie.SameSite = http.SameSiteStrictMode

	if isDevelopmentEnvironment(h.config.Environment) {
		cookie.Secure = false
	} else {
		cookie.Secure = true
	}

	ctx.SetCookie(cookie)

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[response]{Data: ret})
}

func isDevelopmentEnvironment(env string) bool {
	return env == string(config.EnvironmentLocal) || env == string(config.EnvironmentDevelopment)
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
			h.metrics.Counters.BadLogins.WithLabelValues("user_not_found").Inc()
			return nil, true, invalidError
		}
		h.sugar.Errorw("Failed to query user", "error", err)
		h.metrics.Counters.BadLogins.WithLabelValues("unknown").Inc()
		return nil, false, err
	}

	if strings.TrimSpace(user.PasswordHash) == "" {
		h.sugar.Warnw("Password login attempted for user without password hash", "username", username)
		h.metrics.Counters.BadLogins.WithLabelValues("missing_hash").Inc()
		return nil, true, invalidError
	}

	if !user.CheckPassword(password) {
		h.sugar.Warnw("Invalid password attempt", "username", username)
		h.metrics.Counters.BadLogins.WithLabelValues("invalid_password").Inc()
		return nil, true, invalidError
	}

	h.metrics.Counters.TotalLogins.Inc()

	now := time.Now()
	if user.ID != nil {
		if err := h.db.Model(&relational.User{}).
			Where("id = ?", user.ID.String()).
			Update("last_login", now).Error; err != nil {
			h.sugar.Warnw("Failed to update last login", "username", username, "error", err)
		} else {
			user.LastLogin = &now
		}
	} else {
		h.sugar.Warnw("User ID missing; cannot update last login", "username", username)
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

// ForgotPassword godoc
//
//	@Summary		Forgot password
//	@Description	Sends a password reset email to users with authMethod=password
//	@Tags			Auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		auth.AuthHandler.ForgotPassword.request	true	"Email"
//	@Success		200		{object}	handler.GenericDataResponse[string]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(ctx echo.Context) error {
	type request struct {
		Email string `json:"email" validate:"required,email"`
	}

	var req request
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind forgot password request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Find user by email
	var user relational.User
	if err := h.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Don't reveal if email exists or not for security
			return ctx.JSON(http.StatusOK, handler.GenericDataResponse[string]{
				Data: "If an account with this email exists, a password reset link has been sent.",
			})
		}
		h.sugar.Errorw("Failed to find user", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Check if user uses password-based authentication
	usesPasswordAuth := user.AuthMethod == "" || user.AuthMethod == "password"
	if !usesPasswordAuth {
		h.sugar.Warnw("Password reset attempted for non-password user", "email", req.Email, "authMethod", user.AuthMethod)
		// Don't reveal if email exists or not for security
		return ctx.JSON(http.StatusOK, handler.GenericDataResponse[string]{
			Data: "If an account with this email exists, a password reset link has been sent.",
		})
	}

	if h.emailService == nil || !h.emailService.IsEnabled() {
		h.sugar.Warnw("Password reset attempted while email service is disabled")
		return ctx.JSON(http.StatusOK, handler.GenericDataResponse[string]{
			Data: "If an account with this email exists, a password reset link has been sent.",
		})
	}

	// Send password reset email
	resetToken, err := authn.GeneratePasswordResetToken(user.Email, h.config.JWTPrivateKey)
	if err != nil {
		h.sugar.Errorw("Failed to generate password reset token", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	resetURL := fmt.Sprintf("%s/auth/password-reset?token=%s", h.config.WebBaseURL, *resetToken)

	// Use template service to render email content
	htmlBody, textBody, err := h.emailService.UseTemplate("forgot-password", map[string]interface{}{
		"FirstName": user.FirstName,
		"ResetURL":  resetURL,
	})
	if err != nil {
		h.sugar.Errorw("Failed to render email template", "error", err)
		// Fallback to basic message if template fails
		htmlBody = fmt.Sprintf(`<p>Hello %s,</p><p>Click <a href="%s">here</a> to reset your password.</p>`, user.FirstName, resetURL)
		textBody = fmt.Sprintf("Hello %s,\nVisit %s to reset your password.", user.FirstName, resetURL)
	}

	message := &emailtypes.Message{
		To:       []string{user.Email},
		Subject:  "Password Reset Request",
		HTMLBody: htmlBody,
		TextBody: textBody,
	}

	// Enqueue email job instead of sending directly
	if h.workerService != nil && h.workerService.IsStarted() {
		args := &worker.SendEmailArgs{
			From:     h.getDefaultFromAddress(),
			To:       message.To,
			Subject:  message.Subject,
			HTMLBody: message.HTMLBody,
			TextBody: message.TextBody,
		}

		err = h.workerService.EnqueueSendEmail(ctx.Request().Context(), args)
		if err != nil {
			h.sugar.Errorw("Failed to enqueue password reset email", "error", err, "email", user.Email)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}

		h.sugar.Infow("Password reset email enqueued", "email", user.Email)
	} else {
		// Fallback to direct sending if worker is not available
		_, err = h.emailService.Send(ctx.Request().Context(), message)
		if err != nil {
			h.sugar.Errorw("Failed to send password reset email", "error", err, "email", user.Email)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}

		h.sugar.Infow("Password reset email sent", "email", user.Email)
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[string]{
		Data: "If an account with this email exists, a password reset link has been sent.",
	})
}

// PasswordReset godoc
//
//	@Summary		Reset password
//	@Description	Resets password using a valid JWT token
//	@Tags			Auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		auth.AuthHandler.PasswordReset.request	true	"Reset data"
//	@Success		200		{object}	handler.GenericDataResponse[string]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/auth/password-reset [post]
func (h *AuthHandler) PasswordReset(ctx echo.Context) error {
	type request struct {
		Token    string `json:"token" validate:"required"`
		Password string `json:"password" validate:"required,min=8"`
	}

	var req request
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Errorw("Failed to bind password reset request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify the password reset token
	claims, err := authn.VerifyPasswordResetToken(req.Token, h.config.JWTPublicKey)
	if err != nil {
		h.sugar.Warnw("Invalid password reset token", "error", err)
		return ctx.JSON(http.StatusUnauthorized, api.NewError(errors.New("invalid or expired token")))
	}

	// Use email from token
	email := claims.Email

	// Find user by email
	var user relational.User
	if err := h.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(errors.New("user not found")))
		}
		h.sugar.Errorw("Failed to find user", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Check if user has password auth method
	usesPasswordAuth := user.AuthMethod == "" || user.AuthMethod == "password"
	if !usesPasswordAuth {
		h.sugar.Warnw("Password reset attempted for non-password user", "email", email, "authMethod", user.AuthMethod)
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("password reset not available for this account")))
	}

	// Update user password
	if err := user.SetPassword(req.Password); err != nil {
		h.sugar.Errorw("Failed to set new password", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Save user to database
	if err := h.db.Save(&user).Error; err != nil {
		h.sugar.Errorw("Failed to save user with new password", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.sugar.Infow("Password reset successful", "email", email)

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[string]{
		Data: "Password has been reset successfully",
	})
}

// getDefaultFromAddress returns the default From address from the email service configuration
func (h *AuthHandler) getDefaultFromAddress() string {
	if h.emailService == nil {
		return ""
	}
	return h.emailService.GetDefaultFromAddress()
}
