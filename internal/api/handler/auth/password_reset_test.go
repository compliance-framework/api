package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Migrate the schema
	err = db.AutoMigrate(&relational.User{})
	require.NoError(t, err)

	return db
}

func setupTestAuthHandler(t *testing.T) *AuthHandler {
	logger := zap.NewNop().Sugar()
	db := setupTestDB(t)

	// Create test config
	cfg := &config.Config{
		WebBaseURL: "http://localhost:3000",
	}

	// Generate test JWT keys
	privateKey, publicKey, err := config.GenerateKeyPair(2048)
	require.NoError(t, err)
	cfg.JWTPrivateKey = privateKey
	cfg.JWTPublicKey = publicKey

	metrics := api.NewMetricsHandler(context.TODO(), logger)

	// Create auth handler without email service for testing
	authHandler := NewAuthHandler(logger, db, cfg, metrics, nil, nil)

	return authHandler
}

func TestForgotPassword_Success(t *testing.T) {
	handler := setupTestAuthHandler(t)

	// Create test user with password auth
	user := relational.User{
		Email:      "test@example.com",
		FirstName:  "Test",
		LastName:   "User",
		AuthMethod: "password",
		IsActive:   true,
	}
	err := user.SetPassword("oldpassword123")
	require.NoError(t, err)
	err = handler.db.Create(&user).Error
	require.NoError(t, err)

	// Create forgot password request
	reqBody := map[string]string{
		"email": "test@example.com",
	}
	body, _ := json.Marshal(reqBody)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Call the handler
	err = handler.ForgotPassword(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Check response
	var response struct {
		Data string `json:"data"`
	}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "If an account with this email exists, a password reset link has been sent.", response.Data)
}

func TestForgotPassword_NonPasswordUser(t *testing.T) {
	handler := setupTestAuthHandler(t)

	// Create test user with SSO auth
	user := relational.User{
		Email:      "sso@example.com",
		FirstName:  "SSO",
		LastName:   "User",
		AuthMethod: "sso",
		IsActive:   true,
	}
	err := handler.db.Create(&user).Error
	require.NoError(t, err)

	// Create forgot password request
	reqBody := map[string]string{
		"email": "sso@example.com",
	}
	body, _ := json.Marshal(reqBody)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Call the handler
	err = handler.ForgotPassword(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Should return same message to avoid revealing user existence
	var response struct {
		Data string `json:"data"`
	}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "If an account with this email exists, a password reset link has been sent.", response.Data)
}

func TestForgotPassword_UserNotFound(t *testing.T) {
	handler := setupTestAuthHandler(t)

	// Create forgot password request for non-existent user
	reqBody := map[string]string{
		"email": "nonexistent@example.com",
	}
	body, _ := json.Marshal(reqBody)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Call the handler
	err := handler.ForgotPassword(c)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Should return same message to avoid revealing user existence
	var response struct {
		Data string `json:"data"`
	}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "If an account with this email exists, a password reset link has been sent.", response.Data)
}
