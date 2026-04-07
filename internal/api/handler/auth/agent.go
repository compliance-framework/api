package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type agentTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (h *AuthHandler) GetAgentToken(ctx echo.Context) error {
	clientID, clientSecret, err := getAgentCredentials(ctx)
	if err != nil {
		return ctx.JSON(http.StatusUnauthorized, api.NewError(err))
	}

	var key relational.AgentServiceAccountKey
	if err := h.db.Where("client_id = ?", clientID).First(&key).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.logAgentAuthEvent(nil, nil, clientID, relational.AgentAuthEventOutcomeFailure, "unknown_client_id", ctx)
			return ctx.JSON(http.StatusUnauthorized, api.NewError(errors.New("invalid client credentials")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if key.AgentID == nil {
		h.logAgentAuthEvent(nil, &key, clientID, relational.AgentAuthEventOutcomeFailure, "missing_agent_id", ctx)
		return ctx.JSON(http.StatusUnauthorized, api.NewError(errors.New("invalid client credentials")))
	}

	var agent relational.Agent
	if err := h.db.Where("id = ?", *key.AgentID).First(&agent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.logAgentAuthEvent(nil, &key, clientID, relational.AgentAuthEventOutcomeFailure, "agent_not_found", ctx)
			return ctx.JSON(http.StatusUnauthorized, api.NewError(errors.New("invalid client credentials")))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	now := time.Now().UTC()
	if key.IsRevoked(now) {
		h.logAgentAuthEvent(&agent, &key, clientID, relational.AgentAuthEventOutcomeFailure, "key_revoked", ctx)
		return ctx.JSON(http.StatusForbidden, api.NewError(errors.New("agent key is revoked")))
	}
	if key.IsExpired(now) {
		h.logAgentAuthEvent(&agent, &key, clientID, relational.AgentAuthEventOutcomeFailure, "key_expired", ctx)
		return ctx.JSON(http.StatusForbidden, api.NewError(errors.New("agent key is expired")))
	}
	if !agent.IsActive {
		h.logAgentAuthEvent(&agent, &key, clientID, relational.AgentAuthEventOutcomeFailure, "agent_inactive", ctx)
		return ctx.JSON(http.StatusForbidden, api.NewError(errors.New("agent is inactive")))
	}
	if !key.CheckSecret(clientSecret) {
		h.logAgentAuthEvent(&agent, &key, clientID, relational.AgentAuthEventOutcomeFailure, "invalid_secret", ctx)
		return ctx.JSON(http.StatusUnauthorized, api.NewError(errors.New("invalid client credentials")))
	}

	token, err := authn.GenerateAgentJWTToken(&agent, &key, h.config.JWTPrivateKey)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&relational.AgentServiceAccountKey{}).
			Where("id = ?", key.ID.String()).
			Update("last_used_at", now).Error; err != nil {
			return err
		}
		if err := tx.Model(&relational.Agent{}).
			Where("id = ?", agent.ID.String()).
			Update("last_authenticated_at", now).Error; err != nil {
			return err
		}
		event := h.newAgentAuthEvent(&agent, &key, clientID, relational.AgentAuthEventOutcomeSuccess, nil, ctx)
		return tx.Create(event).Error
	}); err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, &agentTokenResponse{
		AccessToken: *token,
		TokenType:   "Bearer",
		ExpiresIn:   86400,
	})
}

func getAgentCredentials(ctx echo.Context) (string, string, error) {
	if clientID, clientSecret, ok := ctx.Request().BasicAuth(); ok {
		clientID = strings.TrimSpace(clientID)
		clientSecret = strings.TrimSpace(clientSecret)
		if clientID != "" && clientSecret != "" {
			return clientID, clientSecret, nil
		}
	}

	clientID := strings.TrimSpace(ctx.FormValue("client_id"))
	clientSecret := strings.TrimSpace(ctx.FormValue("client_secret"))
	if clientID == "" || clientSecret == "" {
		return "", "", errors.New("missing client credentials")
	}
	return clientID, clientSecret, nil
}

func (h *AuthHandler) logAgentAuthEvent(agent *relational.Agent, key *relational.AgentServiceAccountKey, principal string, outcome string, reason string, ctx echo.Context) {
	event := h.newAgentAuthEvent(agent, key, principal, outcome, &reason, ctx)
	if err := h.db.Create(event).Error; err != nil {
		h.sugar.Warnw("Failed to log agent auth event", "error", err)
	}
}

func (h *AuthHandler) newAgentAuthEvent(agent *relational.Agent, key *relational.AgentServiceAccountKey, principal string, outcome string, reason *string, ctx echo.Context) *relational.AgentAuthEvent {
	event := &relational.AgentAuthEvent{
		AuthMethod: relational.AgentAuthMethodServiceAccount,
		Outcome:    outcome,
		Principal:  &principal,
		Reason:     reason,
	}
	if agent != nil && agent.ID != nil {
		agentID := *agent.ID
		event.AgentID = &agentID
	}
	if key != nil && key.ID != nil {
		keyID := *key.ID
		event.CredentialID = &keyID
	}
	if remoteAddr := strings.TrimSpace(ctx.RealIP()); remoteAddr != "" {
		event.RemoteAddr = &remoteAddr
	}
	if userAgent := strings.TrimSpace(ctx.Request().UserAgent()); userAgent != "" {
		event.UserAgent = &userAgent
	}
	return event
}
