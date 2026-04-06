package handler

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type AgentHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

type agentResponse struct {
	ID                  string     `json:"id"`
	CreatedAt           time.Time  `json:"created-at"`
	UpdatedAt           time.Time  `json:"updated-at"`
	Name                string     `json:"name"`
	Description         *string    `json:"description,omitempty"`
	IsActive            bool       `json:"is-active"`
	LastAuthenticatedAt *time.Time `json:"last-authenticated-at,omitempty"`
	ServiceAccountKeys  int64      `json:"service-account-key-count"`
}

type agentKeyResponse struct {
	ID           string     `json:"id"`
	CreatedAt    time.Time  `json:"created-at"`
	UpdatedAt    time.Time  `json:"updated-at"`
	Name         *string    `json:"name,omitempty"`
	ClientID     string     `json:"client-id"`
	LastUsedAt   *time.Time `json:"last-used-at,omitempty"`
	ExpiresAt    *time.Time `json:"expires-at,omitempty"`
	NeverExpires bool       `json:"never-expires"`
	RevokedAt    *time.Time `json:"revoked-at,omitempty"`
}

type agentKeyCreateResponse struct {
	agentKeyResponse
	ClientSecret string `json:"client-secret"`
}

type createAgentRequest struct {
	Name        string  `json:"name" validate:"required"`
	Description *string `json:"description"`
	IsActive    *bool   `json:"is-active"`
}

type updateAgentRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	IsActive    *bool   `json:"is-active"`
}

type createAgentKeyRequest struct {
	Name         *string    `json:"name"`
	ExpiresAt    *time.Time `json:"expires-at,omitempty"`
	NeverExpires bool       `json:"never-expires,omitempty"`
}

func NewAgentHandler(sugar *zap.SugaredLogger, db *gorm.DB) *AgentHandler {
	return &AgentHandler{sugar: sugar, db: db}
}

func (h *AgentHandler) Register(api *echo.Group) {
	api.GET("", h.ListAgents)
	api.POST("", h.CreateAgent)
	api.GET("/:id", h.GetAgent)
	api.PUT("/:id", h.UpdateAgent)
	api.DELETE("/:id", h.DeleteAgent)
	api.POST("/:id/keys", h.CreateAgentKey)
	api.GET("/:id/keys", h.ListAgentKeys)
	api.GET("/:id/keys/:keyId", h.GetAgentKey)
	api.DELETE("/:id/keys/:keyId", h.DeleteAgentKey)
}

func (h *AgentHandler) ListAgents(ctx echo.Context) error {
	var agents []relational.Agent
	if err := h.db.Order("created_at asc").Find(&agents).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	resp := make([]agentResponse, 0, len(agents))
	for _, agent := range agents {
		item, err := h.buildAgentResponse(&agent)
		if err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
		resp = append(resp, item)
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[agentResponse]{Data: resp})
}

func (h *AgentHandler) GetAgent(ctx echo.Context) error {
	agent, err := h.getAgentByParam(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if agent == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
	}

	resp, err := h.buildAgentResponse(agent)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, GenericDataResponse[agentResponse]{Data: resp})
}

func (h *AgentHandler) CreateAgent(ctx echo.Context) error {
	var req createAgentRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if err := ctx.Validate(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.Validator(err))
	}

	agent := &relational.Agent{
		Name:        req.Name,
		Description: req.Description,
		IsActive:    true,
	}
	if req.IsActive != nil {
		agent.IsActive = *req.IsActive
	}

	if err := h.db.Create(agent).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	resp, err := h.buildAgentResponse(agent)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusCreated, GenericDataResponse[agentResponse]{Data: resp})
}

func (h *AgentHandler) UpdateAgent(ctx echo.Context) error {
	agent, err := h.getAgentByParam(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if agent == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
	}

	var req updateAgentRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if req.Name != nil {
		agent.Name = *req.Name
	}
	if req.Description != nil {
		agent.Description = req.Description
	}
	if req.IsActive != nil {
		agent.IsActive = *req.IsActive
	}

	if err := h.db.Save(agent).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	resp, err := h.buildAgentResponse(agent)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, GenericDataResponse[agentResponse]{Data: resp})
}

func (h *AgentHandler) DeleteAgent(ctx echo.Context) error {
	agent, err := h.getAgentByParam(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if agent == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
	}
	if err := h.db.Delete(agent).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.NoContent(http.StatusNoContent)
}

func (h *AgentHandler) CreateAgentKey(ctx echo.Context) error {
	agent, err := h.getAgentByParam(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if agent == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
	}

	var req createAgentKeyRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	expiresAt, err := normalizeAgentKeyExpiry(req.ExpiresAt, req.NeverExpires)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	clientSecret, err := generateAgentSecret()
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	key := &relational.AgentServiceAccountKey{
		AgentID:   stringPtr(agent.ID.String()),
		Name:      normalizeOptionalString(req.Name),
		ClientID:  uuid.NewString(),
		ExpiresAt: expiresAt,
	}
	if err := key.SetSecret(clientSecret); err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if err := h.db.Create(key).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, GenericDataResponse[agentKeyCreateResponse]{
		Data: agentKeyCreateResponse{
			agentKeyResponse: buildAgentKeyResponse(key),
			ClientSecret:     clientSecret,
		},
	})
}

func (h *AgentHandler) ListAgentKeys(ctx echo.Context) error {
	agent, err := h.getAgentByParam(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if agent == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
	}

	var keys []relational.AgentServiceAccountKey
	if err := h.db.Where("agent_id = ?", agent.ID.String()).Order("created_at asc").Find(&keys).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	resp := make([]agentKeyResponse, 0, len(keys))
	for _, key := range keys {
		resp = append(resp, buildAgentKeyResponse(&key))
	}
	return ctx.JSON(http.StatusOK, GenericDataListResponse[agentKeyResponse]{Data: resp})
}

func (h *AgentHandler) GetAgentKey(ctx echo.Context) error {
	key, status, err := h.getAgentKey(ctx.Param("id"), ctx.Param("keyId"))
	if err != nil {
		return ctx.JSON(status, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, GenericDataResponse[agentKeyResponse]{Data: buildAgentKeyResponse(key)})
}

func (h *AgentHandler) DeleteAgentKey(ctx echo.Context) error {
	key, status, err := h.getAgentKey(ctx.Param("id"), ctx.Param("keyId"))
	if err != nil {
		return ctx.JSON(status, api.NewError(err))
	}
	now := time.Now().UTC()
	key.RevokedAt = &now
	if err := h.db.Save(key).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.NoContent(http.StatusNoContent)
}

func (h *AgentHandler) getAgentByParam(agentID string) (*relational.Agent, error) {
	agentUUID, err := uuid.Parse(agentID)
	if err != nil {
		return nil, err
	}
	var agent relational.Agent
	if err := h.db.First(&agent, agentUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &agent, nil
}

func (h *AgentHandler) getAgentKey(agentID, keyID string) (*relational.AgentServiceAccountKey, int, error) {
	agent, err := h.getAgentByParam(agentID)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if agent == nil {
		return nil, http.StatusNotFound, gorm.ErrRecordNotFound
	}
	keyUUID, err := uuid.Parse(keyID)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	var key relational.AgentServiceAccountKey
	if err := h.db.Where("agent_id = ?", agent.ID.String()).First(&key, keyUUID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, http.StatusNotFound, err
		}
		return nil, http.StatusInternalServerError, err
	}
	return &key, http.StatusOK, nil
}

func (h *AgentHandler) buildAgentResponse(agent *relational.Agent) (agentResponse, error) {
	var keyCount int64
	if err := h.db.Model(&relational.AgentServiceAccountKey{}).
		Where("agent_id = ? AND revoked_at IS NULL", agent.ID.String()).
		Count(&keyCount).Error; err != nil {
		return agentResponse{}, err
	}

	return agentResponse{
		ID:                  agent.ID.String(),
		CreatedAt:           agent.CreatedAt,
		UpdatedAt:           agent.UpdatedAt,
		Name:                agent.Name,
		Description:         agent.Description,
		IsActive:            agent.IsActive,
		LastAuthenticatedAt: agent.LastAuthenticatedAt,
		ServiceAccountKeys:  keyCount,
	}, nil
}

func buildAgentKeyResponse(key *relational.AgentServiceAccountKey) agentKeyResponse {
	return agentKeyResponse{
		ID:           key.ID.String(),
		CreatedAt:    key.CreatedAt,
		UpdatedAt:    key.UpdatedAt,
		Name:         key.Name,
		ClientID:     key.ClientID,
		LastUsedAt:   key.LastUsedAt,
		ExpiresAt:    key.ExpiresAt,
		NeverExpires: key.ExpiresAt == nil,
		RevokedAt:    key.RevokedAt,
	}
}

func generateAgentSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func stringPtr(v string) *string {
	return &v
}

func normalizeOptionalString(value *string) *string {
	if value == nil {
		return nil
	}

	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return nil
	}

	return &trimmed
}

func normalizeAgentKeyExpiry(expiresAt *time.Time, neverExpires bool) (*time.Time, error) {
	if neverExpires && expiresAt != nil {
		return nil, errors.New("expires-at cannot be combined with never-expires")
	}
	if expiresAt == nil {
		return nil, nil
	}

	normalized := expiresAt.UTC()
	if !normalized.After(time.Now().UTC()) {
		return nil, errors.New("expires-at must be in the future")
	}

	return &normalized, nil
}
