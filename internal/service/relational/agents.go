package relational

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	AgentAuthMethodServiceAccount = "service_account"
	AgentAuthEventOutcomeSuccess  = "success"
	AgentAuthEventOutcomeFailure  = "failure"
)

var ErrAgentSecretRequired = errors.New("agent secret is required")

type Agent struct {
	UUIDModel

	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `json:"deletedAt" gorm:"index"`

	Name                string     `json:"name" gorm:"not null"`
	Description         *string    `json:"description,omitempty"`
	IsActive            bool       `json:"isActive" gorm:"default:true"`
	LastAuthenticatedAt *time.Time `json:"lastAuthenticatedAt,omitempty"`

	ServiceAccountKeys []AgentServiceAccountKey `json:"serviceAccountKeys,omitempty"`
}

func (Agent) TableName() string {
	return "ccf_agents"
}

type AgentServiceAccountKey struct {
	UUIDModel

	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `json:"deletedAt" gorm:"index"`

	AgentID *uuid.UUID `json:"agentId" gorm:"type:uuid;not null;index"`
	Agent   Agent      `json:"-" gorm:"foreignKey:AgentID;references:ID"`

	Name       *string    `json:"name,omitempty"`
	ClientID   string     `json:"clientId" gorm:"uniqueIndex;not null"`
	SecretHash string     `json:"-"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

func (AgentServiceAccountKey) TableName() string {
	return "ccf_agent_service_account_keys"
}

func (k *AgentServiceAccountKey) SetSecret(secret string) error {
	if strings.TrimSpace(secret) == "" {
		return ErrAgentSecretRequired
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	k.SecretHash = string(hash)
	return nil
}

func (k *AgentServiceAccountKey) CheckSecret(secret string) bool {
	if strings.TrimSpace(k.SecretHash) == "" || strings.TrimSpace(secret) == "" {
		return false
	}

	return bcrypt.CompareHashAndPassword([]byte(k.SecretHash), []byte(secret)) == nil
}

func (k *AgentServiceAccountKey) IsExpired(at time.Time) bool {
	if k.ExpiresAt == nil {
		return false
	}

	return !k.ExpiresAt.After(at.UTC())
}

func (k *AgentServiceAccountKey) IsRevoked(at time.Time) bool {
	if k.RevokedAt == nil {
		return false
	}

	return !k.RevokedAt.After(at.UTC())
}

type AgentAuthEvent struct {
	UUIDModel

	CreatedAt time.Time `json:"createdAt"`

	AgentID      *uuid.UUID `json:"agentId,omitempty" gorm:"type:uuid;index"`
	CredentialID *uuid.UUID `json:"credentialId,omitempty" gorm:"type:uuid;index"`
	AuthMethod   string     `json:"authMethod" gorm:"type:varchar(64);not null;index"`
	Outcome      string     `json:"outcome" gorm:"type:varchar(32);not null;index"`
	Principal    *string    `json:"principal,omitempty"`
	Reason       *string    `json:"reason,omitempty"`
	RemoteAddr   *string    `json:"remoteAddr,omitempty"`
	UserAgent    *string    `json:"userAgent,omitempty"`
}

func (AgentAuthEvent) TableName() string {
	return "ccf_agent_auth_events"
}

func (e *AgentAuthEvent) BeforeUpdate(_ *gorm.DB) error {
	return errors.New("agent auth events are append-only")
}

func (e *AgentAuthEvent) BeforeDelete(_ *gorm.DB) error {
	return errors.New("agent auth events are append-only")
}
