package relational

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// ErrAgentConfigRevisionAppendOnly is returned when code tries to update or delete a
// configuration revision.
var ErrAgentConfigRevisionAppendOnly = errors.New("agent config revisions are append-only")

// AgentConfigRevision is one immutable revision of an agent's configuration overlay (D11).
// The desired revision of an agent is MAX(revision). The row id feeds the agent-facing
// opaque ETag (R7), so a DB reset never produces a false 304.
type AgentConfigRevision struct {
	UUIDModel
	CreatedAt   time.Time      `json:"createdAt"`
	AgentID     uuid.UUID      `json:"agentId" gorm:"type:uuid;not null;uniqueIndex:idx_agent_config_rev,priority:1"`
	Revision    int64          `json:"revision" gorm:"not null;uniqueIndex:idx_agent_config_rev,priority:2"`
	Overlay     datatypes.JSON `json:"overlay" gorm:"type:jsonb;not null"`
	Comment     *string        `json:"comment,omitempty" gorm:"type:text"`
	CreatedBy   string         `json:"createdBy" gorm:"type:text;not null"`    // user subject id (email)
	CreatedByID *uuid.UUID     `json:"createdById,omitempty" gorm:"type:uuid"` // user_uuid claim when present
	RevertOf    *int64         `json:"revertOf,omitempty"`
}

func (AgentConfigRevision) TableName() string { return "ccf_agent_config_revisions" }

// BeforeUpdate keeps revisions append-only.
func (*AgentConfigRevision) BeforeUpdate(*gorm.DB) error { return ErrAgentConfigRevisionAppendOnly }

// BeforeDelete keeps revisions append-only.
func (*AgentConfigRevision) BeforeDelete(*gorm.DB) error { return ErrAgentConfigRevisionAppendOnly }

// AgentInstance is one running agent process (instance id) of an agent service account, as
// last reported through a config report or an authenticated heartbeat. The displayed status
// is derived at read time (R10), not stored.
type AgentInstance struct {
	UUIDModel
	CreatedAt time.Time
	UpdatedAt time.Time

	AgentID      uuid.UUID  `gorm:"type:uuid;not null;uniqueIndex:idx_agent_instance,priority:1"`
	InstanceID   uuid.UUID  `gorm:"type:uuid;not null;uniqueIndex:idx_agent_instance,priority:2"`
	CredentialID *uuid.UUID `gorm:"type:uuid"`

	Hostname     *string `gorm:"type:text"`
	AgentVersion *string `gorm:"type:text"`
	Mode         string  `gorm:"type:text;not null;default:''"` // '' until the first report
	Daemon       *bool   // R37; null until reported

	FirstSeenAt time.Time `gorm:"not null"`
	LastSeenAt  time.Time `gorm:"not null;index"` // authenticated heartbeats AND reports
	ReportedAt  *time.Time

	AppliedRevision   *int64
	AttemptedRevision *int64
	ReportedStatus    string         `gorm:"type:text;not null;default:''"` // agent-sent; '' = never reported
	ApplyReason       *string        `gorm:"type:text"`
	ApplyError        *string        `gorm:"type:text"`
	Truncated         bool           `gorm:"not null;default:false"` // R10
	Warnings          datatypes.JSON `gorm:"type:jsonb"`             // R41: []agentconfig.FieldError

	BaseConfig      datatypes.JSON `gorm:"type:jsonb"`
	EffectiveConfig datatypes.JSON `gorm:"type:jsonb"`
	EffectiveDigest *string        `gorm:"type:text"`
	RemoteConfig    datatypes.JSON `gorm:"type:jsonb"`
	PolicyBundles   datatypes.JSON `gorm:"type:jsonb"`
	PolicyErrors    datatypes.JSON `gorm:"type:jsonb"`
	UnsafeChanges   datatypes.JSON `gorm:"type:jsonb"`
	Plugins         datatypes.JSON `gorm:"type:jsonb"` // R76: []agentconfig.PluginReport

	HeartbeatConfigRevision *int64
	HeartbeatConfigDigest   *string `gorm:"type:text"`
}

func (AgentInstance) TableName() string { return "ccf_agent_instances" }
