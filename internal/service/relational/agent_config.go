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
