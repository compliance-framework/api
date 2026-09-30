package relational

import (
	"time"

	"github.com/google/uuid"
)

// Artifact is immutable content addressed by its digest: a policy bundle, the input data or
// the policy data a policy evaluation used. Evidence refers to artifacts by digest so the
// evaluation can be played back later. Rows are never updated; a repeated upload of the
// same content is a no-op.
type Artifact struct {
	Digest           string     `json:"digest" gorm:"type:text;primaryKey"`
	MediaType        string     `json:"mediaType" gorm:"type:text;not null"`
	SizeBytes        int64      `json:"sizeBytes" gorm:"not null"`
	Content          []byte     `json:"-" gorm:"type:bytea;not null"`
	CreatedAt        time.Time  `json:"createdAt"`
	CreatedByAgentID *uuid.UUID `json:"createdByAgentId,omitempty" gorm:"type:uuid"`
}

func (Artifact) TableName() string {
	return "artifacts"
}
