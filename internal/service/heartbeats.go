package service

import (
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
)

type Heartbeat struct {
	relational.UUIDModel

	UUID      uuid.UUID `gorm:"index"`
	CreatedAt time.Time `gorm:"index"`
}
