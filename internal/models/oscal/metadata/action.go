package metadata

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
	"time"
)

type Action struct {
	Uuid oscal.Uuid `json:"uuid"`

	oscal.ComprehensiveDetails

	Date                  time.Time `json:"date"`
	ResponsiblePartyUuids []string  `json:"responsiblePartyUuids"`
	System                string    `json:"system"`
	Type                  string    `json:"type"`
}
