package metadata

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
	"time"
)

type Action struct {
	Uuid                  string           `json:"uuid"`
	Date                  time.Time        `json:"date"`
	Links                 []Link           `json:"links"`
	Props                 []oscal.Property `json:"props"`
	Remarks               string           `json:"remarks"`
	ResponsiblePartyUuids []string         `json:"responsiblePartyUuids"`
	System                string           `json:"system"`
	Type                  string           `json:"type"`
}
