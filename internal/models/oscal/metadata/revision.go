package metadata

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
	"time"
)

type Revision struct {
	Title        string           `json:"title"`
	Published    time.Time        `json:"published"`
	LastModified time.Time        `json:"lastModified"`
	Version      string           `json:"version"`
	OscalVersion string           `json:"oscalVersion"`
	Props        []oscal.Property `json:"props"`
	Links        []Link           `json:"links"`
	Remarks      string           `json:"remarks"`
}
