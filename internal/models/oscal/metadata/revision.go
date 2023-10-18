package metadata

import (
	"github.com/compliance-framework/configuration-service/internal/models/oscal"
	"time"
)

type Revision struct {
	oscal.ComprehensiveDetails

	Published    time.Time `json:"published"`
	LastModified time.Time `json:"lastModified"`
	Version      string    `json:"version"`
	OscalVersion string    `json:"oscalVersion"`
}
