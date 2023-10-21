package model

import (
	"time"
)

type Revision struct {
	ComprehensiveDetails

	Published    time.Time `json:"published"`
	LastModified time.Time `json:"lastModified"`
	Version      string    `json:"version"`
	OscalVersion string    `json:"oscalVersion"`
}
