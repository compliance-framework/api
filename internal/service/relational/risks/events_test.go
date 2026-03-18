package risks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

func TestBuildRiskEventDetails(t *testing.T) {
	lastSeen := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		eventType string
		payload   datatypes.JSONMap
		occurred  time.Time
		expected  string
	}{
		{
			name:      "created",
			eventType: string(RiskEventTypeCreated),
			payload:   datatypes.JSONMap{"status": "open"},
			expected:  "Risk was created with status open.",
		},
		{
			name:      "last seen",
			eventType: string(RiskEventTypeLastSeen),
			payload:   datatypes.JSONMap{"new_last_seen": lastSeen},
			expected:  "This risk was last seen on 2026-03-18T10:00:00Z.",
		},
		{
			name:      "status changed",
			eventType: string(RiskEventTypeStatusChange),
			payload:   datatypes.JSONMap{"from": "open", "to": "investigating"},
			expected:  "Risk status changed from open to investigating.",
		},
		{
			name:      "accepted",
			eventType: string(RiskEventTypeAccepted),
			payload:   datatypes.JSONMap{"justification": "temporary acceptance"},
			expected:  "Risk was accepted. Justification: temporary acceptance",
		},
		{
			name:      "reviewed",
			eventType: string(RiskEventTypeReviewed),
			payload:   datatypes.JSONMap{"decision": "extend"},
			expected:  "Risk review decision recorded: extend.",
		},
		{
			name:      "score reassessed",
			eventType: string(RiskEventTypeScoreReassessed),
			payload: datatypes.JSONMap{
				"fromLikelihood": "low",
				"fromImpact":     "low",
				"toLikelihood":   "high",
				"toImpact":       "critical",
			},
			expected: "Risk score was reassessed from likelihood=low impact=low to likelihood=high impact=critical.",
		},
		{
			name:      "evidence linked",
			eventType: string(RiskEventTypeEvidenceLink),
			payload:   datatypes.JSONMap{"evidence_id": "ev-1"},
			expected:  "Evidence ev-1 was linked to this risk.",
		},
		{
			name:      "evidence unlinked",
			eventType: string(RiskEventTypeEvidenceUnlink),
			payload:   datatypes.JSONMap{"evidenceId": "ev-2"},
			expected:  "Evidence ev-2 was unlinked from this risk.",
		},
		{
			name:      "control linked",
			eventType: string(RiskEventTypeControlLink),
			payload:   datatypes.JSONMap{"catalogId": "cat-1", "controlId": "AC-1"},
			expected:  "Control AC-1 from catalog cat-1 was linked to this risk.",
		},
		{
			name:      "control unlinked",
			eventType: string(RiskEventTypeControlUnlink),
			payload:   datatypes.JSONMap{"catalog_id": "cat-2", "control_id": "AC-2"},
			expected:  "Control AC-2 from catalog cat-2 was unlinked from this risk.",
		},
		{
			name:      "component linked",
			eventType: string(RiskEventTypeComponentLink),
			payload:   datatypes.JSONMap{"componentId": "comp-1"},
			expected:  "Component comp-1 was linked to this risk.",
		},
		{
			name:      "component unlinked",
			eventType: string(RiskEventTypeComponentUnlink),
			payload:   datatypes.JSONMap{"component_id": "comp-2"},
			expected:  "Component comp-2 was unlinked from this risk.",
		},
		{
			name:      "subject linked",
			eventType: string(RiskEventTypeSubjectLink),
			payload:   datatypes.JSONMap{"subjectId": "sub-1"},
			expected:  "Subject sub-1 was linked to this risk.",
		},
		{
			name:      "unknown",
			eventType: "custom_event",
			payload:   datatypes.JSONMap{},
			expected:  "Risk event recorded: custom_event.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := BuildRiskEventDetails(tc.eventType, tc.payload, tc.occurred)
			require.Equal(t, tc.expected, actual)
		})
	}
}
