package suggestions

import (
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

type DashboardSuggestionRun struct {
	relational.UUIDModel

	SSPID         uuid.UUID         `json:"sspId" gorm:"column:ssp_id;type:uuid;not null;index"`
	Status        string            `json:"status" gorm:"type:varchar(16);not null;index"`
	Error         *string           `json:"error" gorm:"type:text"`
	Model         string            `json:"model" gorm:"type:text;not null"`
	PromptVersion string            `json:"promptVersion" gorm:"type:varchar(32);not null"`
	Scope         datatypes.JSONMap `json:"scope" gorm:"type:jsonb;not null"`
	Constraints   datatypes.JSONMap `json:"constraints" gorm:"type:jsonb"`
	// LabelFilter is the evidence-scoping label filter applied to this run, so the
	// worker can restrict its per-cell evidence scan and the UI can show it.
	LabelFilter              datatypes.JSONMap              `json:"labelFilter" gorm:"type:jsonb"`
	PlannedCalls             int                            `json:"plannedCalls" gorm:"not null"`
	TriggeredByUserID        *uuid.UUID                     `json:"triggeredByUserId" gorm:"type:uuid;index"`
	StartedAt                *time.Time                     `json:"startedAt"`
	CompletedAt              *time.Time                     `json:"completedAt"`
	SuggestionCount          int                            `json:"suggestionCount" gorm:"not null"`
	InputTokens              int                            `json:"inputTokens" gorm:"not null"`
	OutputTokens             int                            `json:"outputTokens" gorm:"not null"`
	CacheReadInputTokens     int                            `json:"cacheReadInputTokens" gorm:"not null;default:0"`
	CacheCreationInputTokens int                            `json:"cacheCreationInputTokens" gorm:"not null;default:0"`
	RateLimitedCount         int                            `json:"rateLimitedCount" gorm:"not null;default:0"`
	Stats                    datatypes.JSONMap              `json:"stats" gorm:"type:jsonb;not null"`
	SystemSecurityPlan       *relational.SystemSecurityPlan `json:"-" gorm:"foreignKey:SSPID;references:ID"`
	Cells                    []DashboardSuggestionRunCell   `json:"cells,omitempty" gorm:"foreignKey:RunID;constraint:OnDelete:CASCADE"`
	Suggestions              []DashboardSuggestion          `json:"suggestions,omitempty" gorm:"foreignKey:RunID;constraint:OnDelete:CASCADE"`
}

func (DashboardSuggestionRun) TableName() string {
	return "dashboard_suggestion_runs"
}

type DashboardSuggestionRunCell struct {
	RunID                    uuid.UUID                   `json:"runId" gorm:"type:uuid;primaryKey"`
	CellIndex                int                         `json:"cellIndex" gorm:"primaryKey"`
	ControlKeys              datatypes.JSONSlice[string] `json:"controlKeys" gorm:"type:jsonb;not null"`
	LabelSetHashes           datatypes.JSONSlice[string] `json:"labelSetHashes" gorm:"type:jsonb;not null"`
	Status                   string                      `json:"status" gorm:"type:varchar(16);not null;index"`
	Error                    *string                     `json:"error" gorm:"type:text"`
	InputTokens              int                         `json:"inputTokens" gorm:"not null"`
	OutputTokens             int                         `json:"outputTokens" gorm:"not null"`
	CacheReadInputTokens     int                         `json:"cacheReadInputTokens" gorm:"not null;default:0"`
	CacheCreationInputTokens int                         `json:"cacheCreationInputTokens" gorm:"not null;default:0"`
	RateLimitedCount         int                         `json:"rateLimitedCount" gorm:"not null;default:0"`
	MappingsReturned         int                         `json:"mappingsReturned" gorm:"not null"`
	MappingsRejected         int                         `json:"mappingsRejected" gorm:"not null"`
	CompletedAt              *time.Time                  `json:"completedAt"`

	Run *DashboardSuggestionRun `json:"-" gorm:"foreignKey:RunID;references:ID;constraint:OnDelete:CASCADE"`
}

func (DashboardSuggestionRunCell) TableName() string {
	return "dashboard_suggestion_run_cells"
}

type DashboardSuggestion struct {
	relational.UUIDModel

	RunID                  uuid.UUID         `json:"runId" gorm:"type:uuid;not null;index"`
	SSPID                  uuid.UUID         `json:"sspId" gorm:"column:ssp_id;type:uuid;not null;index"`
	ControlCatalogID       uuid.UUID         `json:"controlCatalogId" gorm:"type:uuid;not null"`
	ControlID              string            `json:"controlId" gorm:"type:text;not null"`
	LabelSet               datatypes.JSONMap `json:"labelSet" gorm:"type:jsonb;not null"`
	LabelSetHash           string            `json:"labelSetHash" gorm:"type:char(64);not null;index"`
	ProposedFilterLabelSet datatypes.JSONMap `json:"proposedFilterLabelSet" gorm:"column:proposed_filter_label_set;type:jsonb"`
	TargetFilterID         *uuid.UUID        `json:"targetFilterId" gorm:"type:uuid;index"`
	ProposedFilterName     string            `json:"proposedFilterName" gorm:"type:text;not null"`
	Reasoning              string            `json:"reasoning" gorm:"type:text;not null"`
	Confidence             float64           `json:"confidence" gorm:"type:double precision;not null"`
	Status                 string            `json:"status" gorm:"type:varchar(16);not null;index"`
	AcceptedFilterID       *uuid.UUID        `json:"acceptedFilterId" gorm:"type:uuid;index"`
	DecidedByUserID        *uuid.UUID        `json:"decidedByUserId" gorm:"type:uuid;index"`
	DecidedAt              *time.Time        `json:"decidedAt"`
	RejectReason           *string           `json:"rejectReason" gorm:"type:text"`
	IsUserEdited           bool              `json:"isUserEdited" gorm:"not null;default:false"`
	EditedByUserID         *uuid.UUID        `json:"editedByUserId" gorm:"type:uuid;index"`
	EditedAt               *time.Time        `json:"editedAt"`
	// AI baseline captured at first user edit (set-once) so the UI can render a
	// diff of what the user changed. Nil on AI-generated, never-edited rows and
	// on rows the user added during an edit (AddedByUser).
	OriginalProposedFilterLabelSet datatypes.JSONMap `json:"originalProposedFilterLabelSet" gorm:"column:original_proposed_filter_label_set;type:jsonb"`
	OriginalProposedFilterName     *string           `json:"originalProposedFilterName" gorm:"type:text"`
	// AddedByUser marks rows created during a group edit (no AI baseline).
	AddedByUser bool `json:"addedByUser" gorm:"not null;default:false"`
	// RemovedControlIds mirrors, onto every surviving group row, the control IDs
	// removed from the group during edits, so the card can show them struck-out.
	RemovedControlIds datatypes.JSONSlice[string] `json:"removedControlIds" gorm:"type:jsonb"`
	// IsGeneralization marks rows produced by the deterministic filter-merge
	// detector (Part 2). Such a row proposes the generalized label set G that
	// merges several near-duplicate SSP filters that differ by one generalizable
	// label. Accepting it moves controls onto G and off the source filters.
	IsGeneralization bool `json:"isGeneralization" gorm:"not null;default:false"`
	// SourceFilterIDs are the SSP filters this generalization merges, recorded so
	// the UI can explain the merge and the accept path can detach controls from
	// them. Nil on ordinary (non-generalization) rows.
	SourceFilterIDs datatypes.JSONSlice[uuid.UUID] `json:"sourceFilterIds" gorm:"type:jsonb"`

	Run                *DashboardSuggestionRun        `json:"-" gorm:"foreignKey:RunID;references:ID;constraint:OnDelete:CASCADE"`
	SystemSecurityPlan *relational.SystemSecurityPlan `json:"-" gorm:"foreignKey:SSPID;references:ID"`
	TargetFilter       *relational.Filter             `json:"-" gorm:"foreignKey:TargetFilterID;references:ID"`
	AcceptedFilter     *relational.Filter             `json:"-" gorm:"foreignKey:AcceptedFilterID;references:ID"`
}

func (DashboardSuggestion) TableName() string {
	return "dashboard_suggestions"
}
