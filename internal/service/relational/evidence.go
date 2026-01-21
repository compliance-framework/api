package relational

import (
	"time"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Evidence struct {
	// ID is the unique ID for this specific observation, and will be used as the primary key in the database.
	UUIDModel

	// UUID needs to remain consistent when automation runs again, but unique for each subject.
	// It represents the "stream" of the same observation being made over time.
	UUID       uuid.UUID   `gorm:"index:evidence_stream_idx;index:evidence_stream_collected_idx,priority:1" json:"uuid,omitempty"`
	BackMatter *BackMatter `gorm:"polymorphic:Parent;" json:"back-matter,omitempty"`

	Title       string  `json:"title"`
	Description string  `json:"description"`
	Remarks     *string `json:"remarks,omitempty"`

	// Assigning labels to Evidence makes it searchable and easily usable in the UI
	Labels []Labels `gorm:"many2many:evidence_labels;" json:"labels"`

	// When did we start collecting the evidence, and when did the process end, and how long is it valid for ?
	Start   time.Time  `json:"start"`
	End     time.Time  `gorm:"index:evidence_stream_collected_idx,priority:2,sort:desc" json:"end"`
	Expires *time.Time `json:"expires,omitempty"`

	Props datatypes.JSONSlice[Prop] `json:"props"`
	Links datatypes.JSONSlice[Link] `json:"links"`

	// Who or What is generating this evidence
	Origins datatypes.JSONSlice[Origin] `json:"origins,omitempty"`

	// What steps did we take to create this evidence
	Activities []Activity `gorm:"many2many:evidence_activities" json:"activities,omitempty"`

	InventoryItems []InventoryItem `gorm:"many2many:evidence_inventory_items" json:"inventory-items,omitempty"`

	// Which components of the subject are being observed. A tool, user, policy etc.
	Components []SystemComponent `gorm:"many2many:evidence_components" json:"components,omitempty"`
	// Who or What are we providing evidence for. What's under test.
	Subjects []AssessmentSubject `gorm:"many2many:evidence_subjects;" json:"subjects,omitempty"`

	// Did we satisfy what was being tested for, or did we fail ?
	Status datatypes.JSONType[oscalTypes_1_1_3.ObjectiveStatus] `json:"status"`
}

func GetLatestEvidenceStreamsQuery(db *gorm.DB) *gorm.DB {
	query := db.
		Model(&Evidence{}).
		Select("DISTINCT ON (uuid) *").
		Order("uuid").
		Order("evidences.end desc")
	return query
}

func GetEvidenceSearchByFilterQuery(latestQuery *gorm.DB, db *gorm.DB, filters ...labelfilter.Filter) (*gorm.DB, error) {
	finalWhere := db.Session(&gorm.Session{}).Table("(?) as l", latestQuery)

	for _, filter := range filters {
		if filter.Scope != nil {
			subQuery, err := filter.Scope.GetClause(db)
			if err != nil {
				return nil, err
			}
			finalWhere = finalWhere.Or(subQuery)
		}
	}

	return finalWhere, nil
}
