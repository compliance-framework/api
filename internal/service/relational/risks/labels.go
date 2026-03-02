package risks

import "github.com/google/uuid"

// TODO[codex-5-3-high]: Implemented as requested in the risk-register plan, but currently dead code. Consider removing after full implementation is done.
type AssessmentSubjectLabel struct {
	AssessmentSubjectID uuid.UUID `json:"assessmentSubjectId" gorm:"type:uuid;primaryKey"`
	Key                 string    `json:"key" gorm:"type:text;primaryKey;index:idx_assessment_subject_label_key_value,priority:1"`
	Value               string    `json:"value" gorm:"type:text;primaryKey;index:idx_assessment_subject_label_key_value,priority:2"`
}

func (AssessmentSubjectLabel) TableName() string {
	return "assessment_subject_labels"
}

// TODO[codex-5-3-high]: Implemented as requested in the risk-register plan, but currently dead code. Consider removing after full implementation is done.
type InventoryItemLabel struct {
	InventoryItemID uuid.UUID `json:"inventoryItemId" gorm:"type:uuid;primaryKey"`
	Key             string    `json:"key" gorm:"type:text;primaryKey;index:idx_inventory_item_label_key_value,priority:1"`
	Value           string    `json:"value" gorm:"type:text;primaryKey;index:idx_inventory_item_label_key_value,priority:2"`
}

func (InventoryItemLabel) TableName() string {
	return "inventory_item_labels"
}

// TODO[codex-5-3-high]: Implemented as requested in the risk-register plan, but currently dead code. Consider removing after full implementation is done.
type SystemComponentLabel struct {
	SystemComponentID uuid.UUID `json:"systemComponentId" gorm:"type:uuid;primaryKey"`
	Key               string    `json:"key" gorm:"type:text;primaryKey;index:idx_system_component_label_key_value,priority:1"`
	Value             string    `json:"value" gorm:"type:text;primaryKey;index:idx_system_component_label_key_value,priority:2"`
}

func (SystemComponentLabel) TableName() string {
	return "system_component_labels"
}
