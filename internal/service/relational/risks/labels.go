package risks

import "github.com/google/uuid"

// AssessmentSubjectLabel stores stable identity labels used by risk and template flows.
type AssessmentSubjectLabel struct {
	AssessmentSubjectID uuid.UUID `json:"assessmentSubjectId" gorm:"type:uuid;primaryKey"`
	Key                 string    `json:"key" gorm:"type:text;primaryKey;index:idx_assessment_subject_label_key_value,priority:1"`
	Value               string    `json:"value" gorm:"type:text;primaryKey;index:idx_assessment_subject_label_key_value,priority:2"`
}

func (AssessmentSubjectLabel) TableName() string {
	return "assessment_subject_labels"
}

type InventoryItemLabel struct {
	InventoryItemID uuid.UUID `json:"inventoryItemId" gorm:"type:uuid;primaryKey"`
	Key             string    `json:"key" gorm:"type:text;primaryKey;index:idx_inventory_item_label_key_value,priority:1"`
	Value           string    `json:"value" gorm:"type:text;primaryKey;index:idx_inventory_item_label_key_value,priority:2"`
}

func (InventoryItemLabel) TableName() string {
	return "inventory_item_labels"
}

type SystemComponentLabel struct {
	SystemComponentID uuid.UUID `json:"systemComponentId" gorm:"type:uuid;primaryKey"`
	Key               string    `json:"key" gorm:"type:text;primaryKey;index:idx_system_component_label_key_value,priority:1"`
	Value             string    `json:"value" gorm:"type:text;primaryKey;index:idx_system_component_label_key_value,priority:2"`
}

func (SystemComponentLabel) TableName() string {
	return "system_component_labels"
}

type ComponentDefinitionLabel struct {
	ComponentDefinitionID uuid.UUID `json:"componentDefinitionId" gorm:"type:uuid;primaryKey"`
	Key                   string    `json:"key" gorm:"type:text;primaryKey;index:idx_component_definition_label_key_value,priority:1"`
	Value                 string    `json:"value" gorm:"type:text;primaryKey;index:idx_component_definition_label_key_value,priority:2"`
}

func (ComponentDefinitionLabel) TableName() string {
	return "component_definition_labels"
}
