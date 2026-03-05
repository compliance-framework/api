package relational

import (
	"fmt"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// EvidenceQuerier provides access to the latest evidence records matching label filters.
// It is implemented by evidencesvc.EvidenceService in production and by test doubles in unit tests.
type EvidenceQuerier interface {
	GetLatestForFilters(filters ...labelfilter.Filter) ([]Evidence, error)
}

// SystemComponentSuggestion represents a DefinedComponent that can be added to the SSP as a SystemComponent.
type SystemComponentSuggestion struct {
	Name                  string    `json:"name"`
	Type                  string    `json:"type"`
	Description           string    `json:"description"`
	Purpose               string    `json:"purpose"`
	DefinedComponentID    uuid.UUID `json:"definedComponentId"`
	ComponentDefinitionID uuid.UUID `json:"componentDefinitionId"`
}

// SystemComponentSuggestionService provides methods to suggest and apply SystemComponent suggestions from DefinedComponents.
type SystemComponentSuggestionService struct {
	db          *gorm.DB
	evidenceSvc EvidenceQuerier
}

// NewSystemComponentSuggestionService creates a new SystemComponentSuggestionService.
func NewSystemComponentSuggestionService(db *gorm.DB, evidenceSvc EvidenceQuerier) *SystemComponentSuggestionService {
	return &SystemComponentSuggestionService{db: db, evidenceSvc: evidenceSvc}
}

// SuggestForImplementedRequirement finds DefinedComponents that are relevant to the control of the given
// ImplementedRequirement by tracing the path: Control → Filter → Evidence → ComponentDefinitionLabels.
// Components already present as SystemComponents in the SSP's SystemImplementation are excluded.
func (s *SystemComponentSuggestionService) SuggestForImplementedRequirement(
	sspID uuid.UUID,
	implReqID uuid.UUID,
) ([]SystemComponentSuggestion, error) {
	// 1. Get the SystemImplementation for this SSP
	var systemImpl SystemImplementation
	if err := s.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		return nil, fmt.Errorf("system implementation not found for SSP %s: %w", sspID, err)
	}
	systemImplID := *systemImpl.ID

	// 2. Fetch the ImplementedRequirement to get the ControlId, ensuring it belongs to this SSP
	var implReq ImplementedRequirement
	if err := s.db.
		Joins("JOIN control_implementations ON control_implementations.id = implemented_requirements.control_implementation_id").
		Where("implemented_requirements.id = ? AND control_implementations.system_security_plan_id = ?", implReqID, sspID).
		First(&implReq).Error; err != nil {
		return nil, fmt.Errorf("implemented requirement not found for SSP %s: %w", sspID, err)
	}

	// 3. Load Filters associated with this control via the filter_controls join table.
	//
	// NOTE: We match Filters by control_id string only (case-insensitive), ignoring
	// the catalog context (control_catalog_id column). This means Filters from
	// different catalogs that share the same control ID string (e.g. "AC-1") will
	// all be evaluated. In practice this is acceptable since control IDs rarely
	// collide across catalogs used together.
	//
	// TODO: To scope by catalog, join through:
	//   SSP → ProfileID → Profile → resolved Catalog IDs → filter_controls.control_catalog_id
	// This requires deriving the relevant catalog IDs from the SSP/profile and including
	// filter_controls.control_catalog_id in the join conditions.
	var filters []Filter
	if err := s.db.
		Joins("JOIN filter_controls ON filter_controls.filter_id = filters.id").
		// Normalize on upper case.
		// We don't need to concern about index hits as for now - these tables will not grow
		// on a typical CCF usage.
		Where("UPPER(filter_controls.control_id) = UPPER(?)", implReq.ControlId).
		Find(&filters).Error; err != nil {
		return nil, fmt.Errorf("failed to query filters for control %s: %w", implReq.ControlId, err)
	}

	if len(filters) == 0 {
		return []SystemComponentSuggestion{}, nil
	}

	// 4. Get latest Evidence for those filters
	labelFilters := make([]labelfilter.Filter, len(filters))
	for i, f := range filters {
		labelFilters[i] = f.Filter.Data()
	}
	evidences, err := s.evidenceSvc.GetLatestForFilters(labelFilters...)
	if err != nil {
		return nil, fmt.Errorf("failed to get evidence for filters: %w", err)
	}

	if len(evidences) == 0 {
		return []SystemComponentSuggestion{}, nil
	}

	evidenceIDs := make([]uuid.UUID, len(evidences))
	for i, e := range evidences {
		evidenceIDs[i] = *e.ID
	}

	// 5. Find DefinedComponents whose ComponentDefinition has labels that overlap with
	//    the evidence labels. The component_definition_labels table is populated by
	//    SubjectTemplateService when ComponentDefinitions are auto-created from evidence.
	subQ := s.db.Table("component_definition_labels cdl").
		Select("cdl.component_definition_id").
		Joins("JOIN evidence_labels el ON LOWER(el.labels_name) = LOWER(cdl.key) AND LOWER(el.labels_value) = LOWER(cdl.value)").
		Where("el.evidence_id IN ?", evidenceIDs)

	var candidates []DefinedComponent
	if err := s.db.
		Where("component_definition_id IN (?)", subQ).
		Find(&candidates).Error; err != nil {
		return nil, fmt.Errorf("failed to query defined components: %w", err)
	}

	if len(candidates) == 0 {
		return []SystemComponentSuggestion{}, nil
	}

	// 6. Collect candidate IDs
	candidateIDs := make([]uuid.UUID, len(candidates))
	for i, c := range candidates {
		candidateIDs[i] = *c.ID
	}

	// 7. Find existing SystemComponents in this SystemImplementation that are already linked
	//    to one of the candidate DefinedComponents
	var existingIDs []uuid.UUID
	if err := s.db.
		Model(&SystemComponent{}).
		Where("system_implementation_id = ? AND defined_component_id IN ?", systemImplID, candidateIDs).
		Pluck("defined_component_id", &existingIDs).Error; err != nil {
		return nil, fmt.Errorf("failed to query existing system components: %w", err)
	}

	existingSet := make(map[uuid.UUID]struct{}, len(existingIDs))
	for _, id := range existingIDs {
		existingSet[id] = struct{}{}
	}

	// 8. Build suggestions from candidates not already present
	suggestions := make([]SystemComponentSuggestion, 0, len(candidates))
	for _, c := range candidates {
		if _, alreadyLinked := existingSet[*c.ID]; alreadyLinked {
			continue
		}
		compDefID := uuid.Nil
		if c.ComponentDefinitionID != nil {
			compDefID = *c.ComponentDefinitionID
		}
		suggestions = append(suggestions, SystemComponentSuggestion{
			Name:                  c.Title,
			Type:                  c.Type,
			Description:           c.Description,
			Purpose:               c.Purpose,
			DefinedComponentID:    *c.ID,
			ComponentDefinitionID: compDefID,
		})
	}

	return suggestions, nil
}

// ApplyForImplementedRequirement creates missing SystemComponents for all suggestions related to the given
// ImplementedRequirement and links each one via a ByComponent entry. Idempotent: re-running is safe.
func (s *SystemComponentSuggestionService) ApplyForImplementedRequirement(
	sspID uuid.UUID,
	implReqID uuid.UUID,
) error {
	// 1. Get the SystemImplementation for this SSP
	var systemImpl SystemImplementation
	if err := s.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		return fmt.Errorf("system implementation not found for SSP %s: %w", sspID, err)
	}
	systemImplID := *systemImpl.ID

	suggestions, err := s.SuggestForImplementedRequirement(sspID, implReqID)
	if err != nil {
		return err
	}

	if len(suggestions) == 0 {
		return nil
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		for _, suggestion := range suggestions {
			definedComponentID := suggestion.DefinedComponentID

			// Use FirstOrCreate to ensure idempotency even under concurrent requests
			status := SystemComponentStatus{State: "operational"}
			component := SystemComponent{
				Type:                   suggestion.Type,
				Title:                  suggestion.Name,
				Description:            suggestion.Description,
				Purpose:                suggestion.Purpose,
				Status:                 datatypes.NewJSONType(status),
				SystemImplementationId: systemImplID,
				DefinedComponentID:     &definedComponentID,
			}
			if err := tx.Where("system_implementation_id = ? AND defined_component_id = ?",
				systemImplID, definedComponentID).
				FirstOrCreate(&component).Error; err != nil {
				return fmt.Errorf("failed to create system component for defined component %s: %w", definedComponentID, err)
			}

			// Create a ByComponent linking the SystemComponent to the ImplementedRequirement
			// Check if it already exists to maintain idempotency
			parentID := implReqID
			parentType := "implemented_requirements"
			implStatus := ImplementationStatus{State: "implemented"}
			byComponent := ByComponent{
				ComponentUUID:        *component.ID,
				Description:          suggestion.Description,
				ParentID:             &parentID,
				ParentType:           &parentType,
				ImplementationStatus: datatypes.NewJSONType(implStatus),
			}
			if err := tx.Where("component_uuid = ? AND parent_id = ? AND parent_type = ?", *component.ID, parentID, parentType).
				FirstOrCreate(&byComponent).Error; err != nil {
				return fmt.Errorf("failed to create by-component for system component %s: %w", *component.ID, err)
			}
		}
		return nil
	})
}

// ApplyForSSP iterates all ImplementedRequirements for the SSP and applies component suggestions for each.
func (s *SystemComponentSuggestionService) ApplyForSSP(sspID uuid.UUID) error {
	var controlImpl ControlImplementation
	if err := s.db.Where("system_security_plan_id = ?", sspID).First(&controlImpl).Error; err != nil {
		return fmt.Errorf("control implementation not found for SSP %s: %w", sspID, err)
	}

	var implReqs []ImplementedRequirement
	if err := s.db.Where("control_implementation_id = ?", controlImpl.ID).Find(&implReqs).Error; err != nil {
		return fmt.Errorf("failed to fetch implemented requirements: %w", err)
	}

	// Apply suggestions for each ImplementedRequirement
	// Note: While this will cause N+1 Query problems, it is a
	// chosen trade-off for now, as a batch-like approach would have
	// cross-product over-linking issues
	// When this endpoint starts to be a bottleneck, we should probably move to an
	// Asynchronous operation.
	for _, implReq := range implReqs {
		if err := s.ApplyForImplementedRequirement(sspID, *implReq.ID); err != nil {
			return fmt.Errorf("failed to apply suggestions for requirement %s: %w", *implReq.ID, err)
		}
	}

	return nil
}
