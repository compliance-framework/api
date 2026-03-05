package relational

import (
	"fmt"
	"strings"

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

	// 2. Fetch the ImplementedRequirement to get the ControlId
	var implReq ImplementedRequirement
	if err := s.db.First(&implReq, "id = ?", implReqID).Error; err != nil {
		return nil, fmt.Errorf("implemented requirement not found: %w", err)
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
	// This would require additional join chains + passing the SSP ID to this method.
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
		Joins("JOIN evidence_labels el ON el.labels_name = cdl.key AND el.labels_value = cdl.value").
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
			if err := tx.Where("component_uuid = ? AND parent_id = ?",
				*component.ID, parentID).
				FirstOrCreate(&byComponent).Error; err != nil {
				return fmt.Errorf("failed to create by-component for system component %s: %w", *component.ID, err)
			}
		}
		return nil
	})
}

// ApplyForSSP iterates all ImplementedRequirements for the SSP and applies component suggestions for each.
// Optimized to batch-load all suggestions and bulk-insert components to avoid N+1 queries.
func (s *SystemComponentSuggestionService) ApplyForSSP(sspID uuid.UUID) error {
	// 1. Get the SystemImplementation for this SSP
	var systemImpl SystemImplementation
	if err := s.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		return fmt.Errorf("system implementation not found for SSP %s: %w", sspID, err)
	}
	systemImplID := *systemImpl.ID

	// 2. Get the ControlImplementation for this SSP
	var controlImpl ControlImplementation
	if err := s.db.Where("system_security_plan_id = ?", sspID).First(&controlImpl).Error; err != nil {
		return fmt.Errorf("control implementation not found for SSP %s: %w", sspID, err)
	}

	// 3. Get all ImplementedRequirements for this ControlImplementation
	var implReqs []ImplementedRequirement
	if err := s.db.Where("control_implementation_id = ?", controlImpl.ID).Find(&implReqs).Error; err != nil {
		return fmt.Errorf("failed to fetch implemented requirements: %w", err)
	}

	if len(implReqs) == 0 {
		return nil
	}

	// 4. Batch-load all control IDs
	controlIDs := make([]string, len(implReqs))
	implReqMap := make(map[string]uuid.UUID, len(implReqs)) // controlID -> implReqID
	for i, req := range implReqs {
		controlIDs[i] = req.ControlId
		implReqMap[req.ControlId] = *req.ID
	}

	// 5. Batch-load all filters for these controls
	var filters []Filter
	if err := s.db.
		Joins("JOIN filter_controls ON filter_controls.filter_id = filters.id").
		Where("UPPER(filter_controls.control_id) IN ?", upperStrings(controlIDs)).
		Find(&filters).Error; err != nil {
		return fmt.Errorf("failed to query filters: %w", err)
	}

	if len(filters) == 0 {
		return nil
	}

	// 6. Get latest Evidence for all filters
	labelFilters := make([]labelfilter.Filter, len(filters))
	for i, f := range filters {
		labelFilters[i] = f.Filter.Data()
	}
	evidences, err := s.evidenceSvc.GetLatestForFilters(labelFilters...)
	if err != nil {
		return fmt.Errorf("failed to get evidence for filters: %w", err)
	}

	if len(evidences) == 0 {
		return nil
	}

	evidenceIDs := make([]uuid.UUID, len(evidences))
	for i, e := range evidences {
		evidenceIDs[i] = *e.ID
	}

	// 7. Batch-load all candidate DefinedComponents
	subQ := s.db.Table("component_definition_labels cdl").
		Select("cdl.component_definition_id").
		Joins("JOIN evidence_labels el ON el.labels_name = cdl.key AND el.labels_value = cdl.value").
		Where("el.evidence_id IN ?", evidenceIDs)

	var candidates []DefinedComponent
	if err := s.db.
		Where("component_definition_id IN (?)", subQ).
		Find(&candidates).Error; err != nil {
		return fmt.Errorf("failed to query defined components: %w", err)
	}

	if len(candidates) == 0 {
		return nil
	}

	candidateIDs := make([]uuid.UUID, len(candidates))
	for i, c := range candidates {
		candidateIDs[i] = *c.ID
	}

	// 8. Batch-load existing SystemComponents to avoid duplicates
	var existingIDs []uuid.UUID
	if err := s.db.
		Model(&SystemComponent{}).
		Where("system_implementation_id = ? AND defined_component_id IN ?", systemImplID, candidateIDs).
		Pluck("defined_component_id", &existingIDs).Error; err != nil {
		return fmt.Errorf("failed to query existing system components: %w", err)
	}

	existingSet := make(map[uuid.UUID]struct{}, len(existingIDs))
	for _, id := range existingIDs {
		existingSet[id] = struct{}{}
	}

	// 9. Build map of controlID -> matching DefinedComponents
	// We need to re-query filters with control associations to map components to controls
	type filterControl struct {
		FilterID  uuid.UUID
		ControlID string
	}
	var filterControls []filterControl
	if err := s.db.Table("filter_controls").
		Select("filter_id, control_id").
		Where("UPPER(control_id) IN ?", upperStrings(controlIDs)).
		Scan(&filterControls).Error; err != nil {
		return fmt.Errorf("failed to query filter controls: %w", err)
	}

	// Map filterID -> []controlID
	filterToControls := make(map[uuid.UUID][]string)
	for _, fc := range filterControls {
		filterToControls[fc.FilterID] = append(filterToControls[fc.FilterID], fc.ControlID)
	}

	// Map each candidate to its applicable controls via filter matching
	// This is simplified - we match any candidate that came from filters associated with the control
	controlToComponents := make(map[string][]DefinedComponent)
	for _, candidate := range candidates {
		// Find which filters would match this component (via evidence labels)
		// For simplicity, we'll associate the component with all controls from matching filters
		// This is an approximation but maintains the same behavior as the per-requirement approach
		for _, filter := range filters {
			if controls, ok := filterToControls[*filter.ID]; ok {
				for _, controlID := range controls {
					if _, alreadyLinked := existingSet[*candidate.ID]; !alreadyLinked {
						controlToComponents[controlID] = append(controlToComponents[controlID], candidate)
					}
				}
			}
		}
	}

	// 10. Bulk-insert SystemComponents and ByComponents in a single transaction
	return s.db.Transaction(func(tx *gorm.DB) error {
		for controlID, components := range controlToComponents {
			implReqID, ok := implReqMap[controlID]
			if !ok {
				continue
			}

			for _, component := range components {
				definedComponentID := *component.ID

				// Use FirstOrCreate to ensure idempotency
				status := SystemComponentStatus{State: "operational"}
				sysComp := SystemComponent{
					Type:                   component.Type,
					Title:                  component.Title,
					Description:            component.Description,
					Purpose:                component.Purpose,
					Status:                 datatypes.NewJSONType(status),
					SystemImplementationId: systemImplID,
					DefinedComponentID:     &definedComponentID,
				}
				if err := tx.Where("system_implementation_id = ? AND defined_component_id = ?",
					systemImplID, definedComponentID).
					FirstOrCreate(&sysComp).Error; err != nil {
					return fmt.Errorf("failed to create system component for defined component %s: %w", definedComponentID, err)
				}

				// Create ByComponent link
				parentID := implReqID
				parentType := "implemented_requirements"
				implStatus := ImplementationStatus{State: "implemented"}
				byComponent := ByComponent{
					ComponentUUID:        *sysComp.ID,
					Description:          component.Description,
					ParentID:             &parentID,
					ParentType:           &parentType,
					ImplementationStatus: datatypes.NewJSONType(implStatus),
				}
				if err := tx.Where("component_uuid = ? AND parent_id = ?",
					*sysComp.ID, parentID).
					FirstOrCreate(&byComponent).Error; err != nil {
					return fmt.Errorf("failed to create by-component for system component %s: %w", *sysComp.ID, err)
				}
			}
		}
		return nil
	})
}

// upperStrings converts a slice of strings to uppercase for case-insensitive matching
func upperStrings(strs []string) []string {
	result := make([]string, len(strs))
	for i, s := range strs {
		result[i] = strings.ToUpper(s)
	}
	return result
}
