package relational

import (
	"fmt"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
		return nil, fmt.Errorf("implemented requirement %s not found for SSP %s: %w", implReqID, sspID, err)
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

	// 5. Find candidate DefinedComponents whose identity labels ALL match evidence labels.
	//    A component is a match only if ALL of its labels are present in the evidence.
	//    component_definition_labels must be scoped to defined_component_id.
	//    Legacy rows without defined_component_id are intentionally unsupported.
	matchedDefinedComponentIDs := make([]uuid.UUID, 0)
	if err := s.db.Table("component_definition_labels cdl").
		Select("cdl.defined_component_id").
		Joins("JOIN evidence_labels el ON LOWER(el.labels_name) = LOWER(cdl.key) AND LOWER(el.labels_value) = LOWER(cdl.value)").
		Where("el.evidence_id IN ?", evidenceIDs).
		Where("cdl.defined_component_id IS NOT NULL").
		Group("cdl.defined_component_id").
		Having("COUNT(DISTINCT cdl.key || '=' || cdl.value) = (SELECT COUNT(*) FROM component_definition_labels WHERE defined_component_id = cdl.defined_component_id)").
		Pluck("cdl.defined_component_id", &matchedDefinedComponentIDs).Error; err != nil {
		return nil, fmt.Errorf("failed to query defined component label matches: %w", err)
	}

	if len(matchedDefinedComponentIDs) == 0 {
		return []SystemComponentSuggestion{}, nil
	}

	var candidates []DefinedComponent
	if err := s.db.
		Where("id IN ?", matchedDefinedComponentIDs).
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

// SuggestForStatement returns the same candidate components as the parent ImplementedRequirement,
// after validating that the statement belongs to the given requirement and SSP.
func (s *SystemComponentSuggestionService) SuggestForStatement(
	sspID uuid.UUID,
	implReqID uuid.UUID,
	stmtID uuid.UUID,
) ([]SystemComponentSuggestion, error) {
	if err := s.validateStatementForImplementedRequirement(sspID, implReqID, stmtID); err != nil {
		return nil, err
	}
	return s.SuggestForImplementedRequirement(sspID, implReqID)
}

// ApplyForImplementedRequirement creates missing SystemComponents for all suggestions related to the given
// ImplementedRequirement and links each one via a ByComponent entry. Idempotent: re-running is safe.
func (s *SystemComponentSuggestionService) ApplyForImplementedRequirement(
	sspID uuid.UUID,
	implReqID uuid.UUID,
) error {
	return s.applyForParent(sspID, implReqID, implReqID, "implemented_requirements")
}

// ApplySuggestionForImplementedRequirement creates or reuses a SystemComponent for the provided
// suggestion and links it to the ImplementedRequirement via ByComponent.
func (s *SystemComponentSuggestionService) ApplySuggestionForImplementedRequirement(
	sspID uuid.UUID,
	implReqID uuid.UUID,
	componentDefinitionID uuid.UUID,
	definedComponentID uuid.UUID,
) error {
	return s.applySuggestionForParent(
		sspID,
		implReqID,
		implReqID,
		"implemented_requirements",
		componentDefinitionID,
		definedComponentID,
	)
}

// ApplyForStatement creates missing SystemComponents for all suggestions related to the
// parent ImplementedRequirement and links each one to the statement via ByComponent.
func (s *SystemComponentSuggestionService) ApplyForStatement(
	sspID uuid.UUID,
	implReqID uuid.UUID,
	stmtID uuid.UUID,
) error {
	if err := s.validateStatementForImplementedRequirement(sspID, implReqID, stmtID); err != nil {
		return err
	}
	return s.applyForParent(sspID, implReqID, stmtID, "statements")
}

// ApplySuggestionForStatement creates or reuses a SystemComponent for the provided suggestion
// and links it to the Statement via ByComponent.
func (s *SystemComponentSuggestionService) ApplySuggestionForStatement(
	sspID uuid.UUID,
	implReqID uuid.UUID,
	stmtID uuid.UUID,
	componentDefinitionID uuid.UUID,
	definedComponentID uuid.UUID,
) error {
	if err := s.validateStatementForImplementedRequirement(sspID, implReqID, stmtID); err != nil {
		return err
	}
	return s.applySuggestionForParent(
		sspID,
		implReqID,
		stmtID,
		"statements",
		componentDefinitionID,
		definedComponentID,
	)
}

func (s *SystemComponentSuggestionService) applyForParent(
	sspID uuid.UUID,
	implReqID uuid.UUID,
	parentID uuid.UUID,
	parentType string,
) error {
	systemImplID, err := s.getSystemImplementationID(sspID)
	if err != nil {
		return err
	}

	suggestions, err := s.SuggestForImplementedRequirement(sspID, implReqID)
	if err != nil {
		return err
	}

	if len(suggestions) == 0 {
		return nil
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		for _, suggestion := range suggestions {
			component, err := s.ensureSystemComponent(tx, systemImplID, suggestion)
			if err != nil {
				return err
			}
			if err := s.ensureByComponentLink(tx, *component.ID, suggestion.Description, parentID, parentType); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SystemComponentSuggestionService) applySuggestionForParent(
	sspID uuid.UUID,
	implReqID uuid.UUID,
	parentID uuid.UUID,
	parentType string,
	componentDefinitionID uuid.UUID,
	definedComponentID uuid.UUID,
) error {
	var definedComponent DefinedComponent
	if err := s.db.
		Where("id = ? AND component_definition_id = ?", definedComponentID, componentDefinitionID).
		First(&definedComponent).Error; err != nil {
		return fmt.Errorf(
			"defined component %s not found in component definition %s: %w",
			definedComponentID,
			componentDefinitionID,
			err,
		)
	}

	suggestions, err := s.SuggestForImplementedRequirement(sspID, implReqID)
	if err != nil {
		return err
	}

	suggestion, found := findSuggestion(suggestions, componentDefinitionID, definedComponentID)
	if !found {
		systemImplID, err := s.getSystemImplementationID(sspID)
		if err != nil {
			return err
		}
		alreadyLinked, err := s.hasByComponentLinkForParent(systemImplID, definedComponentID, parentID, parentType)
		if err != nil {
			return err
		}
		if alreadyLinked {
			return nil
		}
		return fmt.Errorf(
			"suggestion for defined component %s in component definition %s not found for implemented requirement %s in SSP %s: %w",
			definedComponentID,
			componentDefinitionID,
			implReqID,
			sspID,
			gorm.ErrRecordNotFound,
		)
	}

	systemImplID, err := s.getSystemImplementationID(sspID)
	if err != nil {
		return err
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		component, err := s.ensureSystemComponent(tx, systemImplID, suggestion)
		if err != nil {
			return err
		}
		if err := s.ensureByComponentLink(tx, *component.ID, suggestion.Description, parentID, parentType); err != nil {
			return err
		}
		return nil
	})
}

func (s *SystemComponentSuggestionService) getSystemImplementationID(sspID uuid.UUID) (uuid.UUID, error) {
	var systemImpl SystemImplementation
	if err := s.db.Where("system_security_plan_id = ?", sspID).First(&systemImpl).Error; err != nil {
		return uuid.Nil, fmt.Errorf("system implementation not found for SSP %s: %w", sspID, err)
	}
	return *systemImpl.ID, nil
}

func (s *SystemComponentSuggestionService) ensureSystemComponent(
	tx *gorm.DB,
	systemImplID uuid.UUID,
	suggestion SystemComponentSuggestion,
) (*SystemComponent, error) {
	definedComponentID := suggestion.DefinedComponentID

	// Use ON CONFLICT DO NOTHING to ensure idempotency even under concurrent requests.
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
	// Use ON CONFLICT DO NOTHING to handle concurrent requests gracefully.
	// The partial unique index on (system_implementation_id, defined_component_id)
	// WHERE defined_component_id IS NOT NULL ensures idempotency.
	if err := tx.Clauses(clause.OnConflict{
		DoNothing: true,
	}).Create(&component).Error; err != nil {
		return nil, fmt.Errorf("failed to create system component for defined component %s: %w", definedComponentID, err)
	}

	// Load the component to get its ID (either newly created or existing).
	if err := tx.
		Where("system_implementation_id = ? AND defined_component_id = ?", systemImplID, definedComponentID).
		First(&component).Error; err != nil {
		return nil, fmt.Errorf("failed to load system component for defined component %s: %w", definedComponentID, err)
	}

	return &component, nil
}

func (s *SystemComponentSuggestionService) ensureByComponentLink(
	tx *gorm.DB,
	componentID uuid.UUID,
	description string,
	parentID uuid.UUID,
	parentType string,
) error {
	implStatus := ImplementationStatus{State: "implemented"}
	// Generate deterministic UUID from the unique key (component_uuid, parent_id, parent_type).
	// This ensures concurrent requests generate the same UUID, making the operation idempotent.
	deterministicID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(
		componentID.String()+":"+parentID.String()+":"+parentType,
	))
	byComponent := ByComponent{
		UUIDModel: UUIDModel{
			ID: &deterministicID,
		},
		ComponentUUID:        componentID,
		Description:          description,
		ParentID:             &parentID,
		ParentType:           &parentType,
		ImplementationStatus: datatypes.NewJSONType(implStatus),
	}
	// Use ON CONFLICT DO NOTHING - the deterministic UUID ensures idempotency.
	if err := tx.Clauses(clause.OnConflict{
		DoNothing: true,
	}).Create(&byComponent).Error; err != nil {
		return fmt.Errorf("failed to create by-component for system component %s: %w", componentID, err)
	}

	return nil
}

func (s *SystemComponentSuggestionService) hasByComponentLinkForParent(
	systemImplID uuid.UUID,
	definedComponentID uuid.UUID,
	parentID uuid.UUID,
	parentType string,
) (bool, error) {
	var count int64
	if err := s.db.
		Table("by_components").
		Joins("JOIN system_components ON system_components.id = by_components.component_uuid").
		Where(
			"system_components.system_implementation_id = ? AND system_components.defined_component_id = ? AND by_components.parent_id = ? AND by_components.parent_type = ?",
			systemImplID,
			definedComponentID,
			parentID,
			parentType,
		).
		Count(&count).Error; err != nil {
		return false, fmt.Errorf(
			"failed to verify existing by-component link for defined component %s and parent %s (%s): %w",
			definedComponentID,
			parentID,
			parentType,
			err,
		)
	}

	return count > 0, nil
}

func findSuggestion(
	suggestions []SystemComponentSuggestion,
	componentDefinitionID uuid.UUID,
	definedComponentID uuid.UUID,
) (SystemComponentSuggestion, bool) {
	for _, suggestion := range suggestions {
		if suggestion.ComponentDefinitionID == componentDefinitionID && suggestion.DefinedComponentID == definedComponentID {
			return suggestion, true
		}
	}
	return SystemComponentSuggestion{}, false
}

func (s *SystemComponentSuggestionService) validateStatementForImplementedRequirement(
	sspID uuid.UUID,
	implReqID uuid.UUID,
	stmtID uuid.UUID,
) error {
	var statement Statement
	if err := s.db.
		Table("statements").
		Joins("JOIN implemented_requirements ON implemented_requirements.id = statements.implemented_requirement_id").
		Joins("JOIN control_implementations ON control_implementations.id = implemented_requirements.control_implementation_id").
		Where(
			"statements.id = ? AND implemented_requirements.id = ? AND control_implementations.system_security_plan_id = ?",
			stmtID,
			implReqID,
			sspID,
		).
		First(&statement).Error; err != nil {
		return fmt.Errorf(
			"statement %s not found for implemented requirement %s in SSP %s: %w",
			stmtID,
			implReqID,
			sspID,
			err,
		)
	}
	return nil
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
