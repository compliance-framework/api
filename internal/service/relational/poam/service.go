package poam

import (
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// PoamService encapsulates all database operations for POAM items and their
// sub-resources. Handlers must not import gorm directly; all persistence is
// delegated here.
type PoamService struct {
	db *gorm.DB
}

// NewPoamService constructs a PoamService backed by the given *gorm.DB.
func NewPoamService(db *gorm.DB) *PoamService {
	return &PoamService{db: db}
}

// ---------------------------------------------------------------------------
// Param types
// ---------------------------------------------------------------------------

// CreatePoamItemParams carries all data required to create a POAM item and its
// initial milestones and link records in a single transaction.
type CreatePoamItemParams struct {
	SspID                 uuid.UUID
	Title                 string
	Description           string
	Status                string
	SourceType            string
	PrimaryOwnerUserID    *uuid.UUID
	PlannedCompletionDate *time.Time
	CreatedFromRiskID     *uuid.UUID
	AcceptanceRationale   *string
	ResourceRequired *string
	RiskIDs               []uuid.UUID
	EvidenceIDs           []uuid.UUID
	ControlRefs           []ControlRef
	FindingIDs            []uuid.UUID
	Milestones            []CreateMilestoneParams
}

// UpdatePoamItemParams carries the fields that may be patched on an existing
// POAM item. Only non-nil pointer fields are applied. Link slices use explicit
// add/remove semantics so callers can manage associations in one call.
type UpdatePoamItemParams struct {
	Title                 *string
	Description           *string
	Status                *string
	PrimaryOwnerUserID    *uuid.UUID
	PlannedCompletionDate *time.Time
	AcceptanceRationale   *string
	// Link management — applied inside the same transaction as the scalar update.
	AddRiskIDs        []uuid.UUID
	RemoveRiskIDs     []uuid.UUID
	AddEvidenceIDs    []uuid.UUID
	RemoveEvidenceIDs []uuid.UUID
	AddControlRefs    []ControlRef
	RemoveControlRefs []ControlRef
	AddFindingIDs     []uuid.UUID
	RemoveFindingIDs  []uuid.UUID
}

// CreateMilestoneParams carries all data required to create a single milestone.
type CreateMilestoneParams struct {
	Title                 string
	Description           string
	Status                string
	PlannedCompletionDate *time.Time
	ResponsibleParty      *string
	Remarks               *string
	OrderIndex            int
}

// UpdateMilestoneParams carries the fields that may be patched on an existing
// milestone. Only non-nil pointer fields are applied.
type UpdateMilestoneParams struct {
	Title                 *string
	Description           *string
	Status                *string
	PlannedCompletionDate *time.Time
	ResponsibleParty      *string
	Remarks               *string
	OrderIndex            *int
}

// ---------------------------------------------------------------------------
// POAM item CRUD
// ---------------------------------------------------------------------------

// List returns all POAM items matching the given filters.
func (s *PoamService) List(filters ListFilters) ([]PoamItem, error) {
	var items []PoamItem
	q := ApplyFilters(s.db, filters)
	if err := q.Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

// Create inserts a new POAM item together with its initial milestones and all
// link records inside a single database transaction.
func (s *PoamService) Create(params CreatePoamItemParams) (*PoamItem, error) {
	item := PoamItem{
		SspID:                 params.SspID,
		Title:                 params.Title,
		Description:           params.Description,
		Status:                params.Status,
		SourceType:            params.SourceType,
		PrimaryOwnerUserID:    params.PrimaryOwnerUserID,
		PlannedCompletionDate: params.PlannedCompletionDate,
		CreatedFromRiskID:     params.CreatedFromRiskID,
		AcceptanceRationale:   params.AcceptanceRationale,
		ResourceRequired:      params.ResourceRequired,
	}

	tx, err := beginTx(s.db)
	if err != nil {
		return nil, err
	}
	defer rollbackTxOnPanic(tx)

	if err := tx.Create(&item).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	for i, mp := range params.Milestones {
		orderIdx := mp.OrderIndex
		if orderIdx == 0 {
			orderIdx = i
		}
		ms := PoamItemMilestone{
			PoamItemID:            item.ID,
			Title:                 mp.Title,
			Description:           mp.Description,
			Status:                mp.Status,
			PlannedCompletionDate: mp.PlannedCompletionDate,
			ResponsibleParty:      mp.ResponsibleParty,
			Remarks:               mp.Remarks,
			OrderIndex:            orderIdx,
		}
		if err := tx.Create(&ms).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	for _, riskID := range params.RiskIDs {
		link := PoamItemRiskLink{PoamItemID: item.ID, RiskID: riskID}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&link).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	for _, evidenceID := range params.EvidenceIDs {
		link := PoamItemEvidenceLink{PoamItemID: item.ID, EvidenceID: evidenceID}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&link).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	for _, cr := range params.ControlRefs {
		link := PoamItemControlLink{PoamItemID: item.ID, CatalogID: cr.CatalogID, ControlID: cr.ControlID}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&link).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	for _, findingID := range params.FindingIDs {
		link := PoamItemFindingLink{PoamItemID: item.ID, FindingID: findingID}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&link).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return s.GetByID(item.ID)
}

// GetByID fetches a single POAM item by its UUID, preloading milestones ordered
// by order_index ascending.
func (s *PoamService) GetByID(id uuid.UUID) (*PoamItem, error) {
	var item PoamItem
	err := s.db.
		Preload("Milestones", func(db *gorm.DB) *gorm.DB {
			return db.Order("order_index ASC")
		}).
		Preload("RiskLinks").
		Preload("EvidenceLinks").
		Preload("ControlLinks").
		Preload("FindingLinks").
		First(&item, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &item, nil
}

// Update applies non-nil scalar fields from params to the POAM item identified
// by id, and processes any link add/remove operations — all inside a single
// transaction. This follows the Risk service pattern: fetch the current record,
// mutate the struct, then call tx.Save() rather than using a raw map.
//
// last_status_change_at is stamped only when the status actually changes.
// completed_at is set automatically when status transitions to "completed" and
// cleared if status moves away from "completed". It is not settable via params.
func (s *PoamService) Update(id uuid.UUID, params UpdatePoamItemParams) (*PoamItem, error) {
	item, err := s.GetByID(id)
	if err != nil {
		return nil, err
	}

	// Detect status change before mutating.
	statusChanged := params.Status != nil && *params.Status != item.Status

	if params.Title != nil {
		item.Title = *params.Title
	}
	if params.Description != nil {
		item.Description = *params.Description
	}
	if params.Status != nil {
		if !PoamItemStatus(*params.Status).IsValid() {
			return nil, fmt.Errorf("invalid status: %s", *params.Status)
		}
		item.Status = *params.Status
		if statusChanged {
			item.LastStatusChangeAt = time.Now().UTC()
			if *params.Status == string(PoamItemStatusCompleted) {
				now := time.Now().UTC()
				item.CompletedAt = &now
			} else {
				// Clear completed_at if moving away from completed.
				item.CompletedAt = nil
			}
		}
	}
	if params.PrimaryOwnerUserID != nil {
		item.PrimaryOwnerUserID = params.PrimaryOwnerUserID
	}
	if params.PlannedCompletionDate != nil {
		item.PlannedCompletionDate = params.PlannedCompletionDate
	}
	if params.AcceptanceRationale != nil {
		item.AcceptanceRationale = params.AcceptanceRationale
	}

	hasLinkChanges := len(params.AddRiskIDs) > 0 || len(params.RemoveRiskIDs) > 0 ||
		len(params.AddEvidenceIDs) > 0 || len(params.RemoveEvidenceIDs) > 0 ||
		len(params.AddControlRefs) > 0 || len(params.RemoveControlRefs) > 0 ||
		len(params.AddFindingIDs) > 0 || len(params.RemoveFindingIDs) > 0

	if !hasLinkChanges {
		// Scalar-only update — use a transaction for the Save.
		tx, err := beginTx(s.db)
		if err != nil {
			return nil, err
		}
		defer rollbackTxOnPanic(tx)
		if err := tx.Save(item).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
		if err := tx.Commit().Error; err != nil {
			return nil, err
		}
		return s.GetByID(id)
	}

	// Combined scalar + link update in a single transaction.
	tx, err := beginTx(s.db)
	if err != nil {
		return nil, err
	}
	defer rollbackTxOnPanic(tx)

	if err := tx.Save(item).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	// Risk links.
	for _, riskID := range params.AddRiskIDs {
		link := PoamItemRiskLink{PoamItemID: id, RiskID: riskID}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&link).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}
	for _, riskID := range params.RemoveRiskIDs {
		if err := tx.Where("poam_item_id = ? AND risk_id = ?", id, riskID).Delete(&PoamItemRiskLink{}).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	// Evidence links.
	for _, evidenceID := range params.AddEvidenceIDs {
		link := PoamItemEvidenceLink{PoamItemID: id, EvidenceID: evidenceID}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&link).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}
	for _, evidenceID := range params.RemoveEvidenceIDs {
		if err := tx.Where("poam_item_id = ? AND evidence_id = ?", id, evidenceID).Delete(&PoamItemEvidenceLink{}).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	// Control links.
	for _, cr := range params.AddControlRefs {
		link := PoamItemControlLink{PoamItemID: id, CatalogID: cr.CatalogID, ControlID: cr.ControlID}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&link).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}
	for _, cr := range params.RemoveControlRefs {
		if err := tx.Where("poam_item_id = ? AND catalog_id = ? AND control_id = ?", id, cr.CatalogID, cr.ControlID).Delete(&PoamItemControlLink{}).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	// Finding links.
	for _, findingID := range params.AddFindingIDs {
		link := PoamItemFindingLink{PoamItemID: id, FindingID: findingID}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&link).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}
	for _, findingID := range params.RemoveFindingIDs {
		if err := tx.Where("poam_item_id = ? AND finding_id = ?", id, findingID).Delete(&PoamItemFindingLink{}).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return s.GetByID(id)
}

// Delete removes a POAM item and all its dependent records (milestones, all
// four link tables) inside a single transaction.
func (s *PoamService) Delete(id uuid.UUID) error {
	tx, err := beginTx(s.db)
	if err != nil {
		return err
	}
	defer rollbackTxOnPanic(tx)

	if err := tx.Where("poam_item_id = ?", id).Delete(&PoamItemRiskLink{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Where("poam_item_id = ?", id).Delete(&PoamItemEvidenceLink{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Where("poam_item_id = ?", id).Delete(&PoamItemControlLink{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Where("poam_item_id = ?", id).Delete(&PoamItemFindingLink{}).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Where("poam_item_id = ?", id).Delete(&PoamItemMilestone{}).Error; err != nil {
		tx.Rollback()
		return err
	}

	result := tx.Delete(&PoamItem{}, "id = ?", id)
	if result.Error != nil {
		tx.Rollback()
		return result.Error
	}
	if result.RowsAffected == 0 {
		tx.Rollback()
		return gorm.ErrRecordNotFound
	}

	return tx.Commit().Error
}

// EnsureExists returns nil if a POAM item with the given id exists, or
// gorm.ErrRecordNotFound if it does not.
func (s *PoamService) EnsureExists(id uuid.UUID) error {
	var item PoamItem
	return s.db.Select("id").First(&item, "id = ?", id).Error
}

// EnsureSSPExists returns nil if an SSP with the given id exists, or
// gorm.ErrRecordNotFound if it does not.
func (s *PoamService) EnsureSSPExists(id uuid.UUID) error {
	var ssp relational.SystemSecurityPlan
	return s.db.Select("id").First(&ssp, "id = ?", id).Error
}

// ---------------------------------------------------------------------------
// Milestone operations
// ---------------------------------------------------------------------------

// ListMilestones returns all milestones for the given POAM item, ordered by
// order_index ascending.
func (s *PoamService) ListMilestones(poamItemID uuid.UUID) ([]PoamItemMilestone, error) {
	var milestones []PoamItemMilestone
	if err := s.db.
		Where("poam_item_id = ?", poamItemID).
		Order("order_index ASC").
		Find(&milestones).Error; err != nil {
		return nil, err
	}
	return milestones, nil
}

// AddMilestone inserts a new milestone for the given POAM item.
func (s *PoamService) AddMilestone(poamItemID uuid.UUID, params CreateMilestoneParams) (*PoamItemMilestone, error) {
	m := PoamItemMilestone{
		PoamItemID:            poamItemID,
		Title:                 params.Title,
		Description:           params.Description,
		Status:                params.Status,
		PlannedCompletionDate: params.PlannedCompletionDate,
		ResponsibleParty:      params.ResponsibleParty,
		Remarks:               params.Remarks,
		OrderIndex:            params.OrderIndex,
	}
	if err := s.db.Create(&m).Error; err != nil {
		return nil, err
	}
	return &m, nil
}

// UpdateMilestone applies non-nil fields from params to the milestone identified
// by (poamItemID, milestoneID). When status transitions to "completed",
// completion_date is set automatically. Returns gorm.ErrRecordNotFound when the
// milestone does not belong to the given POAM item.
func (s *PoamService) UpdateMilestone(poamItemID, milestoneID uuid.UUID, params UpdateMilestoneParams) (*PoamItemMilestone, error) {
	m, err := s.getMilestoneByID(poamItemID, milestoneID)
	if err != nil {
		return nil, err
	}

	statusChanged := params.Status != nil && *params.Status != m.Status

	if params.Title != nil {
		m.Title = *params.Title
	}
	if params.Description != nil {
		m.Description = *params.Description
	}
	if params.Status != nil {
		if !MilestoneStatus(*params.Status).IsValid() {
			return nil, fmt.Errorf("invalid milestone status: %s", *params.Status)
		}
		m.Status = *params.Status
		if statusChanged && *params.Status == string(MilestoneStatusCompleted) {
			now := time.Now().UTC()
			m.CompletionDate = &now
		}
	}
	if params.PlannedCompletionDate != nil {
		m.PlannedCompletionDate = params.PlannedCompletionDate
	}
	if params.ResponsibleParty != nil {
		m.ResponsibleParty = params.ResponsibleParty
	}
	if params.Remarks != nil {
		m.Remarks = params.Remarks
	}
	if params.OrderIndex != nil {
		m.OrderIndex = *params.OrderIndex
	}

	tx, err := beginTx(s.db)
	if err != nil {
		return nil, err
	}
	defer rollbackTxOnPanic(tx)

	if err := tx.Save(m).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return s.getMilestoneByID(poamItemID, milestoneID)
}

// DeleteMilestone removes the milestone identified by (poamItemID, milestoneID).
// Returns gorm.ErrRecordNotFound when the milestone does not exist or does not
// belong to the given POAM item.
func (s *PoamService) DeleteMilestone(poamItemID, milestoneID uuid.UUID) error {
	result := s.db.
		Where("poam_item_id = ? AND id = ?", poamItemID, milestoneID).
		Delete(&PoamItemMilestone{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// getMilestoneByID is an internal helper that fetches a milestone by its
// composite key (poamItemID, milestoneID).
func (s *PoamService) getMilestoneByID(poamItemID, milestoneID uuid.UUID) (*PoamItemMilestone, error) {
	var m PoamItemMilestone
	if err := s.db.First(&m, "poam_item_id = ? AND id = ?", poamItemID, milestoneID).Error; err != nil {
		return nil, err
	}
	return &m, nil
}

// ---------------------------------------------------------------------------
// Link sub-resource operations
// ---------------------------------------------------------------------------

// ListRiskLinks returns all risk link records for the given POAM item.
func (s *PoamService) ListRiskLinks(poamItemID uuid.UUID) ([]PoamItemRiskLink, error) {
	var links []PoamItemRiskLink
	if err := s.db.Where("poam_item_id = ?", poamItemID).Find(&links).Error; err != nil {
		return nil, err
	}
	return links, nil
}

// AddRiskLink creates a risk link for the given POAM item. Duplicate links are
// silently ignored (ON CONFLICT DO NOTHING), matching the Risk service pattern.
func (s *PoamService) AddRiskLink(poamItemID, riskID uuid.UUID) (*PoamItemRiskLink, error) {
	link := PoamItemRiskLink{PoamItemID: poamItemID, RiskID: riskID}
	result := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&link)
	if result.Error != nil {
		return nil, result.Error
	}
	// Re-fetch to ensure we return the persisted record regardless of conflict.
	if err := s.db.Where("poam_item_id = ? AND risk_id = ?", poamItemID, riskID).First(&link).Error; err != nil {
		return nil, err
	}
	return &link, nil
}

// DeleteRiskLink removes the risk link identified by (poamItemID, riskID).
// Returns gorm.ErrRecordNotFound when the link does not exist.
func (s *PoamService) DeleteRiskLink(poamItemID, riskID uuid.UUID) error {
	result := s.db.
		Where("poam_item_id = ? AND risk_id = ?", poamItemID, riskID).
		Delete(&PoamItemRiskLink{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ListEvidenceLinks returns all evidence link records for the given POAM item.
func (s *PoamService) ListEvidenceLinks(poamItemID uuid.UUID) ([]PoamItemEvidenceLink, error) {
	var links []PoamItemEvidenceLink
	if err := s.db.Where("poam_item_id = ?", poamItemID).Find(&links).Error; err != nil {
		return nil, err
	}
	return links, nil
}

// AddEvidenceLink creates an evidence link for the given POAM item. Duplicate
// links are silently ignored.
func (s *PoamService) AddEvidenceLink(poamItemID, evidenceID uuid.UUID) (*PoamItemEvidenceLink, error) {
	link := PoamItemEvidenceLink{PoamItemID: poamItemID, EvidenceID: evidenceID}
	result := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&link)
	if result.Error != nil {
		return nil, result.Error
	}
	if err := s.db.Where("poam_item_id = ? AND evidence_id = ?", poamItemID, evidenceID).First(&link).Error; err != nil {
		return nil, err
	}
	return &link, nil
}

// DeleteEvidenceLink removes the evidence link identified by (poamItemID, evidenceID).
func (s *PoamService) DeleteEvidenceLink(poamItemID, evidenceID uuid.UUID) error {
	result := s.db.
		Where("poam_item_id = ? AND evidence_id = ?", poamItemID, evidenceID).
		Delete(&PoamItemEvidenceLink{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ListControlLinks returns all control link records for the given POAM item.
func (s *PoamService) ListControlLinks(poamItemID uuid.UUID) ([]PoamItemControlLink, error) {
	var links []PoamItemControlLink
	if err := s.db.Where("poam_item_id = ?", poamItemID).Find(&links).Error; err != nil {
		return nil, err
	}
	return links, nil
}

// AddControlLink creates a control link for the given POAM item. Duplicate
// links are silently ignored.
func (s *PoamService) AddControlLink(poamItemID uuid.UUID, ref ControlRef) (*PoamItemControlLink, error) {
	link := PoamItemControlLink{PoamItemID: poamItemID, CatalogID: ref.CatalogID, ControlID: ref.ControlID}
	result := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&link)
	if result.Error != nil {
		return nil, result.Error
	}
	if err := s.db.Where("poam_item_id = ? AND catalog_id = ? AND control_id = ?", poamItemID, ref.CatalogID, ref.ControlID).First(&link).Error; err != nil {
		return nil, err
	}
	return &link, nil
}

// DeleteControlLink removes the control link identified by (poamItemID, catalogID, controlID).
func (s *PoamService) DeleteControlLink(poamItemID, catalogID uuid.UUID, controlID string) error {
	result := s.db.
		Where("poam_item_id = ? AND catalog_id = ? AND control_id = ?", poamItemID, catalogID, controlID).
		Delete(&PoamItemControlLink{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ListFindingLinks returns all finding link records for the given POAM item.
func (s *PoamService) ListFindingLinks(poamItemID uuid.UUID) ([]PoamItemFindingLink, error) {
	var links []PoamItemFindingLink
	if err := s.db.Where("poam_item_id = ?", poamItemID).Find(&links).Error; err != nil {
		return nil, err
	}
	return links, nil
}

// AddFindingLink creates a finding link for the given POAM item. Duplicate
// links are silently ignored.
func (s *PoamService) AddFindingLink(poamItemID, findingID uuid.UUID) (*PoamItemFindingLink, error) {
	link := PoamItemFindingLink{PoamItemID: poamItemID, FindingID: findingID}
	result := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&link)
	if result.Error != nil {
		return nil, result.Error
	}
	if err := s.db.Where("poam_item_id = ? AND finding_id = ?", poamItemID, findingID).First(&link).Error; err != nil {
		return nil, err
	}
	return &link, nil
}

// DeleteFindingLink removes the finding link identified by (poamItemID, findingID).
func (s *PoamService) DeleteFindingLink(poamItemID, findingID uuid.UUID) error {
	result := s.db.
		Where("poam_item_id = ? AND finding_id = ?", poamItemID, findingID).
		Delete(&PoamItemFindingLink{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// CreateWithTx inserts a new POAM item and its milestones/links within an
// externally-managed *gorm.DB transaction. The caller is responsible for
// committing or rolling back the transaction. This is used by cross-context
// operations such as RiskService.PromoteToPoam that need atomicity across
// multiple bounded contexts.
func (s *PoamService) CreateWithTx(tx *gorm.DB, params CreatePoamItemParams) (*PoamItem, error) {
	item := PoamItem{
		SspID:                 params.SspID,
		Title:                 params.Title,
		Description:           params.Description,
		Status:                params.Status,
		SourceType:            params.SourceType,
		PrimaryOwnerUserID:    params.PrimaryOwnerUserID,
		PlannedCompletionDate: params.PlannedCompletionDate,
		CreatedFromRiskID:     params.CreatedFromRiskID,
		AcceptanceRationale:   params.AcceptanceRationale,
		ResourceRequired:      params.ResourceRequired,
	}

	if err := tx.Create(&item).Error; err != nil {
		return nil, err
	}

	for i, mp := range params.Milestones {
		orderIdx := mp.OrderIndex
		if orderIdx == 0 {
			orderIdx = i
		}
		ms := PoamItemMilestone{
			PoamItemID:            item.ID,
			Title:                 mp.Title,
			Description:           mp.Description,
			Status:                mp.Status,
			PlannedCompletionDate: mp.PlannedCompletionDate,
			ResponsibleParty:      mp.ResponsibleParty,
			Remarks:               mp.Remarks,
			OrderIndex:            orderIdx,
		}
		if err := tx.Create(&ms).Error; err != nil {
			return nil, err
		}
	}

	for _, riskID := range params.RiskIDs {
		link := PoamItemRiskLink{PoamItemID: item.ID, RiskID: riskID}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&link).Error; err != nil {
			return nil, err
		}
	}

	return &item, nil
}

// ---------------------------------------------------------------------------
// Transaction helpers
// ---------------------------------------------------------------------------

func beginTx(db *gorm.DB) (*gorm.DB, error) {
	tx := db.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	return tx, nil
}

func rollbackTxOnPanic(tx *gorm.DB) {
	if r := recover(); r != nil {
		tx.Rollback()
		panic(r)
	}
}
