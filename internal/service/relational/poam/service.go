package poam

import (
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
	RiskIDs               []uuid.UUID
	EvidenceIDs           []uuid.UUID
	ControlRefs           []ControlRef
	FindingIDs            []uuid.UUID
	Milestones            []CreateMilestoneParams
}

// UpdatePoamItemParams carries the fields that may be patched on an existing
// POAM item. Only non-nil pointer fields are applied.
type UpdatePoamItemParams struct {
	Title                 *string
	Description           *string
	Status                *string
	PrimaryOwnerUserID    *uuid.UUID
	PlannedCompletionDate *time.Time
	CompletedAt           *time.Time
	AcceptanceRationale   *string
}

// CreateMilestoneParams carries all data required to create a single milestone.
type CreateMilestoneParams struct {
	Title                   string
	Description             string
	Status                  string
	ScheduledCompletionDate *time.Time
	OrderIndex              int
}

// UpdateMilestoneParams carries the fields that may be patched on an existing
// milestone. Only non-nil pointer fields are applied.
type UpdateMilestoneParams struct {
	Title                   *string
	Description             *string
	Status                  *string
	ScheduledCompletionDate *time.Time
	OrderIndex              *int
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
			PoamItemID:              item.ID,
			Title:                   mp.Title,
			Description:             mp.Description,
			Status:                  mp.Status,
			ScheduledCompletionDate: mp.ScheduledCompletionDate,
			OrderIndex:              orderIdx,
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
		First(&item, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &item, nil
}

// Update applies non-nil fields from params to the POAM item identified by id.
// When status transitions to "completed", completed_at is set automatically.
// last_status_change_at is stamped on every status change.
func (s *PoamService) Update(id uuid.UUID, params UpdatePoamItemParams) (*PoamItem, error) {
	updates := map[string]interface{}{}

	if params.Title != nil {
		updates["title"] = *params.Title
	}
	if params.Description != nil {
		updates["description"] = *params.Description
	}
	if params.Status != nil {
		updates["status"] = *params.Status
		updates["last_status_change_at"] = time.Now().UTC()
		if *params.Status == string(PoamItemStatusCompleted) {
			now := time.Now().UTC()
			updates["completed_at"] = &now
		}
	}
	if params.PrimaryOwnerUserID != nil {
		updates["primary_owner_user_id"] = *params.PrimaryOwnerUserID
	}
	if params.PlannedCompletionDate != nil {
		updates["planned_completion_date"] = params.PlannedCompletionDate
	}
	if params.CompletedAt != nil {
		updates["completed_at"] = params.CompletedAt
	}
	if params.AcceptanceRationale != nil {
		updates["acceptance_rationale"] = *params.AcceptanceRationale
	}

	if len(updates) == 0 {
		return s.GetByID(id)
	}

	if err := s.db.Model(&PoamItem{}).Where("id = ?", id).Updates(updates).Error; err != nil {
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
		PoamItemID:              poamItemID,
		Title:                   params.Title,
		Description:             params.Description,
		Status:                  params.Status,
		ScheduledCompletionDate: params.ScheduledCompletionDate,
		OrderIndex:              params.OrderIndex,
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
	updates := map[string]interface{}{}

	if params.Title != nil {
		updates["title"] = *params.Title
	}
	if params.Description != nil {
		updates["description"] = *params.Description
	}
	if params.Status != nil {
		updates["status"] = *params.Status
		if *params.Status == string(MilestoneStatusCompleted) {
			now := time.Now().UTC()
			updates["completion_date"] = &now
		}
	}
	if params.ScheduledCompletionDate != nil {
		updates["scheduled_completion_date"] = params.ScheduledCompletionDate
	}
	if params.OrderIndex != nil {
		updates["order_index"] = *params.OrderIndex
	}

	if len(updates) == 0 {
		return s.getMilestoneByID(poamItemID, milestoneID)
	}

	result := s.db.Model(&PoamItemMilestone{}).
		Where("poam_item_id = ? AND id = ?", poamItemID, milestoneID).
		Updates(updates)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
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
// silently ignored (ON CONFLICT DO NOTHING).
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
