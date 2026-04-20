package risks

import (
	"errors"
	"time"

	poamsvc "github.com/compliance-framework/api/internal/service/relational/poam"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// PromoteToPoamParams carries all inputs required to promote an investigating
// risk to a POAM item.
type PromoteToPoamParams struct {
	// RiskID is the UUID of the risk to promote. The risk must be in
	// investigating status; any other status returns a 422 ValidationError.
	RiskID uuid.UUID
	// ActorUserID is the authenticated user performing the promotion.
	ActorUserID *uuid.UUID
	// Title overrides the risk's title as the POAM item title.
	// If nil, the risk's own title is used.
	Title *string
	// Deadline maps to PoamItem.PlannedCompletionDate.
	Deadline *time.Time
	// ResourceRequired is a free-text planning field describing effort or budget needed.
	ResourceRequired *string
	// PrimaryOwnerUserID optionally overrides the POAM item owner.
	// If nil, the risk's own PrimaryOwnerUserID is inherited automatically.
	PrimaryOwnerUserID *uuid.UUID
	// ExtraMilestones are additional milestones supplied in the request body.
	// They are appended after any milestones copied from the risk's
	// RemediationTemplate, with order_index offset accordingly.
	ExtraMilestones []poamsvc.CreateMilestoneParams
}

// PromoteToPoam promotes an investigating risk to a POAM item and transitions
// the risk status to mitigating-planned. The entire operation — POAM item
// creation, milestone creation, risk link creation, risk status transition, and
// risk event emission — is executed inside a single database transaction so
// that no partial state is persisted on failure.
//
// Re-promotion is allowed only if all previously linked POAM items are in
// completed status. If an active (non-completed) POAM item already exists for
// this risk, a ValidationError is returned.
func (s *RiskService) PromoteToPoam(poamSvc *poamsvc.PoamService, params PromoteToPoamParams) (*poamsvc.PoamItem, error) {
	tx, err := beginTx(s.db)
	if err != nil {
		return nil, err
	}
	defer rollbackTxOnPanic(tx)

	// 1. Load and lock the risk row.
	var risk Risk
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		First(&risk, "id = ?", params.RiskID).Error; err != nil {
		tx.Rollback()
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return nil, err
	}

	// 2. Guard: risk must be in investigating status.
	//    A risk that is accepted (risk-accepted) has been formally accepted as
	//    tolerable — it should not receive a remediation plan. POAM promotion
	//    is only valid while the risk is actively being investigated.
	if risk.Status != string(RiskStatusInvestigating) {
		tx.Rollback()
		return nil, newValidationError("only risks in status investigating can be promoted to a POAM item")
	}

	// 3. Re-promotion guard: reject if an active (non-completed) POAM item
	//    is already linked to this risk.
	type linkRow struct {
		PoamItemID uuid.UUID
		Status     string
	}
	var activeLinks []linkRow
	if err := tx.Raw(`
		SELECT l.poam_item_id, p.status
		FROM ccf_poam_item_risk_links l
		JOIN ccf_poam_items p ON p.id = l.poam_item_id
		WHERE l.risk_id = ? AND p.status != 'completed'
	`, params.RiskID).Scan(&activeLinks).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	if len(activeLinks) > 0 {
		tx.Rollback()
		return nil, newValidationError("an active POAM item is already linked to this risk; complete it before re-promoting")
	}

	// 4. Load the risk's RemediationTemplate (if any) to copy tasks as
	//    initial milestones.
	var templateMilestones []poamsvc.CreateMilestoneParams
	var remediationTemplate RiskRemediationTemplate
	err = tx.
		Where("risk_id = ?", params.RiskID).
		Preload("Tasks", func(db *gorm.DB) *gorm.DB { return db.Order("order_index ASC") }).
		First(&remediationTemplate).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return nil, err
	}
	if err == nil {
		for _, task := range remediationTemplate.Tasks {
			idx := task.OrderIndex
			templateMilestones = append(templateMilestones, poamsvc.CreateMilestoneParams{
				Title:      task.Title,
				OrderIndex: &idx,
			})
		}
	}

	// 5. Merge template milestones with extra milestones from the request.
	//    Extra milestones are appended after template tasks, with order_index
	//    offset by the number of template tasks. A nil OrderIndex means
	//    "auto-assign"; a non-nil pointer (including 0) is used as-is.
	offset := len(templateMilestones)
	for i, extra := range params.ExtraMilestones {
		if extra.OrderIndex == nil {
			idx := offset + i
			extra.OrderIndex = &idx
		}
		templateMilestones = append(templateMilestones, extra)
	}

	// 6. Resolve the POAM item title — default to risk title if not overridden.
	title := risk.Title
	if params.Title != nil && *params.Title != "" {
		title = *params.Title
	}

	// 7. Build the POAM item creation params.
	createParams := poamsvc.CreatePoamItemParams{
		SspID:                 risk.SSPID,
		Title:                 title,
		Description:           risk.Description,
		Status:                string(poamsvc.PoamItemStatusOpen),
		SourceType:            string(poamsvc.PoamItemSourceTypeRiskPromotion),
		PrimaryOwnerUserID:    coalesceUUID(params.PrimaryOwnerUserID, risk.PrimaryOwnerUserID),
		PlannedCompletionDate: params.Deadline,
		ResourceRequired:      params.ResourceRequired,
		RiskIDs:               []uuid.UUID{params.RiskID},
		Milestones:            templateMilestones,
	}

	// 8. Create the POAM item within the shared transaction.
	poamItem, err := poamSvc.CreateWithTx(tx, createParams)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	// 9. Transition the risk status: investigating → mitigating-planned.
	//    This records that a formal remediation plan now exists for the risk.
	oldStatus := risk.Status
	risk.Status = string(RiskStatusMitigatingPlanned)
	if err := tx.Save(&risk).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	// 10. Emit risk events: status_changed + poam_promoted.
	riskSnapshot, err := s.getRiskSnapshot(tx, params.RiskID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := s.logRiskEventWithSnapshot(tx, params.RiskID, RiskEventTypeStatusChange, params.ActorUserID, datatypes.JSONMap{
		"from": oldStatus,
		"to":   risk.Status,
	}, riskSnapshot); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := s.logRiskEventWithSnapshot(tx, params.RiskID, RiskEventTypePoamPromoted, params.ActorUserID, datatypes.JSONMap{
		"poamItemId": poamItem.ID.String(),
	}, riskSnapshot); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := s.RecordRiskScoreSnapshot(tx, params.RiskID, RiskEventTypeStatusChange, params.ActorUserID, time.Now().UTC()); err != nil {
		tx.Rollback()
		return nil, err
	}

	// 11. Commit the transaction.
	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	// 12. Return the fully-loaded POAM item (with milestones and links).
	return poamSvc.GetByID(poamItem.ID)
}

// coalesceUUID returns the first non-nil UUID pointer from the provided
// arguments, mirroring the SQL COALESCE semantics. Used to allow an optional
// caller-supplied override to fall back to a model-derived default.
func coalesceUUID(vals ...*uuid.UUID) *uuid.UUID {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}
