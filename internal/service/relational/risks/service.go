package risks

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type RiskService struct {
	db *gorm.DB
}

func NewRiskService(db *gorm.DB) *RiskService {
	return &RiskService{db: db}
}

type ListParams struct {
	Filters   ListFilters
	SortField string
	SortOrder string
	Limit     int
	Offset    int
}

type CreateRiskParams struct {
	Risk             Risk
	OwnerAssignments []RiskOwnerAssignment
	ActorUserID      *uuid.UUID
}

type UpdateRiskParams struct {
	Risk                    *Risk
	ReplaceOwnerAssignments bool
	OwnerAssignments        []RiskOwnerAssignment
	PrimaryOwnerUserID      *uuid.UUID
	ActorUserID             *uuid.UUID
	OldStatus               string
	StatusChanged           bool
	RecordReview            bool
	ReviewedAt              *time.Time
	ReviewJustification     *string
}

type AcceptRiskParams struct {
	RiskID         uuid.UUID
	ActorUserID    *uuid.UUID
	Justification  string
	ReviewDeadline time.Time
}

type ReviewRiskParams struct {
	RiskID             uuid.UUID
	ActorUserID        *uuid.UUID
	ReviewedAt         *time.Time
	Decision           RiskReviewDecision
	Notes              *string
	NextReviewDeadline *time.Time
}

type Associations struct {
	EvidenceIDs  []uuid.UUID
	ControlLinks []RiskControlLink
	ComponentIDs []uuid.UUID
	SubjectIDs   []uuid.UUID
}

func (s *RiskService) ResolveUserIDByEmail(email string) (*uuid.UUID, error) {
	var user relational.User
	if err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return user.ID, nil
}

func (s *RiskService) List(params ListParams) ([]Risk, int64, error) {
	query := ApplyRiskFilters(s.db, params.Filters)

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	query = ApplyRiskSorting(query, params.SortField, params.SortOrder).
		Preload("OwnerAssignments").
		Limit(params.Limit).
		Offset(params.Offset)

	var items []Risk
	if err := query.Find(&items).Error; err != nil {
		return nil, 0, err
	}

	return items, total, nil
}

func (s *RiskService) Create(params CreateRiskParams) (*Risk, error) {
	risk := params.Risk
	tx, err := beginTx(s.db)
	if err != nil {
		return nil, err
	}
	defer rollbackTxOnPanic(tx)

	if err := tx.Create(&risk).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := s.replaceOwnerAssignments(tx, *risk.ID, params.OwnerAssignments, risk.PrimaryOwnerUserID); err != nil {
		tx.Rollback()
		return nil, err
	}

	riskSnapshot, err := s.getRiskSnapshot(tx, *risk.ID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := s.logRiskEventWithSnapshot(tx, *risk.ID, RiskEventTypeCreated, params.ActorUserID, datatypes.JSONMap{"status": risk.Status}, riskSnapshot); err != nil {
		tx.Rollback()
		return nil, err
	}
	if risk.Status == string(RiskStatusRiskAccepted) {
		if err := s.logRiskEventWithSnapshot(tx, *risk.ID, RiskEventTypeAccepted, params.ActorUserID, datatypes.JSONMap{"status": risk.Status}, riskSnapshot); err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return s.GetByID(*risk.ID)
}

func (s *RiskService) GetByID(riskID uuid.UUID) (*Risk, error) {
	var risk Risk
	if err := s.db.Preload("OwnerAssignments").First(&risk, "id = ?", riskID).Error; err != nil {
		return nil, err
	}
	return &risk, nil
}

func (s *RiskService) Update(params UpdateRiskParams) (*Risk, error) {
	if params.Risk == nil || params.Risk.ID == nil {
		return nil, fmt.Errorf("risk is required")
	}

	tx, err := beginTx(s.db)
	if err != nil {
		return nil, err
	}
	defer rollbackTxOnPanic(tx)

	if err := tx.Save(params.Risk).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if params.ReplaceOwnerAssignments {
		if err := s.replaceOwnerAssignments(tx, *params.Risk.ID, params.OwnerAssignments, params.PrimaryOwnerUserID); err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	var riskSnapshot datatypes.JSONMap
	if params.StatusChanged || params.RecordReview {
		snapshot, err := s.getRiskSnapshot(tx, *params.Risk.ID)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		riskSnapshot = snapshot
	}

	if params.StatusChanged {
		if err := s.logRiskEventWithSnapshot(tx, *params.Risk.ID, RiskEventTypeStatusChange, params.ActorUserID, datatypes.JSONMap{"from": params.OldStatus, "to": params.Risk.Status}, riskSnapshot); err != nil {
			tx.Rollback()
			return nil, err
		}
		if params.Risk.Status == string(RiskStatusRiskAccepted) {
			if err := s.logRiskEventWithSnapshot(tx, *params.Risk.ID, RiskEventTypeAccepted, params.ActorUserID, datatypes.JSONMap{"status": params.Risk.Status}, riskSnapshot); err != nil {
				tx.Rollback()
				return nil, err
			}
		}
	}

	if params.RecordReview {
		reviewedAt := time.Now().UTC()
		if params.ReviewedAt != nil {
			reviewedAt = params.ReviewedAt.UTC()
		}

		review := RiskReview{
			RiskID:              *params.Risk.ID,
			ReviewedByUserID:    params.ActorUserID,
			ReviewedAt:          reviewedAt,
			Decision:            params.Risk.Status,
			NextReviewDeadline:  params.Risk.ReviewDeadline,
			ReviewJustification: params.ReviewJustification,
			RiskSnapshot:        riskSnapshot,
		}
		if err := tx.Create(&review).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
		if err := s.logRiskEventWithSnapshot(tx, *params.Risk.ID, RiskEventTypeReviewed, params.ActorUserID, datatypes.JSONMap{"decision": params.Risk.Status}, riskSnapshot); err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return s.GetByID(*params.Risk.ID)
}

func (s *RiskService) AcceptRisk(params AcceptRiskParams) (*Risk, error) {
	justification := strings.TrimSpace(params.Justification)
	if justification == "" {
		return nil, newValidationError("justification is required")
	}
	if params.ReviewDeadline.IsZero() {
		return nil, newValidationError("reviewDeadline is required")
	}
	reviewDeadline := params.ReviewDeadline.UTC()
	if !reviewDeadline.After(time.Now().UTC()) {
		return nil, newValidationError("reviewDeadline must be in the future")
	}

	tx, err := beginTx(s.db)
	if err != nil {
		return nil, err
	}
	defer rollbackTxOnPanic(tx)

	var risk Risk
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Preload("OwnerAssignments").First(&risk, "id = ?", params.RiskID).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if risk.Status != string(RiskStatusInvestigating) {
		tx.Rollback()
		return nil, newValidationError("only risks in status investigating can be accepted")
	}

	now := time.Now().UTC()
	oldStatus := risk.Status
	risk.Status = string(RiskStatusRiskAccepted)
	risk.AcceptanceJustification = &justification
	risk.ReviewDeadline = &reviewDeadline
	risk.LastReviewedAt = &now

	if err := tx.Save(&risk).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	riskSnapshot, err := s.getRiskSnapshot(tx, *risk.ID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := s.logRiskEventWithSnapshot(tx, *risk.ID, RiskEventTypeStatusChange, params.ActorUserID, datatypes.JSONMap{
		"from": oldStatus,
		"to":   risk.Status,
	}, riskSnapshot); err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := s.logRiskEventWithSnapshot(tx, *risk.ID, RiskEventTypeAccepted, params.ActorUserID, datatypes.JSONMap{
		"status":        risk.Status,
		"justification": justification,
	}, riskSnapshot); err != nil {
		tx.Rollback()
		return nil, err
	}

	// TODO(BCH-1182): enqueue a risk-accepted notification worker job once its type/worker is available in this branch.

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return s.GetByID(*risk.ID)
}

func (s *RiskService) ReviewRisk(params ReviewRiskParams) (*Risk, error) {
	decision := params.Decision
	if decision == "" {
		return nil, newValidationError("decision is required")
	}
	if !decision.IsValid() {
		return nil, newValidationError(fmt.Sprintf("decision must be one of: %s, %s", RiskReviewDecisionExtend, RiskReviewDecisionReopen))
	}
	nextReviewDeadline := params.NextReviewDeadline
	if decision == RiskReviewDecisionExtend {
		if nextReviewDeadline == nil {
			return nil, newValidationError("nextReviewDeadline is required when decision is extend")
		}
		nextUTC := nextReviewDeadline.UTC()
		if !nextUTC.After(time.Now().UTC()) {
			return nil, newValidationError("nextReviewDeadline must be in the future when decision is extend")
		}
		nextReviewDeadline = &nextUTC
	}
	if decision == RiskReviewDecisionReopen && nextReviewDeadline != nil {
		return nil, newValidationError("nextReviewDeadline must not be provided when decision is reopen")
	}

	tx, err := beginTx(s.db)
	if err != nil {
		return nil, err
	}
	defer rollbackTxOnPanic(tx)

	var risk Risk
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Preload("OwnerAssignments").First(&risk, "id = ?", params.RiskID).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	if risk.Status != string(RiskStatusRiskAccepted) {
		tx.Rollback()
		return nil, newValidationError("only risks in status risk-accepted can be reviewed")
	}

	reviewedAt := time.Now().UTC()
	if params.ReviewedAt != nil {
		reviewedAt = params.ReviewedAt.UTC()
	}
	if decision == RiskReviewDecisionExtend {
		risk.ReviewDeadline = nextReviewDeadline
	}

	if decision == RiskReviewDecisionReopen {
		nextReviewDeadline = nil
		risk.Status = string(RiskStatusInvestigating)
		risk.ReviewDeadline = nil
		risk.AcceptanceJustification = nil
	}

	risk.LastReviewedAt = &reviewedAt
	if err := tx.Save(&risk).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	riskSnapshot, err := s.getRiskSnapshot(tx, *risk.ID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	if decision == RiskReviewDecisionReopen {
		if err := s.logRiskEventWithSnapshot(tx, *risk.ID, RiskEventTypeStatusChange, params.ActorUserID, datatypes.JSONMap{
			"from": string(RiskStatusRiskAccepted),
			"to":   risk.Status,
		}, riskSnapshot); err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	review := RiskReview{
		RiskID:              *risk.ID,
		ReviewedByUserID:    params.ActorUserID,
		ReviewedAt:          reviewedAt,
		Decision:            string(decision),
		NextReviewDeadline:  nextReviewDeadline,
		ReviewJustification: params.Notes,
		RiskSnapshot:        riskSnapshot,
	}
	if err := tx.Create(&review).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := s.logRiskEventWithSnapshot(tx, *risk.ID, RiskEventTypeReviewed, params.ActorUserID, datatypes.JSONMap{
		"decision": string(decision),
	}, riskSnapshot); err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return s.GetByID(*risk.ID)
}

func (s *RiskService) Delete(riskID uuid.UUID) error {
	tx, err := beginTx(s.db)
	if err != nil {
		return err
	}
	defer rollbackTxOnPanic(tx)

	if err := tx.Delete(&RiskEvidenceLink{}, "risk_id = ?", riskID).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Delete(&RiskControlLink{}, "risk_id = ?", riskID).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Delete(&RiskComponentLink{}, "risk_id = ?", riskID).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Delete(&RiskSubjectLink{}, "risk_id = ?", riskID).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Delete(&RiskOwnerAssignment{}, "risk_id = ?", riskID).Error; err != nil {
		tx.Rollback()
		return err
	}

	result := tx.Delete(&Risk{}, "id = ?", riskID)
	if result.Error != nil {
		tx.Rollback()
		return result.Error
	}
	if result.RowsAffected == 0 {
		tx.Rollback()
		return gorm.ErrRecordNotFound
	}

	if err := tx.Commit().Error; err != nil {
		return err
	}

	return nil
}

func (s *RiskService) EnsureRiskExists(riskID uuid.UUID) error {
	var risk Risk
	return s.db.Select("id").First(&risk, "id = ?", riskID).Error
}

func (s *RiskService) EnsureRiskInSSP(riskID, sspID uuid.UUID) error {
	var risk Risk
	return s.db.Select("id").First(&risk, "id = ? AND ssp_id = ?", riskID, sspID).Error
}

func (s *RiskService) EnsureSSPExists(sspID uuid.UUID) error {
	var ssp relational.SystemSecurityPlan
	return s.db.Select("id").First(&ssp, "id = ?", sspID).Error
}

func (s *RiskService) ListEvidenceLinks(riskID uuid.UUID, limit, offset int) ([]uuid.UUID, int64, error) {
	q := s.db.Model(&RiskEvidenceLink{}).Where("risk_id = ?", riskID)

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var links []RiskEvidenceLink
	if err := q.Order("created_at desc").Limit(limit).Offset(offset).Find(&links).Error; err != nil {
		return nil, 0, err
	}

	ids := make([]uuid.UUID, 0, len(links))
	for _, link := range links {
		ids = append(ids, link.EvidenceID)
	}

	return ids, total, nil
}

func (s *RiskService) AddEvidenceLink(riskID, evidenceID uuid.UUID, actorUserID *uuid.UUID) (*RiskEvidenceLink, error) {
	tx, err := beginTx(s.db)
	if err != nil {
		return nil, err
	}
	defer rollbackTxOnPanic(tx)

	var risk Risk
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").First(&risk, "id = ?", riskID).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	evidenceStreamID, err := s.resolveEvidenceStreamID(tx, evidenceID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	link := RiskEvidenceLink{RiskID: riskID, EvidenceID: evidenceStreamID, CreatedByID: actorUserID}
	createResult := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&link)
	if createResult.Error != nil {
		tx.Rollback()
		return nil, createResult.Error
	}

	if createResult.RowsAffected > 0 {
		if err := s.logRiskEvent(tx, riskID, RiskEventTypeEvidenceLink, actorUserID, datatypes.JSONMap{"evidenceId": evidenceStreamID.String()}); err != nil {
			tx.Rollback()
			return nil, err
		}
	} else {
		if err := tx.Where("risk_id = ? AND evidence_id = ?", riskID, evidenceStreamID).First(&link).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return &link, nil
}

func (s *RiskService) DeleteEvidenceLink(riskID, evidenceID uuid.UUID, actorUserID *uuid.UUID) (bool, error) {
	tx, err := beginTx(s.db)
	if err != nil {
		return false, err
	}
	defer rollbackTxOnPanic(tx)

	evidenceStreamID := evidenceID
	resolvedStreamID, resolveErr := s.resolveEvidenceStreamID(tx, evidenceID)
	if resolveErr == nil {
		evidenceStreamID = resolvedStreamID
	} else if !errors.Is(resolveErr, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return false, resolveErr
	}

	deletedEvidenceID := evidenceStreamID
	result := tx.Delete(&RiskEvidenceLink{}, "risk_id = ? AND evidence_id = ?", riskID, evidenceStreamID)
	if result.Error != nil {
		tx.Rollback()
		return false, result.Error
	}

	if result.RowsAffected > 0 && evidenceStreamID != evidenceID {
		// Best-effort cleanup for legacy rows that may still store evidences.id.
		if err := tx.Delete(&RiskEvidenceLink{}, "risk_id = ? AND evidence_id = ?", riskID, evidenceID).Error; err != nil {
			tx.Rollback()
			return false, err
		}
	}

	if result.RowsAffected == 0 && evidenceStreamID != evidenceID {
		legacyDelete := tx.Delete(&RiskEvidenceLink{}, "risk_id = ? AND evidence_id = ?", riskID, evidenceID)
		if legacyDelete.Error != nil {
			tx.Rollback()
			return false, legacyDelete.Error
		}
		result = legacyDelete
		deletedEvidenceID = evidenceID
	}

	if result.RowsAffected == 0 {
		tx.Rollback()
		return false, nil
	}

	if err := s.logRiskEvent(tx, riskID, RiskEventTypeEvidenceUnlink, actorUserID, datatypes.JSONMap{"evidenceId": deletedEvidenceID.String()}); err != nil {
		tx.Rollback()
		return false, err
	}
	if err := tx.Commit().Error; err != nil {
		return false, err
	}
	return true, nil
}

func (s *RiskService) resolveEvidenceStreamID(tx *gorm.DB, evidenceRef uuid.UUID) (uuid.UUID, error) {
	var evidence relational.Evidence
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Select("id", "uuid").
		Where("id = ?", evidenceRef).
		First(&evidence).Error; err == nil {
		if evidence.UUID == uuid.Nil {
			return uuid.Nil, fmt.Errorf("evidence %s is missing stream uuid", evidence.ID)
		}
		return evidence.UUID, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return uuid.Nil, err
	}

	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Select("id", "uuid").
		Where("uuid = ?", evidenceRef).
		Order(`"evidences"."end" DESC`).
		First(&evidence).Error; err != nil {
		return uuid.Nil, err
	}
	if evidence.UUID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("evidence %s is missing stream uuid", evidence.ID)
	}

	return evidence.UUID, nil
}

func (s *RiskService) ListControlLinks(riskID uuid.UUID, limit, offset int) ([]RiskControlLink, int64, error) {
	q := s.db.Model(&RiskControlLink{}).Where("risk_id = ?", riskID)

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var links []RiskControlLink
	if err := q.Order("created_at desc, catalog_id asc, control_id asc").Limit(limit).Offset(offset).Find(&links).Error; err != nil {
		return nil, 0, err
	}

	return links, total, nil
}

func (s *RiskService) AddControlLink(riskID, catalogID uuid.UUID, controlID string, actorUserID *uuid.UUID) (*RiskControlLink, error) {
	tx, err := beginTx(s.db)
	if err != nil {
		return nil, err
	}
	defer rollbackTxOnPanic(tx)

	var risk Risk
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").First(&risk, "id = ?", riskID).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	var control relational.Control
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").First(&control, "catalog_id = ? AND id = ?", catalogID, controlID).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	link := RiskControlLink{RiskID: riskID, CatalogID: catalogID, ControlID: controlID, CreatedByID: actorUserID}
	createResult := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&link)
	if createResult.Error != nil {
		tx.Rollback()
		return nil, createResult.Error
	}

	if createResult.RowsAffected > 0 {
		if err := s.logRiskEvent(tx, riskID, RiskEventTypeControlLink, actorUserID, datatypes.JSONMap{
			"catalogId": catalogID.String(),
			"controlId": controlID,
		}); err != nil {
			tx.Rollback()
			return nil, err
		}
	} else {
		if err := tx.Where("risk_id = ? AND catalog_id = ? AND control_id = ?", riskID, catalogID, controlID).First(&link).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}
	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return &link, nil
}

func (s *RiskService) ListComponentLinks(riskID uuid.UUID, limit, offset int) ([]RiskComponentLink, int64, error) {
	q := s.db.Model(&RiskComponentLink{}).Where("risk_id = ?", riskID)

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var links []RiskComponentLink
	if err := q.Order("created_at desc, component_id asc").Limit(limit).Offset(offset).Find(&links).Error; err != nil {
		return nil, 0, err
	}

	return links, total, nil
}

func (s *RiskService) AddComponentLink(riskID, componentID uuid.UUID, actorUserID *uuid.UUID) (*RiskComponentLink, error) {
	if err := s.EnsureRiskExists(riskID); err != nil {
		return nil, err
	}

	var component relational.SystemComponent
	if err := s.db.Select("id").First(&component, "id = ?", componentID).Error; err != nil {
		return nil, err
	}

	tx, err := beginTx(s.db)
	if err != nil {
		return nil, err
	}
	defer rollbackTxOnPanic(tx)

	link := RiskComponentLink{RiskID: riskID, ComponentID: componentID, CreatedByID: actorUserID}
	createResult := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&link)
	if createResult.Error != nil {
		tx.Rollback()
		return nil, createResult.Error
	}
	if createResult.RowsAffected > 0 {
		if err := s.logRiskEvent(tx, riskID, RiskEventTypeComponentLink, actorUserID, datatypes.JSONMap{
			"componentId": componentID.String(),
		}); err != nil {
			tx.Rollback()
			return nil, err
		}
	} else {
		if err := tx.Where("risk_id = ? AND component_id = ?", riskID, componentID).First(&link).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}
	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return &link, nil
}

func (s *RiskService) ListSubjectLinks(riskID uuid.UUID, limit, offset int) ([]RiskSubjectLink, int64, error) {
	q := s.db.Model(&RiskSubjectLink{}).Where("risk_id = ?", riskID)

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var links []RiskSubjectLink
	if err := q.Order("created_at desc, subject_id asc").Limit(limit).Offset(offset).Find(&links).Error; err != nil {
		return nil, 0, err
	}

	return links, total, nil
}

func (s *RiskService) AddSubjectLink(riskID, subjectID uuid.UUID, actorUserID *uuid.UUID) (*RiskSubjectLink, error) {
	if err := s.EnsureRiskExists(riskID); err != nil {
		return nil, err
	}

	var subject relational.AssessmentSubject
	if err := s.db.Select("id").First(&subject, "id = ?", subjectID).Error; err != nil {
		return nil, err
	}

	tx, err := beginTx(s.db)
	if err != nil {
		return nil, err
	}
	defer rollbackTxOnPanic(tx)

	link := RiskSubjectLink{RiskID: riskID, SubjectID: subjectID, CreatedByID: actorUserID}
	createResult := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&link)
	if createResult.Error != nil {
		tx.Rollback()
		return nil, createResult.Error
	}
	if createResult.RowsAffected > 0 {
		if err := s.logRiskEvent(tx, riskID, RiskEventTypeSubjectLink, actorUserID, datatypes.JSONMap{
			"subjectId": subjectID.String(),
		}); err != nil {
			tx.Rollback()
			return nil, err
		}
	} else {
		if err := tx.Where("risk_id = ? AND subject_id = ?", riskID, subjectID).First(&link).Error; err != nil {
			tx.Rollback()
			return nil, err
		}
	}
	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return &link, nil
}

func (s *RiskService) GetAssociations(riskID uuid.UUID) (Associations, error) {
	associations := Associations{}

	var evidenceLinks []RiskEvidenceLink
	if err := s.db.Where("risk_id = ?", riskID).Find(&evidenceLinks).Error; err != nil {
		return associations, err
	}
	for _, link := range evidenceLinks {
		associations.EvidenceIDs = append(associations.EvidenceIDs, link.EvidenceID)
	}

	if err := s.db.Where("risk_id = ?", riskID).Find(&associations.ControlLinks).Error; err != nil {
		return associations, err
	}

	var componentLinks []RiskComponentLink
	if err := s.db.Where("risk_id = ?", riskID).Find(&componentLinks).Error; err != nil {
		return associations, err
	}
	for _, link := range componentLinks {
		associations.ComponentIDs = append(associations.ComponentIDs, link.ComponentID)
	}

	var subjectLinks []RiskSubjectLink
	if err := s.db.Where("risk_id = ?", riskID).Find(&subjectLinks).Error; err != nil {
		return associations, err
	}
	for _, link := range subjectLinks {
		associations.SubjectIDs = append(associations.SubjectIDs, link.SubjectID)
	}

	return associations, nil
}

func (s *RiskService) GetAssociationsByRiskIDs(riskIDs []uuid.UUID) (map[uuid.UUID]Associations, error) {
	byRiskID := make(map[uuid.UUID]Associations, len(riskIDs))
	if len(riskIDs) == 0 {
		return byRiskID, nil
	}

	for _, riskID := range riskIDs {
		byRiskID[riskID] = Associations{}
	}

	var evidenceLinks []RiskEvidenceLink
	if err := s.db.Where("risk_id IN ?", riskIDs).Find(&evidenceLinks).Error; err != nil {
		return nil, err
	}
	for _, link := range evidenceLinks {
		assoc := byRiskID[link.RiskID]
		assoc.EvidenceIDs = append(assoc.EvidenceIDs, link.EvidenceID)
		byRiskID[link.RiskID] = assoc
	}

	var controlLinks []RiskControlLink
	if err := s.db.Where("risk_id IN ?", riskIDs).Find(&controlLinks).Error; err != nil {
		return nil, err
	}
	for _, link := range controlLinks {
		assoc := byRiskID[link.RiskID]
		assoc.ControlLinks = append(assoc.ControlLinks, link)
		byRiskID[link.RiskID] = assoc
	}

	var componentLinks []RiskComponentLink
	if err := s.db.Where("risk_id IN ?", riskIDs).Find(&componentLinks).Error; err != nil {
		return nil, err
	}
	for _, link := range componentLinks {
		assoc := byRiskID[link.RiskID]
		assoc.ComponentIDs = append(assoc.ComponentIDs, link.ComponentID)
		byRiskID[link.RiskID] = assoc
	}

	var subjectLinks []RiskSubjectLink
	if err := s.db.Where("risk_id IN ?", riskIDs).Find(&subjectLinks).Error; err != nil {
		return nil, err
	}
	for _, link := range subjectLinks {
		assoc := byRiskID[link.RiskID]
		assoc.SubjectIDs = append(assoc.SubjectIDs, link.SubjectID)
		byRiskID[link.RiskID] = assoc
	}

	return byRiskID, nil
}

func (s *RiskService) replaceOwnerAssignments(tx *gorm.DB, riskID uuid.UUID, assignments []RiskOwnerAssignment, primaryOwnerUserID *uuid.UUID) error {
	if err := tx.Delete(&RiskOwnerAssignment{}, "risk_id = ?", riskID).Error; err != nil {
		return err
	}

	rows := append([]RiskOwnerAssignment{}, assignments...)
	if primaryOwnerUserID != nil {
		primaryOwnerRef := primaryOwnerUserID.String()
		normalizedRows := make([]RiskOwnerAssignment, 0, len(rows)+1)
		for _, row := range rows {
			if row.OwnerKind == "user" && row.OwnerRef == primaryOwnerRef {
				continue
			}
			row.IsPrimary = false
			normalizedRows = append(normalizedRows, row)
		}
		normalizedRows = append(normalizedRows, RiskOwnerAssignment{RiskID: riskID, OwnerKind: "user", OwnerRef: primaryOwnerRef, IsPrimary: true})
		rows = normalizedRows
	}

	seen := map[string]struct{}{}
	finalRows := make([]RiskOwnerAssignment, 0, len(rows))
	primarySeen := false
	for _, row := range rows {
		row.RiskID = riskID
		if row.OwnerKind == "" || row.OwnerRef == "" {
			continue
		}
		if row.OwnerKind != "user" && row.OwnerKind != "group" && row.OwnerKind != "role" {
			return fmt.Errorf("invalid ownerKind: %s", row.OwnerKind)
		}
		if row.OwnerKind == "user" {
			if _, err := uuid.Parse(row.OwnerRef); err != nil {
				return fmt.Errorf("ownerRef must be a valid UUID when ownerKind is user")
			}
		}

		key := row.OwnerKind + ":" + row.OwnerRef
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		if row.IsPrimary {
			if primarySeen {
				return fmt.Errorf("only one primary owner assignment is allowed")
			}
			primarySeen = true
		}

		finalRows = append(finalRows, row)
	}

	if len(finalRows) > 0 {
		if err := tx.Create(&finalRows).Error; err != nil {
			return err
		}
	}

	return nil
}

func (s *RiskService) logRiskEvent(tx *gorm.DB, riskID uuid.UUID, eventType RiskEventType, actorUserID *uuid.UUID, payload datatypes.JSONMap) error {
	riskSnapshot, err := s.getRiskSnapshot(tx, riskID)
	if err != nil {
		return err
	}

	return s.logRiskEventWithSnapshot(tx, riskID, eventType, actorUserID, payload, riskSnapshot)
}

func (s *RiskService) logRiskEventWithSnapshot(tx *gorm.DB, riskID uuid.UUID, eventType RiskEventType, actorUserID *uuid.UUID, payload datatypes.JSONMap, riskSnapshot datatypes.JSONMap) error {
	if riskSnapshot == nil {
		var err error
		riskSnapshot, err = s.getRiskSnapshot(tx, riskID)
		if err != nil {
			return err
		}
	}

	event := RiskEvent{
		RiskID:       riskID,
		EventType:    string(eventType),
		ActorUserID:  actorUserID,
		OccurredAt:   time.Now().UTC(),
		Payload:      payload,
		RiskSnapshot: riskSnapshot,
	}
	return tx.Create(&event).Error
}

func (s *RiskService) getRiskSnapshot(tx *gorm.DB, riskID uuid.UUID) (datatypes.JSONMap, error) {
	var risk Risk
	if err := tx.Preload("OwnerAssignments").First(&risk, "id = ?", riskID).Error; err != nil {
		return nil, err
	}

	raw, err := json.Marshal(risk)
	if err != nil {
		return nil, err
	}

	snapshot := datatypes.JSONMap{}
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, err
	}

	return snapshot, nil
}

func beginTx(db *gorm.DB) (*gorm.DB, error) {
	tx := db.Begin()
	if err := tx.Error; err != nil {
		return nil, err
	}
	return tx, nil
}

func rollbackTxOnPanic(tx *gorm.DB) {
	if r := recover(); r != nil {
		tx.Rollback()
		panic(r)
	}
}
