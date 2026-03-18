package risks

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	maxRiskAssociationFieldLength = 1000
	maxThreatRefsPerRisk          = 50
	maxRemediationTasksPerRisk    = 100
)

type RiskThreatRefInput struct {
	System     string
	ExternalID string
	Title      string
	URL        *string
}

type RiskRemediationTaskInput struct {
	Title      string
	OrderIndex int
}

type RiskRemediationTemplateInput struct {
	Title       string
	Description *string
	Tasks       []RiskRemediationTaskInput
}

func normalizeThreatRefInput(input *RiskThreatRefInput) {
	input.System = strings.TrimSpace(input.System)
	input.ExternalID = strings.TrimSpace(input.ExternalID)
	input.Title = strings.TrimSpace(input.Title)
	if input.URL != nil {
		normalized := strings.TrimSpace(*input.URL)
		input.URL = &normalized
	}
}

func normalizeRemediationInput(input *RiskRemediationTemplateInput) {
	if input == nil {
		return
	}

	input.Title = strings.TrimSpace(input.Title)
	if input.Description != nil {
		normalized := strings.TrimSpace(*input.Description)
		input.Description = &normalized
	}
	for i := range input.Tasks {
		input.Tasks[i].Title = strings.TrimSpace(input.Tasks[i].Title)
	}
}

func validateRiskAssociationText(field, value string) error {
	if utf8.RuneCountInString(value) > maxRiskAssociationFieldLength {
		return newValidationError(fmt.Sprintf("%s must be at most %d characters", field, maxRiskAssociationFieldLength))
	}
	return nil
}

func validateRiskThreatRefs(refs []RiskThreatRefInput) error {
	if len(refs) > maxThreatRefsPerRisk {
		return newValidationError(fmt.Sprintf("threatIds must contain at most %d items", maxThreatRefsPerRisk))
	}

	seen := make(map[string]struct{}, len(refs))
	for i := range refs {
		normalizeThreatRefInput(&refs[i])
		ref := refs[i]
		if ref.System == "" {
			return newValidationError("threatIds.system is required")
		}
		if ref.ExternalID == "" {
			return newValidationError("threatIds.id is required")
		}
		if ref.Title == "" {
			return newValidationError("threatIds.title is required")
		}
		if err := validateRiskAssociationText("threatIds.system", ref.System); err != nil {
			return err
		}
		if err := validateRiskAssociationText("threatIds.id", ref.ExternalID); err != nil {
			return err
		}
		if err := validateRiskAssociationText("threatIds.title", ref.Title); err != nil {
			return err
		}
		if ref.URL != nil {
			if err := validateRiskAssociationText("threatIds.url", *ref.URL); err != nil {
				return err
			}
		}

		key := ref.System + "|" + ref.ExternalID
		if _, exists := seen[key]; exists {
			return newValidationError("threatIds contains duplicate system/id pairs")
		}
		seen[key] = struct{}{}
	}

	return nil
}

func validateRiskRemediationTemplate(input *RiskRemediationTemplateInput) error {
	if input == nil {
		return nil
	}

	normalizeRemediationInput(input)

	if input.Title == "" {
		return newValidationError("remediationTemplate.title is required")
	}
	if err := validateRiskAssociationText("remediationTemplate.title", input.Title); err != nil {
		return err
	}
	if input.Description != nil {
		if err := validateRiskAssociationText("remediationTemplate.description", *input.Description); err != nil {
			return err
		}
	}

	if len(input.Tasks) > maxRemediationTasksPerRisk {
		return newValidationError(fmt.Sprintf("remediationTemplate.tasks must contain at most %d items", maxRemediationTasksPerRisk))
	}

	seenOrder := make(map[int]struct{}, len(input.Tasks))
	for _, task := range input.Tasks {
		if task.Title == "" {
			return newValidationError("remediationTemplate.tasks.title is required")
		}
		if err := validateRiskAssociationText("remediationTemplate.tasks.title", task.Title); err != nil {
			return err
		}
		if task.OrderIndex <= 0 {
			return newValidationError("remediationTemplate.tasks.orderIndex must be greater than 0")
		}
		if _, exists := seenOrder[task.OrderIndex]; exists {
			return newValidationError("remediationTemplate.tasks.orderIndex must be unique")
		}
		seenOrder[task.OrderIndex] = struct{}{}
	}

	return nil
}

func threatRefKey(system, externalID string) string {
	return strings.TrimSpace(system) + "|" + strings.TrimSpace(externalID)
}

func urlsEqual(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func (s *RiskService) replaceThreatRefs(tx *gorm.DB, riskID uuid.UUID, refs []RiskThreatRefInput, actorUserID *uuid.UUID) error {
	if err := validateRiskThreatRefs(refs); err != nil {
		return err
	}

	var existing []RiskThreatRef
	if err := tx.Where("risk_id = ?", riskID).Find(&existing).Error; err != nil {
		return err
	}

	existingByKey := make(map[string]RiskThreatRef, len(existing))
	for _, row := range existing {
		existingByKey[threatRefKey(row.System, row.ExternalID)] = row
	}

	for _, ref := range refs {
		key := threatRefKey(ref.System, ref.ExternalID)
		row, found := existingByKey[key]
		if found {
			delete(existingByKey, key)
			if row.Title == ref.Title && urlsEqual(row.URL, ref.URL) {
				continue
			}
			row.Title = ref.Title
			row.URL = ref.URL
			if err := tx.Save(&row).Error; err != nil {
				return err
			}
			if actorUserID != nil {
				if err := s.logRiskEvent(tx, riskID, RiskEventTypeThreatUpdated, actorUserID, datatypes.JSONMap{
					"threatRefId": row.ID.String(),
					"system":      row.System,
					"id":          row.ExternalID,
				}); err != nil {
					return err
				}
			}
			continue
		}

		newRow := RiskThreatRef{
			RiskID:     riskID,
			System:     ref.System,
			ExternalID: ref.ExternalID,
			Title:      ref.Title,
			URL:        ref.URL,
		}
		if err := tx.Create(&newRow).Error; err != nil {
			return err
		}
		if actorUserID != nil {
			if err := s.logRiskEvent(tx, riskID, RiskEventTypeThreatLinked, actorUserID, datatypes.JSONMap{
				"threatRefId": newRow.ID.String(),
				"system":      newRow.System,
				"id":          newRow.ExternalID,
			}); err != nil {
				return err
			}
		}
	}

	for _, row := range existingByKey {
		if err := tx.Delete(&RiskThreatRef{}, "id = ? AND risk_id = ?", *row.ID, riskID).Error; err != nil {
			return err
		}
		if actorUserID != nil {
			if err := s.logRiskEvent(tx, riskID, RiskEventTypeThreatUnlinked, actorUserID, datatypes.JSONMap{
				"threatRefId": row.ID.String(),
				"system":      row.System,
				"id":          row.ExternalID,
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *RiskService) upsertRemediationTemplate(tx *gorm.DB, riskID uuid.UUID, input *RiskRemediationTemplateInput, actorUserID *uuid.UUID) (*RiskRemediationTemplate, bool, error) {
	if err := validateRiskRemediationTemplate(input); err != nil {
		return nil, false, err
	}
	if input == nil {
		return nil, false, newValidationError("remediationTemplate is required")
	}

	var existing RiskRemediationTemplate
	err := tx.Where("risk_id = ?", riskID).First(&existing).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, err
	}

	created := false
	if errors.Is(err, gorm.ErrRecordNotFound) {
		created = true
		existing = RiskRemediationTemplate{
			RiskID:      riskID,
			Title:       input.Title,
			Description: input.Description,
		}
		if err := tx.Create(&existing).Error; err != nil {
			return nil, false, err
		}
	} else {
		existing.Title = input.Title
		existing.Description = input.Description
		if err := tx.Save(&existing).Error; err != nil {
			return nil, false, err
		}
	}

	if err := tx.Delete(&RiskRemediationTask{}, "risk_remediation_template_id = ?", *existing.ID).Error; err != nil {
		return nil, false, err
	}

	if len(input.Tasks) > 0 {
		tasks := make([]RiskRemediationTask, 0, len(input.Tasks))
		for _, task := range input.Tasks {
			tasks = append(tasks, RiskRemediationTask{
				RiskRemediationTemplateID: *existing.ID,
				Title:                     task.Title,
				OrderIndex:                task.OrderIndex,
			})
		}
		if err := tx.Create(&tasks).Error; err != nil {
			return nil, false, err
		}
	}

	if actorUserID != nil {
		eventType := RiskEventTypeRemediationUpdated
		if created {
			eventType = RiskEventTypeRemediationCreated
		}
		if err := s.logRiskEvent(tx, riskID, eventType, actorUserID, datatypes.JSONMap{
			"remediationTemplateId": existing.ID.String(),
		}); err != nil {
			return nil, false, err
		}
	}

	var row RiskRemediationTemplate
	if err := tx.
		Where("risk_id = ?", riskID).
		Preload("Tasks", func(db *gorm.DB) *gorm.DB { return db.Order("order_index ASC") }).
		First(&row).Error; err != nil {
		return nil, false, err
	}

	return &row, created, nil
}

func (s *RiskService) deleteRemediationTemplate(tx *gorm.DB, riskID uuid.UUID, actorUserID *uuid.UUID) (bool, error) {
	var existing RiskRemediationTemplate
	if err := tx.Where("risk_id = ?", riskID).First(&existing).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}

	if err := tx.Delete(&RiskRemediationTask{}, "risk_remediation_template_id = ?", *existing.ID).Error; err != nil {
		return false, err
	}
	if err := tx.Delete(&RiskRemediationTemplate{}, "id = ?", *existing.ID).Error; err != nil {
		return false, err
	}

	if actorUserID != nil {
		if err := s.logRiskEvent(tx, riskID, RiskEventTypeRemediationDeleted, actorUserID, datatypes.JSONMap{
			"remediationTemplateId": existing.ID.String(),
		}); err != nil {
			return false, err
		}
	}

	return true, nil
}

func (s *RiskService) ListThreatRefs(riskID uuid.UUID, limit, offset int) ([]RiskThreatRef, int64, error) {
	q := s.db.Model(&RiskThreatRef{}).Where("risk_id = ?", riskID)

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var rows []RiskThreatRef
	if err := q.Order("system asc, external_id asc").Limit(limit).Offset(offset).Find(&rows).Error; err != nil {
		return nil, 0, err
	}

	return rows, total, nil
}

func (s *RiskService) GetThreatRef(riskID, threatRefID uuid.UUID) (*RiskThreatRef, error) {
	var row RiskThreatRef
	if err := s.db.Where("risk_id = ? AND id = ?", riskID, threatRefID).First(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func (s *RiskService) AddThreatRef(riskID uuid.UUID, input RiskThreatRefInput, actorUserID *uuid.UUID) (*RiskThreatRef, error) {
	if err := validateRiskThreatRefs([]RiskThreatRefInput{input}); err != nil {
		return nil, err
	}
	normalized := input
	normalizeThreatRefInput(&normalized)

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

	var existing RiskThreatRef
	if err := tx.Where("risk_id = ? AND system = ? AND external_id = ?", riskID, normalized.System, normalized.ExternalID).First(&existing).Error; err == nil {
		if err := tx.Commit().Error; err != nil {
			return nil, err
		}
		return &existing, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return nil, err
	}

	var existingCount int64
	if err := tx.Model(&RiskThreatRef{}).Where("risk_id = ?", riskID).Count(&existingCount).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	if existingCount >= maxThreatRefsPerRisk {
		tx.Rollback()
		return nil, newValidationError(fmt.Sprintf("threatIds must contain at most %d items", maxThreatRefsPerRisk))
	}

	row := RiskThreatRef{
		RiskID:     riskID,
		System:     normalized.System,
		ExternalID: normalized.ExternalID,
		Title:      normalized.Title,
		URL:        normalized.URL,
	}
	if err := tx.Create(&row).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := s.logRiskEvent(tx, riskID, RiskEventTypeThreatLinked, actorUserID, datatypes.JSONMap{
		"threatRefId": row.ID.String(),
		"system":      row.System,
		"id":          row.ExternalID,
	}); err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return &row, nil
}

func (s *RiskService) UpdateThreatRef(riskID, threatRefID uuid.UUID, input RiskThreatRefInput, actorUserID *uuid.UUID) (*RiskThreatRef, error) {
	if err := validateRiskThreatRefs([]RiskThreatRefInput{input}); err != nil {
		return nil, err
	}
	normalized := input
	normalizeThreatRefInput(&normalized)

	tx, err := beginTx(s.db)
	if err != nil {
		return nil, err
	}
	defer rollbackTxOnPanic(tx)

	var row RiskThreatRef
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("risk_id = ? AND id = ?", riskID, threatRefID).First(&row).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	row.System = normalized.System
	row.ExternalID = normalized.ExternalID
	row.Title = normalized.Title
	row.URL = normalized.URL

	var duplicate RiskThreatRef
	if err := tx.
		Select("id").
		Where("risk_id = ? AND system = ? AND external_id = ? AND id <> ?", riskID, row.System, row.ExternalID, threatRefID).
		First(&duplicate).Error; err == nil {
		tx.Rollback()
		return nil, newValidationError("threatIds contains duplicate system/id pairs")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return nil, err
	}

	if err := tx.Save(&row).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := s.logRiskEvent(tx, riskID, RiskEventTypeThreatUpdated, actorUserID, datatypes.JSONMap{
		"threatRefId": row.ID.String(),
		"system":      row.System,
		"id":          row.ExternalID,
	}); err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return &row, nil
}

func (s *RiskService) DeleteThreatRef(riskID, threatRefID uuid.UUID, actorUserID *uuid.UUID) (bool, error) {
	tx, err := beginTx(s.db)
	if err != nil {
		return false, err
	}
	defer rollbackTxOnPanic(tx)

	var row RiskThreatRef
	if err := tx.Where("risk_id = ? AND id = ?", riskID, threatRefID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			tx.Rollback()
			return false, nil
		}
		tx.Rollback()
		return false, err
	}

	if err := tx.Delete(&RiskThreatRef{}, "risk_id = ? AND id = ?", riskID, threatRefID).Error; err != nil {
		tx.Rollback()
		return false, err
	}

	if err := s.logRiskEvent(tx, riskID, RiskEventTypeThreatUnlinked, actorUserID, datatypes.JSONMap{
		"threatRefId": threatRefID.String(),
		"system":      row.System,
		"id":          row.ExternalID,
	}); err != nil {
		tx.Rollback()
		return false, err
	}

	if err := tx.Commit().Error; err != nil {
		return false, err
	}

	return true, nil
}

func (s *RiskService) GetRemediationTemplate(riskID uuid.UUID) (*RiskRemediationTemplate, error) {
	var row RiskRemediationTemplate
	if err := s.db.
		Where("risk_id = ?", riskID).
		Preload("Tasks", func(db *gorm.DB) *gorm.DB { return db.Order("order_index ASC") }).
		First(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

func (s *RiskService) CreateRemediationTemplate(riskID uuid.UUID, input *RiskRemediationTemplateInput, actorUserID *uuid.UUID) (*RiskRemediationTemplate, error) {
	if err := validateRiskRemediationTemplate(input); err != nil {
		return nil, err
	}
	if input == nil {
		return nil, newValidationError("remediationTemplate is required")
	}

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

	var existing RiskRemediationTemplate
	if err := tx.Where("risk_id = ?", riskID).First(&existing).Error; err == nil {
		tx.Rollback()
		return nil, ErrRemediationTemplateAlreadyExists
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		tx.Rollback()
		return nil, err
	}

	row, _, err := s.upsertRemediationTemplate(tx, riskID, input, actorUserID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return row, nil
}

func (s *RiskService) UpsertRemediationTemplate(riskID uuid.UUID, input *RiskRemediationTemplateInput, actorUserID *uuid.UUID) (*RiskRemediationTemplate, error) {
	if err := validateRiskRemediationTemplate(input); err != nil {
		return nil, err
	}
	if input == nil {
		return nil, newValidationError("remediationTemplate is required")
	}

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

	row, _, err := s.upsertRemediationTemplate(tx, riskID, input, actorUserID)
	if err != nil {
		tx.Rollback()
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return row, nil
}

func (s *RiskService) DeleteRemediationTemplate(riskID uuid.UUID, actorUserID *uuid.UUID) (bool, error) {
	tx, err := beginTx(s.db)
	if err != nil {
		return false, err
	}
	defer rollbackTxOnPanic(tx)

	deleted, err := s.deleteRemediationTemplate(tx, riskID, actorUserID)
	if err != nil {
		tx.Rollback()
		return false, err
	}
	if !deleted {
		tx.Rollback()
		return false, nil
	}

	if err := tx.Commit().Error; err != nil {
		return false, err
	}
	return true, nil
}
