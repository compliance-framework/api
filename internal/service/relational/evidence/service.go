package evidence

import (
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type StatusCount struct {
	Count  int64  `json:"count"`
	Status string `json:"status"`
}

type EvidenceService struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewEvidenceService(db *gorm.DB, cfg *config.Config) *EvidenceService {
	return &EvidenceService{db: db, cfg: cfg}
}

type CreateEvidenceParams struct {
	Evidence       relational.Evidence
	Components     []relational.SystemComponent
	InventoryItems []relational.InventoryItem
	Activities     []relational.Activity
	Subjects       []relational.AssessmentSubject
	Labels         []relational.Labels
}

func (s *EvidenceService) Create(params CreateEvidenceParams) (*relational.Evidence, error) {
	for i := range params.Components {
		if err := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&params.Components[i]).Error; err != nil {
			return nil, err
		}
	}

	for i := range params.InventoryItems {
		if err := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&params.InventoryItems[i]).Error; err != nil {
			return nil, err
		}
	}

	for i := range params.Activities {
		if err := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&params.Activities[i]).Error; err != nil {
			return nil, err
		}
	}

	for i := range params.Subjects {
		if err := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&params.Subjects[i]).Error; err != nil {
			return nil, err
		}
	}

	for i := range params.Labels {
		if err := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&params.Labels[i]).Error; err != nil {
			return nil, err
		}
	}

	if params.Evidence.Expires == nil && s.cfg != nil {
		baseDate := params.Evidence.End
		if baseDate.IsZero() {
			baseDate = time.Now().UTC()
		}
		expiryDate := baseDate.AddDate(0, s.cfg.EvidenceDefaultExpiryMonths, 0)
		params.Evidence.Expires = &expiryDate
	}

	if err := s.db.Create(&params.Evidence).Error; err != nil {
		return nil, err
	}

	if len(params.Activities) > 0 {
		if err := s.db.Model(&params.Evidence).Association("Activities").Append(params.Activities); err != nil {
			return nil, err
		}
	}

	if len(params.InventoryItems) > 0 {
		if err := s.db.Model(&params.Evidence).Association("InventoryItems").Append(params.InventoryItems); err != nil {
			return nil, err
		}
	}

	if len(params.Components) > 0 {
		if err := s.db.Model(&params.Evidence).Association("Components").Append(params.Components); err != nil {
			return nil, err
		}
	}

	if len(params.Subjects) > 0 {
		if err := s.db.Model(&params.Evidence).Association("Subjects").Append(params.Subjects); err != nil {
			return nil, err
		}
	}

	if len(params.Labels) > 0 {
		if err := s.db.Model(&params.Evidence).Association("Labels").Append(params.Labels); err != nil {
			return nil, err
		}
	}

	return &params.Evidence, nil
}

func (s *EvidenceService) GetByID(id uuid.UUID) (*relational.Evidence, error) {
	var evidence relational.Evidence
	if err := s.db.
		Preload("Labels").
		Preload("BackMatter").
		Preload("BackMatter.Resources").
		Preload("Activities").
		Preload("Activities.Steps").
		Preload("InventoryItems").
		Preload("Components").
		Preload("Subjects").
		First(&evidence, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &evidence, nil
}

func (s *EvidenceService) GetHistory(streamUUID uuid.UUID) ([]relational.Evidence, error) {
	var evidences []relational.Evidence
	if err := s.db.
		Preload("Labels").
		Preload("Activities").
		Preload("Activities.Steps").
		Preload("InventoryItems").
		Preload("Components").
		Preload("Subjects").
		Order("evidences.end DESC").
		Find(&evidences, "uuid = ?", streamUUID).Error; err != nil {
		return nil, err
	}
	return evidences, nil
}

func (s *EvidenceService) Search(filter labelfilter.Filter) ([]relational.Evidence, error) {
	var results []relational.Evidence
	query, err := relational.GetEvidenceSearchByFilterQuery(relational.GetLatestEvidenceStreamsQuery(s.db), s.db, filter)
	if err != nil {
		return nil, err
	}
	if err := query.Preload("Labels").Find(&results).Error; err != nil {
		return nil, err
	}
	return results, nil
}

func (s *EvidenceService) GetLatestForFilters(filters ...labelfilter.Filter) ([]relational.Evidence, error) {
	latestQuery := s.db.Session(&gorm.Session{})
	latestQuery = relational.GetLatestEvidenceStreamsQuery(latestQuery)
	q, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, s.db, filters...)
	if err != nil {
		return nil, err
	}
	var evidences []relational.Evidence
	if err := q.Model(&relational.Evidence{}).Scan(&evidences).Error; err != nil {
		return nil, err
	}
	return evidences, nil
}

func (s *EvidenceService) GetStatusCountsAtPoint(filter labelfilter.Filter, endBefore *time.Time) ([]StatusCount, error) {
	latestQuery := s.db.Session(&gorm.Session{})
	latestQuery = relational.GetLatestEvidenceStreamsQuery(latestQuery)
	if endBefore != nil {
		latestQuery = latestQuery.Where("evidences.end < ?", endBefore.UTC())
	}
	q, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, s.db, filter)
	if err != nil {
		return nil, err
	}
	var rows []StatusCount
	if err := q.Model(&relational.Evidence{}).
		Select("count(*) as count, status->>'state' as status").
		Group("status->>'state'").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *EvidenceService) GetStatusCountsByUUIDAtPoint(streamUUID uuid.UUID, endBefore *time.Time) ([]StatusCount, error) {
	latestQuery := s.db.Session(&gorm.Session{})
	latestQuery = relational.GetLatestEvidenceStreamsQuery(latestQuery)
	latestQuery = latestQuery.Where("uuid = ?", streamUUID.String())
	if endBefore != nil {
		latestQuery = latestQuery.Where("evidences.end < ?", endBefore.UTC())
	}
	q, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, s.db, labelfilter.Filter{})
	if err != nil {
		return nil, err
	}
	var rows []StatusCount
	if err := q.Model(&relational.Evidence{}).
		Select("count(*) as count, status->>'state' as status").
		Group("status->>'state'").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *EvidenceService) GetStatusCountsByFilters(filters ...labelfilter.Filter) ([]StatusCount, error) {
	latestQuery := s.db.Session(&gorm.Session{})
	latestQuery = relational.GetLatestEvidenceStreamsQuery(latestQuery)
	q, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, s.db, filters...)
	if err != nil {
		return nil, err
	}
	var rows []StatusCount
	if err := q.Model(&relational.Evidence{}).
		Select("count(*) as count, status->>'state' as status").
		Group("status->>'state'").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *EvidenceService) GetFilterByID(id uuid.UUID) (*relational.Filter, error) {
	var filter relational.Filter
	if err := s.db.First(&filter, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &filter, nil
}

func (s *EvidenceService) GetControlByID(id string) (*relational.Control, error) {
	var control relational.Control
	if err := s.db.Preload("Filters").First(&control, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &control, nil
}
