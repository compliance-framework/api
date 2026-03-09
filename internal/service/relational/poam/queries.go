package poam

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ListFilters holds all supported filter parameters for listing POAM items.
type ListFilters struct {
	Status     *string
	SspID      *uuid.UUID
	RiskID     *uuid.UUID
	DueBefore  *time.Time
	OverdueOnly bool
	OwnerRef   *uuid.UUID
}

// ApplyFilters applies all non-nil filters to the given GORM query and returns it.
func ApplyFilters(query *gorm.DB, filters ListFilters) *gorm.DB {
	q := query.Model(&PoamItem{})

	if filters.Status != nil && *filters.Status != "" {
		q = q.Where("ccf_poam_items.status = ?", *filters.Status)
	}
	if filters.SspID != nil {
		q = q.Where("ccf_poam_items.ssp_id = ?", *filters.SspID)
	}
	if filters.OwnerRef != nil {
		q = q.Where("ccf_poam_items.primary_owner_user_id = ?", *filters.OwnerRef)
	}
	if filters.DueBefore != nil {
		q = q.Where(
			"ccf_poam_items.planned_completion_date IS NOT NULL AND ccf_poam_items.planned_completion_date < ?",
			*filters.DueBefore,
		)
	}
	if filters.OverdueOnly {
		now := time.Now().UTC()
		q = q.Where(
			"ccf_poam_items.status IN ('open','in-progress') AND ccf_poam_items.planned_completion_date IS NOT NULL AND ccf_poam_items.planned_completion_date < ?",
			now,
		)
	}
	if filters.RiskID != nil {
		q = q.Joins(
			"JOIN ccf_poam_item_risk_links rl ON rl.poam_item_id = ccf_poam_items.id AND rl.risk_id = ?",
			*filters.RiskID,
		)
	}

	return q
}
