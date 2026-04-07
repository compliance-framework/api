package poam

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ListFilters holds all supported filter parameters for listing POAM items.
type ListFilters struct {
	Status         string
	SspID          *uuid.UUID
	RiskID         *uuid.UUID
	DeadlineBefore *time.Time
	OverdueOnly    bool
	OwnerRef       *uuid.UUID
}

// ApplyFilters applies all non-nil filters to the given GORM query and returns it.
func ApplyFilters(query *gorm.DB, filters ListFilters) *gorm.DB {
	q := query.Model(&PoamItem{})

	if filters.Status != "" {
		q = q.Where("ccf_poam_items.status = ?", filters.Status)
	}
	if filters.SspID != nil {
		q = q.Where("ccf_poam_items.ssp_id = ?", *filters.SspID)
	}
	if filters.OwnerRef != nil {
		q = q.Where("ccf_poam_items.primary_owner_user_id = ?", *filters.OwnerRef)
	}
	if filters.DeadlineBefore != nil {
		q = q.Where(
			"ccf_poam_items.planned_completion_date IS NOT NULL AND ccf_poam_items.planned_completion_date < ?",
			*filters.DeadlineBefore,
		)
	}
	if filters.OverdueOnly {
		now := time.Now().UTC()
		q = q.Where(
			// Include 'overdue' in the filter so that items already persisted with
			// that status (a valid PoamItemStatus) are not silently excluded.
			"ccf_poam_items.status IN ('open','in-progress','overdue') AND ccf_poam_items.planned_completion_date IS NOT NULL AND ccf_poam_items.planned_completion_date < ?",
			now,
		)
	}
	if filters.RiskID != nil {
		// Filter through a subquery so the list query still returns one row per
		// POAM item even when multiple matches or future joins are involved.
		riskLinkSubquery := query.
			Session(&gorm.Session{NewDB: true}).
			Table("ccf_poam_item_risk_links").
			Select("poam_item_id").
			Where("risk_id = ?", *filters.RiskID)
		q = q.Where("ccf_poam_items.id IN (?)", riskLinkSubquery)
	}

	return q
}
