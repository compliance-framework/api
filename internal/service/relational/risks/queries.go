package risks

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ListFilters struct {
	Status               *string
	Likelihood           *string
	Impact               *string
	SSPID                *uuid.UUID
	ControlID            *string
	EvidenceID           *uuid.UUID
	OwnerKind            *string
	OwnerRef             *string
	ReviewDeadlineBefore *time.Time
}

func ApplyRiskFilters(query *gorm.DB, filters ListFilters) *gorm.DB {
	q := query.Model(&Risk{})

	if filters.Status != nil && *filters.Status != "" {
		q = q.Where("risk_register_risks.status = ?", *filters.Status)
	}
	if filters.Likelihood != nil && *filters.Likelihood != "" {
		q = q.Where("risk_register_risks.likelihood = ?", *filters.Likelihood)
	}
	if filters.Impact != nil && *filters.Impact != "" {
		q = q.Where("risk_register_risks.impact = ?", *filters.Impact)
	}
	if filters.SSPID != nil {
		q = q.Where("risk_register_risks.ssp_id = ?", *filters.SSPID)
	}
	if filters.ReviewDeadlineBefore != nil {
		q = q.Where("risk_register_risks.review_deadline IS NOT NULL AND risk_register_risks.review_deadline < ?", *filters.ReviewDeadlineBefore)
	}
	if filters.ControlID != nil && *filters.ControlID != "" {
		q = q.Where("EXISTS (SELECT 1 FROM risk_control_links rcl WHERE rcl.risk_id = risk_register_risks.id AND rcl.control_id = ?)", *filters.ControlID)
	}
	if filters.EvidenceID != nil {
		q = q.Where("EXISTS (SELECT 1 FROM risk_evidence_links rel WHERE rel.risk_id = risk_register_risks.id AND rel.evidence_id = ?)", *filters.EvidenceID)
	}
	if (filters.OwnerKind != nil && *filters.OwnerKind != "") || (filters.OwnerRef != nil && *filters.OwnerRef != "") {
		if filters.OwnerKind != nil && *filters.OwnerKind != "" {
			if filters.OwnerRef != nil && *filters.OwnerRef != "" {
				q = q.Where("EXISTS (SELECT 1 FROM risk_owner_assignments roa WHERE roa.risk_id = risk_register_risks.id AND roa.owner_kind = ? AND roa.owner_ref = ?)", *filters.OwnerKind, *filters.OwnerRef)
			} else {
				q = q.Where("EXISTS (SELECT 1 FROM risk_owner_assignments roa WHERE roa.risk_id = risk_register_risks.id AND roa.owner_kind = ?)", *filters.OwnerKind)
			}
		}
		if filters.OwnerKind == nil || *filters.OwnerKind == "" {
			if filters.OwnerRef != nil && *filters.OwnerRef != "" {
				q = q.Where("EXISTS (SELECT 1 FROM risk_owner_assignments roa WHERE roa.risk_id = risk_register_risks.id AND roa.owner_ref = ?)", *filters.OwnerRef)
			}
		}
	}

	return q
}

func ApplyRiskSorting(query *gorm.DB, sortField, sortOrder string) *gorm.DB {
	column := mapSortField(sortField)
	order := strings.ToUpper(sortOrder)
	if order != "ASC" && order != "DESC" {
		order = "DESC"
	}
	return query.Order(column + " " + order)
}

func mapSortField(sortField string) string {
	switch sortField {
	case "createdAt":
		return "risk_register_risks.created_at"
	case "updatedAt":
		return "risk_register_risks.updated_at"
	case "status":
		return "risk_register_risks.status"
	case "reviewDeadline":
		return "risk_register_risks.review_deadline"
	case "firstSeenAt":
		return "risk_register_risks.first_seen_at"
	case "lastSeenAt":
		return "risk_register_risks.last_seen_at"
	default:
		return "risk_register_risks.created_at"
	}
}
