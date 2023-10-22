package store

import "github.com/compliance-framework/configuration-service/domain"

type PlanStore interface {
	CreatePlan(catalog *domain.Plan) (interface{}, error)
}
