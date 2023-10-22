package store

import "github.com/compliance-framework/configuration-service/domain"

type PlanStore interface {
	GetById(id string) (*domain.Plan, error)
	Create(plan *domain.Plan) (interface{}, error)
	Update(plan *domain.Plan) error
}
