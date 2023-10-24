package handler

import (
	"errors"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/labstack/echo/v4"
)

// createCatalogRequest defines the request payload for method CreateCatalog
type createCatalogRequest struct {
	Catalog struct {
		Title string `json:"title" validate:"required"`
	}
}

func newCreateCatalogRequest() *createCatalogRequest {
	return &createCatalogRequest{}
}

func (r *createCatalogRequest) bind(ctx echo.Context, c *domain.Catalog) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}
	c.Title = r.Catalog.Title
	return nil
}

// createPlanRequest defines the request payload for method Create
// TODO: Using minimal data for now, we might need to expand it later
type createPlanRequest struct {
	Title string `json:"title" validate:"required"`
}

func (r *createPlanRequest) bind(ctx echo.Context, p *domain.Plan) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}
	p.Title = r.Title
	return nil
}

// addTaskRequest defines the request payload for method CreateTask
type addAssetRequest struct {
	AssetUuid string `json:"assetUuid" validate:"required"`
	Type      string `json:"type" validate:"required"`
}

func (r *addAssetRequest) bind(ctx echo.Context, p *domain.Plan) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}

	return nil
}

// createTaskRequest defines the request payload for method CreateTask
type createTaskRequest struct {
	// TODO: We are keeping it minimal for now for the demo
	Title       string `json:"title,omitempty" validate:"required"`
	Description string `json:"description,omitempty" validate:"required"`
}

func (r *createTaskRequest) bind(ctx echo.Context, t *domain.Task) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}
	t.Title = r.Title
	t.Description = r.Description
	return nil
}

// createSubjectSelectionRequest defines the request payload for method CreateSubjectSelection
type createSubjectSelectionRequest struct {
	Title       string            `json:"title,omitempty" validate:"required"`
	Description string            `json:"description,omitempty"`
	Query       string            `json:"query"`
	Labels      map[string]string `json:"labels,omitempty"`
	Expressions []struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values"`
	} `json:"expressions,omitempty"`
	Ids []string `json:"ids,omitempty"`
}

func (r *createSubjectSelectionRequest) bind(ctx echo.Context, s *domain.SubjectSelection) error {
	// Check if Query, Labels, Ids or Expressions are set
	// The service runs this check as well, but we want to return a 422 error before that
	if s.Query == "" && len(s.Labels) == 0 && len(s.Ids) == 0 && len(s.Expressions) == 0 {
		return errors.New("at least one of Query, Labels, Ids or Expressions must be set")
	}

	if err := ctx.Bind(r); err != nil {
		return err
	}
	s.Title = r.Title
	s.Description = r.Description
	s.Query = r.Query
	s.Labels = r.Labels

	for _, expression := range r.Expressions {
		s.Expressions = append(s.Expressions, domain.SubjectMatchExpression{
			Key:      expression.Key,
			Operator: expression.Operator,
			Values:   expression.Values,
		})
	}

	s.Ids = r.Ids
	return nil
}

// createSubjectRequest defines the request payload for method CreateSubject
type attachMetadataRequest struct {
	Uuid                string `json:"uuid" validate:"required"`
	Collection          string `json:"collection" validate:"required"`
	RevisionTitle       string `json:"revisionTitle,omitempty"`
	RevisionDescription string `json:"revisionDescription,omitempty"`
	RevisionRemarks     string `json:"revisionRemarks,omitempty"`
}

func (r *attachMetadataRequest) bind(ctx echo.Context, rev *domain.Revision) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}

	rev.Title = r.RevisionTitle
	rev.Description = r.RevisionDescription
	rev.Remarks = r.RevisionRemarks

	return nil
}
