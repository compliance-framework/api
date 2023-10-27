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

type createSSPRequest struct {
	Title string `json:"title" validate:"required"`
}

func (r *createSSPRequest) bind(ctx echo.Context, ssp *domain.SystemSecurityPlan) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}

	ssp.Title = r.Title
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
	AssetId string `json:"assetId" validate:"required"`
	Type    string `json:"type" validate:"required"`
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
	Title       string `json:"title" validate:"required"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type" validate:"required"`
}

func (r *createTaskRequest) Bind(ctx echo.Context, t *domain.Task) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}
	t.Title = r.Title
	t.Description = r.Description
	t.Type = domain.TaskType(r.Type)
	return nil
}

// setSubjectSelectionRequest defines the request payload for method SetSubjectSelection
type setSubjectSelectionRequest struct {
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

func (r *setSubjectSelectionRequest) bind(ctx echo.Context, s *domain.SubjectSelection) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}

	s.Title = r.Title
	s.Description = r.Description
	s.Query = r.Query
	s.Labels = r.Labels

	// Check if Query, Labels, Ids or Expressions are set
	// The service runs this check as well, but we want to return a 422 error before that
	if s.Query == "" && len(s.Labels) == 0 && len(s.Ids) == 0 && len(s.Expressions) == 0 {
		return errors.New("at least one of Query, Labels, Ids or Expressions must be set")
	}

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

// setScheduleRequest defines the request payload for method SetSchedule
type setScheduleRequest struct {
	Schedule []string `json:"schedule"`
}

func (r *setScheduleRequest) bind(ctx echo.Context) error {
	return ctx.Bind(r)
}

// createSubjectRequest defines the request payload for method CreateSubject
type attachMetadataRequest struct {
	Id                  string `json:"id" validate:"required"`
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

// createActivityRequest defines the request payload for method CreateActivity
type createActivityRequest struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Provider    struct {
		Name    string            `json:"name"`
		Package string            `json:"package"`
		Version string            `json:"version"`
		Params  map[string]string `json:"params"`
	} `json:"provider"`
}

func (r *createActivityRequest) bind(ctx echo.Context, a *domain.Activity) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}
	a.Title = r.Title
	a.Description = r.Description
	a.Provider = domain.ProviderConfiguration{
		Name:    r.Provider.Name,
		Package: r.Provider.Package,
		Version: r.Provider.Version,
		Params:  r.Provider.Params,
	}
	return nil
}
