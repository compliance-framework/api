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

// createControlRequest defines the request payload for method CreateControl
type createControlRequest struct {
	Control struct {
		Title string `json:"title" validate:"required"`
	}
}

func newCreateControlRequest() *createControlRequest {
	return &createControlRequest{}
}

func (r *createControlRequest) bind(ctx echo.Context, c *domain.Control) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}
	c.Title = r.Control.Title
	return nil
}

// createSSPRequest defines the request payload for method CreateSSP
type CreateSSPRequest struct {
	Title string `json:"title" validate:"required"`
}

func (r *CreateSSPRequest) bind(ctx echo.Context, ssp *domain.SystemSecurityPlan) error {
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
// TODO: these are not currently used anywhere - When it is used, remove nolints:
type addAssetRequest struct { //nolint
	AssetId string `json:"assetId" validate:"required"`
	Type    string `json:"type" validate:"required"`
}

func (r *addAssetRequest) bind(ctx echo.Context, p *domain.Plan) error { //nolint
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
	Schedule    string `json:"schedule" validate:"required"`
}

func (r *createTaskRequest) Bind(ctx echo.Context, t *domain.Task) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}
	t.Title = r.Title
	t.Description = r.Description
	t.Type = domain.TaskType(r.Type)
	t.Schedule = r.Schedule
	return nil
}

// setSubjectSelectionRequest defines the request payload for method SetSubjectsForActivity
// TODO: these are not currently used anywhere - When it is used, remove nolints:
type setSubjectSelectionRequest struct { //nolint
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

func (r *setSubjectSelectionRequest) bind(ctx echo.Context, s *domain.SubjectSelection) error { //nolint
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
// TODO: these are not currently used anywhere - When it is used, remove nolints:
type setScheduleRequest struct { //nolint
	Schedule []string `json:"schedule"`
}

func (r *setScheduleRequest) bind(ctx echo.Context) error { //nolint
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
	Title       string `json:"title,omitempty" validate:"required"`
	Description string `json:"description,omitempty"`
	Provider    struct {
		Name          string            `json:"name" validate:"required"`
		Package       string            `json:"package" validate:"required"`
		Version       string            `json:"version" validate:"required"`
		Params        map[string]string `json:"params,omitempty"`
		Configuration map[string]string `json:"configuration,omitempty"`
	} `json:"provider" validate:"required"`
	Subjects struct {
		Title       string            `json:"title" validate:"required"`
		Description string            `json:"description" validate:"required"`
		Query       string            `json:"query,omitempty"`
		Labels      map[string]string `json:"labels,omitempty"`
		Expressions []struct {
			Key      string   `json:"key"`
			Operator string   `json:"operator"`
			Values   []string `json:"values"`
		} `json:"expressions,omitempty"`
		Ids []string `json:"ids,omitempty"`
	}
}

func (r *createActivityRequest) bind(ctx echo.Context, a *domain.Activity) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}

	if err := ctx.Validate(r); err != nil {
		return err
	}

	if r.Subjects.Ids == nil && r.Subjects.Expressions == nil && r.Subjects.Query == "" && r.Subjects.Labels == nil {
		return errors.New("at least one of Query, Labels, Ids or Expressions must be set")
	}

	a.Title = r.Title
	a.Description = r.Description
	a.Provider = domain.Provider{
		Name:          r.Provider.Name,
		Package:       r.Provider.Package,
		Version:       r.Provider.Version,
		Configuration: r.Provider.Configuration,
		Params:        r.Provider.Params,
	}
	a.Subjects = domain.SubjectSelection{
		Title:       r.Subjects.Title,
		Description: r.Subjects.Description,
		Query:       r.Subjects.Query,
		Labels:      r.Subjects.Labels,
		Ids:         r.Subjects.Ids,
		Expressions: []domain.SubjectMatchExpression{},
	}
	for _, expression := range r.Subjects.Expressions {
		a.Subjects.Expressions = append(a.Subjects.Expressions, domain.SubjectMatchExpression{
			Key:      expression.Key,
			Operator: expression.Operator,
			Values:   expression.Values,
		})
	}
	return nil
}

// updateSSPRequest defines the request payload for method UpdateSSP
type UpdateSSPRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

func (r *UpdateSSPRequest) bind(ctx echo.Context, ssp *domain.SystemSecurityPlan) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}

	ssp.Title = r.Title
	return nil
}

type UpdateCatalogRequest struct {
	Uuid       domain.Uuid `json:"uuid"`
	Title      string      `json:"title"`
	// Metadata   domain.Metadata   `json:"metadata"`
	Params     []domain.Parameter `json:"params"`
	Controls   []domain.Control   `json:"controlUuids"`
	Groups     []domain.Uuid      `json:"groupUuids"`
	BackMatter domain.BackMatter  `json:"backMatter"`
}

func (r *UpdateCatalogRequest) bind(ctx echo.Context, catalog *domain.Catalog) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}

	catalog.Uuid = r.Uuid
	catalog.Title = r.Title
	// catalog.Metadata = r.Metadata
	catalog.Params = r.Params
	catalog.Controls = r.Controls
	catalog.Groups = r.Groups
	catalog.BackMatter = r.BackMatter
	return nil
}

type UpdateControlRequest struct {
	// Uuid     domain.Uuid        `json:"uuid"`
	Props    []domain.Property  `json:"props,omitempty"`
	Links    []domain.Link      `json:"links,omitempty"`
	Parts    []domain.Part      `json:"parts,omitempty"`
	Class    string             `json:"class"`
	Title    string             `json:"title"`
	Params   []domain.Parameter `json:"params"`
	Controls []domain.Uuid      `json:"controlUuids"`
}

func (r *UpdateControlRequest) bind(ctx echo.Context, control *domain.Control) error {
	if err := ctx.Bind(r); err != nil {
		return err
	}

	// control.Uuid = r.Uuid
	control.Props = r.Props
	control.Links = r.Links
	control.Parts = r.Parts
	control.Class = r.Class
	control.Title = r.Title
	control.Params = r.Params
	control.Controls = r.Controls

	return nil
}
