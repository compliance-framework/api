package handler

import (
	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/service"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"net/http"
)

// TODO: Publishing the events from the handler is not a good idea. We should
//  publish the events from the domain services, following the business logic.

type PlanHandler struct {
	service *service.PlanService
	sugar   *zap.SugaredLogger
}

func (h *PlanHandler) Register(api *echo.Group) {
	// TODO: Most of the methods require other ops like delete and update

	api.POST("/plan", h.CreatePlan)
	api.POST("/plan/:id/assets", h.AddAsset)
	api.POST("/plan/:id/tasks", h.CreateTask)
	api.POST("/plan/:id/task/:taskId/subjects", h.CreateSubjectSelection)
}

func NewPlanHandler(l *zap.SugaredLogger, s *service.PlanService) *PlanHandler {
	return &PlanHandler{
		sugar:   l,
		service: s,
	}
}

// CreatePlan godoc
// @Summary 		Create a plan
// @Description 	Creates a new plan in the system
// @Accept  		json
// @Produce  		json
// @Param   		plan body createPlanRequest true "Plan to add"
// @Success 		201 {object} planIdResponse
// @Failure 		401 {object} api.Error
// @Failure 		422 {object} api.Error
// @Failure 		500 {object} api.Error
// @Router 			/api/plan [post]
func (h *PlanHandler) CreatePlan(ctx echo.Context) error {
	// Initialize a new plan object
	p := domain.NewPlan()

	// Initialize a new createPlanRequest object
	req := createPlanRequest{}

	// Bind the incoming request to the plan object
	// If there's an error, return a 422 status code with the error message
	if err := req.bind(ctx, p); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	// Attempt to create the plan in the service
	// If there's an error, return a 500 status code with the error message
	id, err := h.service.Create(p)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// If everything went well, return a 201 status code with the ID of the created plan
	return ctx.JSON(http.StatusCreated, planIdResponse{
		Id: id,
	})
}

// AddAsset godoc
// @Summary Add asset to a plan
// @Description This method adds an existing asset to a specific plan by its ID.
// @Tags Plan
// @Accept  json
// @Produce  json
// @Param id path string true "Plan ID"
// @Param asset body addAssetRequest true "Asset to add"
// @Success 200 {object} api.Response "Successfully added the asset to the plan"
// @Failure 404 {object} api.Response "Plan not found"
// @Failure 422 {object} api.Response "Unprocessable Entity: Error binding the request"
// @Failure 500 {object} api.Response "Internal Server Error"
// @Router /plans/{id}/assets [post]
func (h *PlanHandler) AddAsset(ctx echo.Context) error {
	plan, err := h.service.GetById(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	} else if plan == nil {
		return ctx.JSON(http.StatusNotFound, api.NotFound())
	}

	req := &addAssetRequest{}
	if err := ctx.Bind(req); err != nil {
		return err
	}

	plan.AddAsset(domain.Uuid(req.AssetUuid), req.Type)
	err = h.service.Update(plan)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, nil)
}

// CreateTask godoc
// @Summary Creates a new task for a specific plan
// @Description This method creates a new task and adds it to a specific plan.
// @Tags Plan
// @Accept  json
// @Produce  json
// @Param id path string true "Plan ID"
// @Param task body createTaskRequest true "Task to add"
// @Success 200 {object} api.Response "Successfully added the task to the plan"
// @Failure 404 {object} api.Response "Plan not found"
// @Failure 422 {object} api.Response "Unprocessable Entity: Error binding the request"
// @Failure 500 {object} api.Response "Internal Server Error"
// @Router /plans/{id}/tasks [post]
func (h *PlanHandler) CreateTask(ctx echo.Context) error {
	plan, err := h.service.GetById(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	} else if plan == nil {
		return ctx.JSON(http.StatusNotFound, api.NotFound())
	}

	req := &createTaskRequest{}
	if err := ctx.Bind(req); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	task := domain.Task{
		Uuid:        domain.NewUuid(),
		Title:       req.Title,
		Description: req.Description,
	}
	err = plan.AddTask(task)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	err = h.service.Update(plan)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, nil)
}

// CreateSubjectSelection godoc
// @Summary Create subject selection
// @Description This function is used to create a subject selection for a given plan.
// @Tags Plan
// @Accept  json
// @Produce  json
// @Param id path int true "Plan ID"
// @Param taskId path int true "Task ID"
// @Param selection body createSubjectSelectionRequest true "Subject Selection"
// @Success 200 {object} api.SuccessResponse "Successfully created subject selection"
// @Failure 404 {object} api.ErrorResponse "Plan not found"
// @Failure 500 {object} api.ErrorResponse "Internal server error"
// @Router /plans/{id}/tasks/{taskId}/subjects [post]
func (h *PlanHandler) CreateSubjectSelection(ctx echo.Context) error {
	plan, err := h.service.GetById(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	} else if plan == nil {
		return ctx.JSON(http.StatusNotFound, api.NotFound())
	}

	var selection domain.SubjectSelection
	req := &createSubjectSelectionRequest{}
	if err = req.bind(ctx, &selection); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	err = plan.AddSubjectsToTask(domain.Uuid(ctx.Param("taskId")).String(), selection)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	err = h.service.Update(plan)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, nil)
}
