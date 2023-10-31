package handler

import (
	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/service"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"net/http"
)

type PlanHandler struct {
	service *service.PlanService
	sugar   *zap.SugaredLogger
}

func (h *PlanHandler) Register(api *echo.Group) {
	api.POST("/plan", h.CreatePlan)
	api.POST("/plan/:id/tasks", h.CreateTask)
	api.PUT("/plan/:id/activate", h.ActivatePlan)
	api.POST("/plan/:id/tasks/:taskId/activities", h.CreateActivity)
	api.GET("/plan/:id/results", h.Results)
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
// @Tags 			Plan
// @Accept  		json
// @Produce  		json
// @Param   		plan body createPlanRequest true "Plan to add"
// @Success 		201 {object} idResponse
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
	return ctx.JSON(http.StatusCreated, idResponse{
		Id: id,
	})
}

// CreateTask godoc
// @Summary Creates a new task for a specific plan
// @Description This method creates a new task and adds it to a specific plan.
// @Tags Plan
// @Accept  json
// @Produce  json
// @Param id path string true "Plan ID"
// @Param task body createTaskRequest true "Task to add"
// @Success 200 {object} string "Successfully added the task to the plan"
// @Failure 404 {object} api.Error "Plan not found"
// @Failure 422 {object} api.Error "Unprocessable Entity: Error binding the request"
// @Failure 500 {object} api.Error "Internal Server Error"
// @Router /api/plan/{id}/tasks [post]
func (h *PlanHandler) CreateTask(ctx echo.Context) error {
	plan, err := h.service.GetById(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	} else if plan == nil {
		return ctx.JSON(http.StatusNotFound, api.NotFound())
	}

	t := domain.Task{}
	req := &createTaskRequest{}
	if err := req.Bind(ctx, &t); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	taskId, err := h.service.CreateTask(ctx.Param("id"), t)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, idResponse{
		Id: taskId,
	})
}

// CreateActivity godoc
// @Summary Create activity
// @Description This function is used to create an activity for a given task.
// @Tags Plan
// @Accept  json
// @Produce  json
// @Param id path int true "Plan ID"
// @Param taskId path int true "Task ID"
// @Param activity body createActivityRequest true "Activity"
// @Success 200 201 {object} idResponse
// @Failure 404 {object} api.Error
// @Failure 500 {object} api.Error "Internal server error"
// @Router /api/plan/{id}/tasks/{taskId}/activities [post]
func (h *PlanHandler) CreateActivity(ctx echo.Context) error {
	plan, err := h.service.GetById(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	} else if plan == nil {
		return ctx.JSON(http.StatusNotFound, api.NotFound())
	}

	var activity domain.Activity
	req := &createActivityRequest{}
	if err = req.bind(ctx, &activity); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	activityId, err := h.service.CreateActivity(ctx.Param("id"), ctx.Param("taskId"), activity)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, idResponse{
		Id: activityId,
	})
}

// ActivatePlan activates a plan with the given ID.
// @Summary 	Activate a plan
// @Description Activate a plan by its ID. If the plan is already active, no action will be taken.
// @Tags Plan
// @Accept  	json
// @Produce  	json
// @Param   	id path string true "Plan ID"
// @Success 	204
// @Failure 	500 {object} api.Error "Internal server error. The plan could not be activated."
// @Router 		/plan/{id}/activate [put]
func (h *PlanHandler) ActivatePlan(ctx echo.Context) error {
	err := h.service.ActivatePlan(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusOK)
}

// Results Returns the assessment results related with the plan with the given ID.
// @Summary 	Return the assessment results
// @Description Return the assessment results related with the plan with the given ID.
// @Tags Plan
// @Produce  	json
// @Param   	id path string true "Plan ID"
// @Success 	204
// @Failure 	500 {object} api.Error "Internal server error. The plan could not be activated."
// @Router 		/plan/{id}/results [get]
func (h *PlanHandler) Results(ctx echo.Context) error {
	results, err := h.service.GetResults(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, results)
}
