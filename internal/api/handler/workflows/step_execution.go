package workflows

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/authcontext"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, "permission denied") ||
		strings.Contains(errMsg, "not assigned to role") ||
		strings.Contains(errMsg, "no assignment found")
}

type StepExecutionHandler struct {
	*BaseHandler
	db                *gorm.DB
	service           *workflows.StepExecutionService
	transitionService *workflow.StepTransitionService
	assignmentService *workflow.AssignmentService
}

func NewStepExecutionHandler(
	sugar *zap.SugaredLogger,
	db *gorm.DB,
	transitionService *workflow.StepTransitionService,
	assignmentService *workflow.AssignmentService,
) *StepExecutionHandler {
	return &StepExecutionHandler{
		BaseHandler:       NewBaseHandler(sugar),
		db:                db,
		service:           transitionService.GetStepExecutionService(), // Use the same service as transition service
		transitionService: transitionService,
		assignmentService: assignmentService,
	}
}

func (h *StepExecutionHandler) Register(api *echo.Group, guard middleware.ResourceGuard) {
	api.GET("", h.List, guard.Read())
	api.GET("/my", h.ListMy, guard.Read())
	api.GET("/:id", h.Get, guard.Read())
	api.PUT("/:id/transition", h.TransitionStep, guard.Update())
	api.GET("/:id/evidence-requirements", h.GetEvidenceRequirements, guard.Read())
	api.GET("/:id/can-transition", h.CanTransition, guard.Read())
	api.PUT("/:id/fail", h.Fail, guard.Update())
	api.PUT("/:id/reassign", h.Reassign, guard.Update())
}

type TransitionStepRequest struct {
	Status   string                        `json:"status" validate:"required,oneof=in_progress completed"`
	Evidence []workflow.EvidenceSubmission `json:"evidence,omitempty"`
	Notes    string                        `json:"notes,omitempty"`
	UserID   string                        `json:"user-id"`
	UserType string                        `json:"user-type" validate:"omitempty,oneof=user group email"`
}

type FailStepRequest struct {
	Reason string `json:"reason" validate:"required"`
}

type ReassignStepRequest struct {
	AssignedToType string `json:"assigned-to-type" validate:"required,oneof=user group email"`
	AssignedToID   string `json:"assigned-to-id" validate:"required"`
	Reason         string `json:"reason,omitempty"`
}

type StepExecutionResponse struct {
	Data *workflows.StepExecution `json:"data"`
}

type StepExecutionListResponse struct {
	Data []workflows.StepExecution `json:"data"`
}

type MyAssignmentsResponse struct {
	Data    []workflows.StepExecution `json:"data"`
	Total   int64                     `json:"total"`
	Limit   int                       `json:"limit"`
	Offset  int                       `json:"offset"`
	HasMore bool                      `json:"has-more"`
}

// ListMy godoc
//
//	@Summary		List my step assignments
//	@Description	List all step executions assigned to the current user with optional filters and pagination
//	@Tags			Step Executions
//	@Produce		json
//	@Param			status					query		string	false	"Filter by status (pending, in_progress, blocked)"
//	@Param			due_before				query		string	false	"Filter by due date before (RFC3339 format)"
//	@Param			due_after				query		string	false	"Filter by due date after (RFC3339 format)"
//	@Param			workflow_definition_id	query		string	false	"Filter by workflow definition ID"
//	@Param			limit					query		int		false	"Limit (default 20, max 100)"
//	@Param			offset					query		int		false	"Offset (default 0)"
//	@Success		200						{object}	MyAssignmentsResponse
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions/my [get]
func (h *StepExecutionHandler) ListMy(ctx echo.Context) error {
	// Get user from JWT claims
	userClaims, ok := ctx.Get("user").(*authn.UserClaims)
	if !ok || userClaims == nil {
		return ctx.JSON(http.StatusUnauthorized, api.NewError(echo.NewHTTPError(http.StatusUnauthorized, "missing authentication claims")))
	}

	// Look up user by email to get their ID
	email := userClaims.Subject
	var user relational.User
	if err := h.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(echo.NewHTTPError(http.StatusNotFound, "user not found")))
		}
		h.sugar.Errorw("Failed to get user by email", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Build filter
	filter := workflows.MyAssignmentsFilter{
		Status: ctx.QueryParam("status"),
	}

	// Parse due_before
	if dueBefore := ctx.QueryParam("due_before"); dueBefore != "" {
		t, err := time.Parse(time.RFC3339, dueBefore)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(echo.NewHTTPError(http.StatusBadRequest, "invalid due_before format, expected RFC3339")))
		}
		filter.DueBefore = &t
	}

	// Parse due_after
	if dueAfter := ctx.QueryParam("due_after"); dueAfter != "" {
		t, err := time.Parse(time.RFC3339, dueAfter)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(echo.NewHTTPError(http.StatusBadRequest, "invalid due_after format, expected RFC3339")))
		}
		filter.DueAfter = &t
	}

	// Parse workflow_definition_id
	if wfDefID := ctx.QueryParam("workflow_definition_id"); wfDefID != "" {
		id, err := uuid.Parse(wfDefID)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(echo.NewHTTPError(http.StatusBadRequest, "invalid workflow_definition_id format")))
		}
		filter.WorkflowDefinitionID = &id
	}

	// Parse pagination
	limit := 20
	offset := 0

	if limitStr := ctx.QueryParam("limit"); limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err != nil || l < 1 {
			return ctx.JSON(http.StatusBadRequest, api.NewError(echo.NewHTTPError(http.StatusBadRequest, "invalid limit parameter")))
		}
		if l > 100 {
			l = 100
		}
		limit = l
	}

	if offsetStr := ctx.QueryParam("offset"); offsetStr != "" {
		o, err := strconv.Atoi(offsetStr)
		if err != nil || o < 0 {
			return ctx.JSON(http.StatusBadRequest, api.NewError(echo.NewHTTPError(http.StatusBadRequest, "invalid offset parameter")))
		}
		offset = o
	}

	// Query by user ID (for type "user") and email (for type "email")
	stepExecutions, total, err := h.service.GetMyAssignments(user.ID.String(), email, filter, limit, offset)
	if err != nil {
		return h.HandleServiceError(ctx, err, "list", "my assignments")
	}

	hasMore := int64(offset+len(stepExecutions)) < total

	return h.RespondOK(ctx, MyAssignmentsResponse{
		Data:    stepExecutions,
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		HasMore: hasMore,
	})
}

// List godoc
//
//	@Summary		List step executions
//	@Description	List all step executions for a workflow execution
//	@Tags			Step Executions
//	@Produce		json
//	@Param			workflow_execution_id	query		string	true	"Workflow Execution ID"
//	@Success		200						{object}	StepExecutionListResponse
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions [get]
func (h *StepExecutionHandler) List(ctx echo.Context) error {
	workflowExecIDStr := ctx.QueryParam("workflow_execution_id")
	if workflowExecIDStr == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(echo.NewHTTPError(http.StatusBadRequest, "workflow_execution_id is required")))
	}

	workflowExecID, err := uuid.Parse(workflowExecIDStr)
	if err != nil {
		return h.HandleServiceError(ctx, err, "parse", "workflow execution ID")
	}

	stepExecutions, err := h.service.GetByWorkflowExecutionID(&workflowExecID)
	if err != nil {
		return h.HandleServiceError(ctx, err, "list", "step executions")
	}

	return h.RespondOK(ctx, StepExecutionListResponse{Data: stepExecutions})
}

// Get godoc
//
//	@Summary		Get step execution
//	@Description	Get step execution by ID
//	@Tags			Step Executions
//	@Produce		json
//	@Param			id	path		string	true	"Step Execution ID"
//	@Success		200	{object}	StepExecutionResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions/{id} [get]
func (h *StepExecutionHandler) Get(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "step execution")
	if err != nil {
		return HandleError(err)
	}

	stepExecution, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "step execution")
	}

	return h.RespondOK(ctx, StepExecutionResponse{Data: stepExecution})
}

// TransitionStep godoc
//
//	@Summary		Transition step execution status
//	@Description	Transition a step execution status with role verification and evidence validation
//	@Tags			Step Executions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Step Execution ID"
//	@Param			request	body		TransitionStepRequest	true	"Transition request"
//	@Success		200		{object}	StepExecutionResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		403		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions/{id}/transition [put]
func (h *StepExecutionHandler) TransitionStep(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "step execution")
	if err != nil {
		return HandleError(err)
	}

	var req TransitionStepRequest
	if err := h.BindAndValidate(ctx, &req); err != nil {
		return HandleError(err)
	}
	signer := authcontext.SignerContextFromEcho(ctx)
	if signer == nil {
		return ctx.JSON(http.StatusUnauthorized, api.NewError(echo.NewHTTPError(http.StatusUnauthorized, "missing authentication claims")))
	}

	actor, err := h.GetActorIdentityFromClaims(ctx, h.db)
	if err != nil {
		return HandleError(err)
	}

	authenticatedUserID := ""
	resolvedUserID := actor.Email
	resolvedUserType := workflows.AssignmentTypeEmail.String()
	if actor.UserID != nil {
		authenticatedUserID = actor.UserID.String()
		resolvedUserID = actor.UserID.String()
		resolvedUserType = workflows.AssignmentTypeUser.String()
	}

	// Convert to workflow.StepTransitionRequest
	transitionReq := &workflow.StepTransitionRequest{
		Status:                   req.Status,
		Evidence:                 req.Evidence,
		Notes:                    req.Notes,
		UserID:                   resolvedUserID,
		UserType:                 resolvedUserType,
		AuthenticatedUserID:      authenticatedUserID,
		AuthenticatedEmail:       actor.Email,
		AuthenticatedIdentifiers: actor.Identifiers,
		AuthenticatedGroups:      actor.Groups,
		Signer:                   signer,
	}

	// Perform the transition with role verification and evidence validation
	if err := h.transitionService.TransitionStepStatus(ctx.Request().Context(), id, transitionReq); err != nil {
		if isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		if errors.Is(err, workflow.ErrInvalidStepTransition) {
			return ctx.JSON(http.StatusBadRequest, api.NewError(err))
		}
		// Check if it's a permission error
		if isPermissionError(err) {
			return ctx.JSON(http.StatusForbidden, api.NewError(err))
		}
		return h.HandleServiceError(ctx, err, "transition", "step execution")
	}

	stepExecution, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "step execution after transition")
	}

	h.sugar.Infow("Step execution transitioned", "id", id, "status", req.Status, "user", actor.Email)
	return h.RespondOK(ctx, StepExecutionResponse{Data: stepExecution})
}

// GetEvidenceRequirements godoc
//
//	@Summary		Get evidence requirements for step
//	@Description	Get the evidence requirements for a step execution
//	@Tags			Step Executions
//	@Produce		json
//	@Param			id	path		string	true	"Step Execution ID"
//	@Success		200	{object}	map[string]interface{}
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions/{id}/evidence-requirements [get]
func (h *StepExecutionHandler) GetEvidenceRequirements(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "step execution")
	if err != nil {
		return HandleError(err)
	}

	requirements, err := h.transitionService.GetEvidenceRequirements(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "evidence requirements")
	}

	return h.RespondOK(ctx, map[string]interface{}{
		"data": requirements,
	})
}

// CanTransition godoc
//
//	@Summary		Check if user can transition step
//	@Description	Check if a user has permission to transition a step execution
//	@Tags			Step Executions
//	@Produce		json
//	@Param			id			path		string	true	"Step Execution ID"
//	@Param			user_id		query		string	true	"User ID"
//	@Param			user_type	query		string	true	"User Type (user, group, email)"
//	@Success		200			{object}	map[string]interface{}
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions/{id}/can-transition [get]
func (h *StepExecutionHandler) CanTransition(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "step execution")
	if err != nil {
		return HandleError(err)
	}

	userID := ctx.QueryParam("user_id")
	userType := ctx.QueryParam("user_type")

	if userID == "" || userType == "" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(echo.NewHTTPError(http.StatusBadRequest, "user_id and user_type are required")))
	}

	canTransition, err := h.transitionService.CanUserTransitionStep(id, userID, userType)
	if err != nil {
		return h.HandleServiceError(ctx, err, "check", "transition permission")
	}

	return h.RespondOK(ctx, map[string]interface{}{
		"data": map[string]interface{}{
			"can-transition": canTransition,
			"user-id":        userID,
			"user-type":      userType,
		},
	})
}

// Fail godoc
//
//	@Summary		Fail step execution
//	@Description	Mark a step execution as failed with a reason
//	@Tags			Step Executions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string			true	"Step Execution ID"
//	@Param			request	body		FailStepRequest	true	"Failure details"
//	@Success		200		{object}	StepExecutionResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions/{id}/fail [put]
func (h *StepExecutionHandler) Fail(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "step execution")
	if err != nil {
		return HandleError(err)
	}

	var req FailStepRequest
	if err := h.BindAndValidate(ctx, &req); err != nil {
		return HandleError(err)
	}

	if err := h.transitionService.FailStep(ctx.Request().Context(), id, req.Reason); err != nil {
		return h.HandleServiceError(ctx, err, "fail", "step execution")
	}

	stepExecution, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "step execution after failure")
	}

	h.sugar.Infow("Step execution marked as failed", "id", id, "reason", req.Reason)
	return h.RespondOK(ctx, StepExecutionResponse{Data: stepExecution})
}

// Reassign godoc
//
//	@Summary		Reassign step execution
//	@Description	Reassign a step execution to a new assignee
//	@Tags			Step Executions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string				true	"Step Execution ID"
//	@Param			request	body		ReassignStepRequest	true	"Reassignment details"
//	@Success		200		{object}	StepExecutionResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/step-executions/{id}/reassign [put]
func (h *StepExecutionHandler) Reassign(ctx echo.Context) error {
	id, err := h.ParseUUID(ctx, "id", "step execution")
	if err != nil {
		return HandleError(err)
	}

	var req ReassignStepRequest
	if err := h.BindAndValidate(ctx, &req); err != nil {
		return HandleError(err)
	}

	reassignedByUserID, reassignedByEmail, err := h.GetActorFromClaims(ctx, h.db)
	if err != nil {
		return HandleError(err)
	}

	if err := h.assignmentService.ReassignStep(
		ctx.Request().Context(),
		*id,
		workflow.Assignee{Type: req.AssignedToType, ID: req.AssignedToID},
		req.Reason,
		reassignedByUserID,
		reassignedByEmail,
	); err != nil {
		if errors.Is(err, workflow.ErrInvalidAssignee) || errors.Is(err, workflow.ErrReassignmentNotAllowed) {
			return ctx.JSON(http.StatusBadRequest, api.NewError(err))
		}
		if errors.Is(err, gorm.ErrRecordNotFound) || isNotFoundError(err) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return h.HandleServiceError(ctx, err, "reassign", "step execution")
	}

	stepExecution, err := h.service.GetByID(id)
	if err != nil {
		return h.HandleServiceError(ctx, err, "get", "step execution after reassignment")
	}

	h.sugar.Infow("Step execution reassigned", "id", id, "assigned_to_type", req.AssignedToType, "assigned_to_id", req.AssignedToID)
	return h.RespondOK(ctx, StepExecutionResponse{Data: stepExecution})
}
