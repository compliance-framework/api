package oscal

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/defenseunicorns/go-oscal/src/pkg/versioning"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

type AssessmentPlanHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

func NewAssessmentPlanHandler(sugar *zap.SugaredLogger, db *gorm.DB) *AssessmentPlanHandler {
	return &AssessmentPlanHandler{
		sugar: sugar,
		db:    db,
	}
}

// Register registers Assessment Plan endpoints to the API group.
func (h *AssessmentPlanHandler) Register(api *echo.Group) {
	// Core CRUD operations with query parameter expansion
	api.GET("", h.List)          // GET /oscal/assessment-plans?expand=all&include=tasks,assets
	api.POST("", h.Create)       // POST /oscal/assessment-plans
	api.GET("/:id", h.Get)       // GET /oscal/assessment-plans/:id?expand=all&include=tasks
	api.PUT("/:id", h.Update)    // PUT /oscal/assessment-plans/:id
	api.DELETE("/:id", h.Delete) // DELETE /oscal/assessment-plans/:id

	// Sub-resource management endpoints - Phase 2
	api.GET("/:id/metadata", h.GetMetadata)
	api.GET("/:id/import-ssp", h.GetImportSsp)
	api.GET("/:id/local-definitions", h.GetLocalDefinitions)
	api.GET("/:id/terms-and-conditions", h.GetTermsAndConditions)
	api.GET("/:id/back-matter", h.GetBackMatter)

	// Tasks sub-resource management
	api.GET("/:id/tasks", h.GetTasks)
	api.POST("/:id/tasks", h.CreateTask)
	api.PUT("/:id/tasks/:taskId", h.UpdateTask)
	api.DELETE("/:id/tasks/:taskId", h.DeleteTask)

	// Task Activities sub-resource management
	api.POST("/:id/tasks/:taskId/activities", h.CreateActivityForTask)

	// Activities sub-resource management
	api.GET("/:id/activities", h.GetActivities)
	api.POST("/:id/activities", h.CreateActivity)
	api.PUT("/:id/activities/:activityId", h.UpdateActivity)
	api.DELETE("/:id/activities/:activityId", h.DeleteActivity)

	// Assessment Subjects sub-resource management
	api.GET("/:id/assessment-subjects", h.GetAssessmentSubjects)
	api.POST("/:id/assessment-subjects", h.CreateAssessmentSubject)
	api.PUT("/:id/assessment-subjects/:subjectId", h.UpdateAssessmentSubject)
	api.DELETE("/:id/assessment-subjects/:subjectId", h.DeleteAssessmentSubject)

	// Assessment Assets sub-resource management
	api.GET("/:id/assessment-assets", h.GetAssessmentAssets)
	api.POST("/:id/assessment-assets", h.CreateAssessmentAsset)
	api.PUT("/:id/assessment-assets/:assetId", h.UpdateAssessmentAsset)
	api.DELETE("/:id/assessment-assets/:assetId", h.DeleteAssessmentAsset)
}

// verifyAssessmentPlanExists checks if an assessment plan exists in the database
func (h *AssessmentPlanHandler) verifyAssessmentPlanExists(ctx echo.Context, planID uuid.UUID) error {
	var count int64
	if err := h.db.Model(&relational.AssessmentPlan{}).Where("id = ?", planID).Count(&count).Error; err != nil {
		h.sugar.Errorf("Failed to verify assessment plan existence: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if count == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("assessment plan not found")))
	}
	return nil
}

// validateAssessmentPlanInput validates assessment plan input following OSCAL requirements
func (h *AssessmentPlanHandler) validateAssessmentPlanInput(plan *oscalTypes_1_1_3.AssessmentPlan) error {
	var errors []string

	if plan.UUID == "" {
		errors = append(errors, "UUID is required")
	} else if _, err := uuid.Parse(plan.UUID); err != nil {
		errors = append(errors, fmt.Sprintf("invalid UUID format: %s", plan.UUID))
	}

	if plan.Metadata.Title == "" {
		errors = append(errors, "metadata.title is required")
	}

	if plan.Metadata.Version == "" {
		errors = append(errors, "metadata.version is required")
	}

	if plan.ImportSsp.Href == "" {
		errors = append(errors, "import-ssp.href is required")
	}

	if len(errors) > 0 {
		return fmt.Errorf("validation errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// buildQueryWithExpansion builds a GORM query with appropriate preloads based on expansion parameters
func (h *AssessmentPlanHandler) buildQueryWithExpansion(baseQuery *gorm.DB, expand, include string) *gorm.DB {
	// Always include basic metadata
	query := baseQuery.
		Preload("Metadata").
		Preload("Metadata.Revisions")

	// Handle full expansion
	if expand == "all" || expand == "full" {
		return h.addAllPreloads(query)
	}

	// Handle selective inclusion
	if include != "" {
		return h.addSelectivePreloads(query, include)
	}

	return query
}

// addAllPreloads adds all available preloads for complete resource expansion
func (h *AssessmentPlanHandler) addAllPreloads(query *gorm.DB) *gorm.DB {
	return query.
		Preload("Tasks").
		Preload("Tasks.Dependencies").
		Preload("Tasks.Tasks"). // Sub-tasks
		Preload("Tasks.AssociatedActivities").
		Preload("Tasks.AssociatedActivities.Steps").
		Preload("Tasks.Subjects").
		Preload("Tasks.ResponsibleRole").
		Preload("AssessmentAssets").
		Preload("AssessmentSubjects").
		Preload("LocalDefinitions").
		Preload("TermsAndConditions").
		Preload("BackMatter")
}

// addSelectivePreloads adds specific preloads based on the include parameter
func (h *AssessmentPlanHandler) addSelectivePreloads(query *gorm.DB, include string) *gorm.DB {
	includes := strings.Split(include, ",")
	for _, inc := range includes {
		switch strings.TrimSpace(inc) {
		case "tasks":
			query = query.Preload("Tasks").
				Preload("Tasks.Dependencies").
				Preload("Tasks.Tasks")
		case "activities":
			query = query.Preload("Tasks").
				Preload("Tasks.AssociatedActivities").
				Preload("Tasks.AssociatedActivities.Steps")
		case "assets", "assessment-assets":
			query = query.Preload("AssessmentAssets")
		case "subjects", "assessment-subjects":
			query = query.Preload("AssessmentSubjects")
		case "local-definitions":
			query = query.Preload("LocalDefinitions")
		case "terms-conditions", "terms-and-conditions":
			query = query.Preload("TermsAndConditions")
		case "back-matter":
			query = query.Preload("BackMatter")
		}
	}
	return query
}

// List godoc
//
//	@Summary		List Assessment Plans
//	@Description	Retrieves all Assessment Plans with optional expansion and filtering.
//	@Tags			Assessment Plans
//	@Produce		json
//	@Param			expand	query		string	false	"Expansion level: 'all', 'full'"
//	@Param			include	query		string	false	"Specific fields to include: 'tasks,assets,subjects'"
//	@Success		200		{array}		oscalTypes_1_1_3.AssessmentPlan
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-plans [get]
func (h *AssessmentPlanHandler) List(ctx echo.Context) error {
	// Parse expansion parameters
	expand := ctx.QueryParam("expand")
	include := ctx.QueryParam("include")

	var plans []relational.AssessmentPlan

	// Build query with expansion
	query := h.buildQueryWithExpansion(h.db, expand, include)

	// Get all results
	if err := query.Find(&plans).Error; err != nil {
		h.sugar.Error(err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Convert to OSCAL format
	oscalPlans := make([]oscalTypes_1_1_3.AssessmentPlan, len(plans))
	for i, plan := range plans {
		oscalPlans[i] = *plan.MarshalOscal()
	}

	// Return simple array response
	return ctx.JSON(http.StatusOK, oscalPlans)
}

// Get godoc
//
//	@Summary		Get an Assessment Plan
//	@Description	Retrieves a single Assessment Plan by its unique ID with optional expansion.
//	@Tags			Assessment Plans
//	@Produce		json
//	@Param			id		path		string	true	"Assessment Plan ID"
//	@Param			expand	query		string	false	"Expansion level: 'all', 'full'"
//	@Param			include	query		string	false	"Specific fields to include: 'tasks,activities,assets,subjects,local-definitions,terms-conditions,back-matter'"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentPlan]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-plans/{id} [get]
//	@Example		GET /oscal/assessment-plans/123?expand=all
//	@Example		GET /oscal/assessment-plans/123?include=tasks,assets
func (h *AssessmentPlanHandler) Get(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Parse expansion parameters
	expand := ctx.QueryParam("expand")
	include := ctx.QueryParam("include")

	// Build query with appropriate preloads
	query := h.buildQueryWithExpansion(h.db, expand, include)

	var plan relational.AssessmentPlan
	if err := query.First(&plan, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load assessment plan", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.AssessmentPlan]{Data: plan.MarshalOscal()})
}

// Create godoc
//
//	@Summary		Create an Assessment Plan
//	@Description	Creates a new OSCAL Assessment Plan with comprehensive validation.
//	@Tags			Assessment Plans
//	@Accept			json
//	@Produce		json
//	@Param			plan	body		oscalTypes_1_1_3.AssessmentPlan									true	"Assessment Plan object with required fields: UUID, metadata (title, version), import-ssp"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentPlan]	"Successfully created assessment plan"
//	@Failure		400		{object}	api.Error														"Bad request - validation errors or malformed input"
//	@Failure		401		{object}	api.Error														"Unauthorized - invalid or missing JWT token"
//	@Failure		500		{object}	api.Error														"Internal server error"
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-plans [post]
func (h *AssessmentPlanHandler) Create(ctx echo.Context) error {
	var plan oscalTypes_1_1_3.AssessmentPlan
	if err := ctx.Bind(&plan); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateAssessmentPlanInput(&plan); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Set metadata timestamps
	now := time.Now()
	plan.Metadata.LastModified = now
	plan.Metadata.OscalVersion = versioning.GetLatestSupportedVersion()

	// Convert to a relational model
	relationalPlan := &relational.AssessmentPlan{}
	relationalPlan.UnmarshalOscal(plan)

	// Save to the database
	if err := h.db.Create(relationalPlan).Error; err != nil {
		h.sugar.Errorf("Failed to create assessment plan: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[*oscalTypes_1_1_3.AssessmentPlan]{Data: relationalPlan.MarshalOscal()})
}

// Update godoc
//
//	@Summary		Update an Assessment Plan
//	@Description	Updates an existing Assessment Plan.
//	@Tags			Assessment Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string							true	"Assessment Plan ID"
//	@Param			plan	body		oscalTypes_1_1_3.AssessmentPlan	true	"Assessment Plan object"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentPlan]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id} [put]
func (h *AssessmentPlanHandler) Update(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify plan exists
	if err := h.verifyAssessmentPlanExists(ctx, id); err != nil {
		return err
	}

	var plan oscalTypes_1_1_3.AssessmentPlan
	if err := ctx.Bind(&plan); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateAssessmentPlanInput(&plan); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Update metadata
	now := time.Now()
	plan.Metadata.LastModified = now

	// Convert to a relational model
	relationalPlan := &relational.AssessmentPlan{}
	relationalPlan.UnmarshalOscal(plan)

	// Update in database
	relationalPlan.ID = &id
	if err := h.db.Where("id = ?", id).Updates(relationalPlan).Error; err != nil {
		h.sugar.Errorf("Failed to update assessment plan: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.AssessmentPlan]{Data: relationalPlan.MarshalOscal()})
}

// Delete godoc
//
//	@Summary		Delete an Assessment Plan
//	@Description	Deletes an Assessment Plan by its unique ID.
//	@Tags			Assessment Plans
//	@Param			id	path	string	true	"Assessment Plan ID"
//	@Success		204	"No Content"
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id} [delete]
func (h *AssessmentPlanHandler) Delete(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify plan exists
	if err := h.verifyAssessmentPlanExists(ctx, id); err != nil {
		return err
	}

	// Delete from database
	if err := h.db.Delete(&relational.AssessmentPlan{}, "id = ?", id).Error; err != nil {
		h.sugar.Errorf("Failed to delete assessment plan: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetMetadata godoc
//
//	@Summary		Get Assessment Plan Metadata
//	@Description	Retrieves metadata for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/metadata [get]
func (h *AssessmentPlanHandler) GetMetadata(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var plan relational.AssessmentPlan
	if err := h.db.Preload("Metadata").Where("id = ?", id).First(&plan).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("assessment plan not found")))
		}
		h.sugar.Errorf("Failed to retrieve assessment plan metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Metadata]{Data: plan.Metadata.MarshalOscal()})
}

// GetImportSsp godoc
//
//	@Summary		Get Assessment Plan Import SSP
//	@Description	Retrieves import SSP information for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ImportSsp]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/import-ssp [get]
func (h *AssessmentPlanHandler) GetImportSsp(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var plan relational.AssessmentPlan
	if err := h.db.Where("id = ?", id).First(&plan).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("assessment plan not found")))
		}
		h.sugar.Errorf("Failed to retrieve assessment plan: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	importSsp := oscalTypes_1_1_3.ImportSsp(plan.ImportSSP.Data())
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.ImportSsp]{Data: &importSsp})
}

// GetLocalDefinitions godoc
//
//	@Summary		Get Assessment Plan Local Definitions
//	@Description	Retrieves local definitions for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.LocalDefinitions]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/local-definitions [get]
func (h *AssessmentPlanHandler) GetLocalDefinitions(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var plan relational.AssessmentPlan
	if err := h.db.Preload("LocalDefinitions").Where("id = ?", id).First(&plan).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("assessment plan not found")))
		}
		h.sugar.Errorf("Failed to retrieve assessment plan: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if plan.LocalDefinitions.ID == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("local definitions not found")))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.LocalDefinitions]{Data: plan.LocalDefinitions.MarshalOscal()})
}

// GetTermsAndConditions godoc
//
//	@Summary		Get Assessment Plan Terms and Conditions
//	@Description	Retrieves terms and conditions for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentPlanTermsAndConditions]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/terms-and-conditions [get]
func (h *AssessmentPlanHandler) GetTermsAndConditions(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var plan relational.AssessmentPlan
	if err := h.db.Preload("TermsAndConditions").Where("id = ?", id).First(&plan).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("assessment plan not found")))
		}
		h.sugar.Errorf("Failed to retrieve assessment plan: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if plan.TermsAndConditions.ID == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("terms and conditions not found")))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.AssessmentPlanTermsAndConditions]{Data: plan.TermsAndConditions.MarshalOscal()})
}

// GetBackMatter godoc
//
//	@Summary		Get Assessment Plan Back Matter
//	@Description	Retrieves back matter for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/back-matter [get]
func (h *AssessmentPlanHandler) GetBackMatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var plan relational.AssessmentPlan
	if err := h.db.Preload("BackMatter").Where("id = ?", id).First(&plan).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("assessment plan not found")))
		}
		h.sugar.Errorf("Failed to retrieve assessment plan: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if plan.BackMatter == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("back matter not found")))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.BackMatter]{Data: plan.BackMatter.MarshalOscal()})
}
