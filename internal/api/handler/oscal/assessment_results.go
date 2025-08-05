package oscal

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/defenseunicorns/go-oscal/src/pkg/versioning"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

// AssessmentResultsHandler handles OSCAL Assessment Results endpoints.
//
//	@Tags	Assessment Results
//
// All types are defined in oscalTypes_1_1_3 (see types.go)
type AssessmentResultsHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

// NewAssessmentResultsHandler creates a new handler for Assessment Results endpoints.
func NewAssessmentResultsHandler(sugar *zap.SugaredLogger, db *gorm.DB) *AssessmentResultsHandler {
	return &AssessmentResultsHandler{
		sugar: sugar,
		db:    db,
	}
}

// verifyAssessmentResultsExists checks if an Assessment Results exists by ID and returns appropriate HTTP error if not
func (h *AssessmentResultsHandler) verifyAssessmentResultsExists(ctx echo.Context, arID uuid.UUID) error {
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", arID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("assessment results not found")))
		}
		h.sugar.Errorf("Failed to find assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return nil
}

// Register registers Assessment Results endpoints to the API group.
func (h *AssessmentResultsHandler) Register(api *echo.Group) {
	api.GET("", h.List)          // GET /oscal/assessment-results
	api.POST("", h.Create)       // POST /oscal/assessment-results
	api.GET("/:id", h.Get)       // GET /oscal/assessment-results/:id
	api.PUT("/:id", h.Update)    // PUT /oscal/assessment-results/:id
	api.DELETE("/:id", h.Delete) // DELETE /oscal/assessment-results/:id
	api.GET("/:id/full", h.Full) // GET /oscal/assessment-results/:id/full
	api.GET("/:id/metadata", h.GetMetadata)
	api.PUT("/:id/metadata", h.UpdateMetadata)
	api.GET("/:id/import-ap", h.GetImportAp)
	api.PUT("/:id/import-ap", h.UpdateImportAp)
	api.GET("/:id/local-definitions", h.GetLocalDefinitions)
	api.PUT("/:id/local-definitions", h.UpdateLocalDefinitions)
	api.GET("/:id/results", h.GetResults)
	api.POST("/:id/results", h.CreateResult)
	api.GET("/:id/results/:resultId", h.GetResult)
	api.PUT("/:id/results/:resultId", h.UpdateResult)
	api.DELETE("/:id/results/:resultId", h.DeleteResult)
	api.GET("/:id/results/:resultId/observations", h.GetResultObservations)
	api.POST("/:id/results/:resultId/observations", h.CreateResultObservation)
	api.PUT("/:id/results/:resultId/observations/:obsId", h.UpdateResultObservation)
	api.DELETE("/:id/results/:resultId/observations/:obsId", h.DeleteResultObservation)
	api.GET("/:id/results/:resultId/risks", h.GetResultRisks)
	api.POST("/:id/results/:resultId/risks", h.CreateResultRisk)
	api.PUT("/:id/results/:resultId/risks/:riskId", h.UpdateResultRisk)
	api.DELETE("/:id/results/:resultId/risks/:riskId", h.DeleteResultRisk)
	api.GET("/:id/results/:resultId/findings", h.GetResultFindings)
	api.POST("/:id/results/:resultId/findings", h.CreateResultFinding)
	api.PUT("/:id/results/:resultId/findings/:findingId", h.UpdateResultFinding)
	api.DELETE("/:id/results/:resultId/findings/:findingId", h.DeleteResultFinding)
	api.GET("/:id/results/:resultId/attestations", h.GetResultAttestations)
	api.POST("/:id/results/:resultId/attestations", h.CreateResultAttestation)
	api.PUT("/:id/results/:resultId/attestations/:attestationId", h.UpdateResultAttestation)
	api.DELETE("/:id/results/:resultId/attestations/:attestationId", h.DeleteResultAttestation)

	// Endpoints to list all observations, risks, and findings across all results
	api.GET("/:id/observations", h.GetAllObservations)
	api.GET("/:id/risks", h.GetAllRisks)
	api.GET("/:id/findings", h.GetAllFindings)

	// Control endpoints for findings
	api.GET("/:id/available-controls", h.GetAvailableControls)
	api.GET("/:id/control/:controlId", h.GetControlDetails)

	// Association endpoints for existing observations, risks, and findings
	api.GET("/:id/results/:resultId/associated-observations", h.GetResultAssociatedObservations)
	api.POST("/:id/results/:resultId/associated-observations/:observationId", h.AssociateResultObservation)
	api.DELETE("/:id/results/:resultId/associated-observations/:observationId", h.DisassociateResultObservation)
	api.GET("/:id/results/:resultId/associated-risks", h.GetResultAssociatedRisks)
	api.POST("/:id/results/:resultId/associated-risks/:riskId", h.AssociateResultRisk)
	api.DELETE("/:id/results/:resultId/associated-risks/:riskId", h.DisassociateResultRisk)
	api.GET("/:id/results/:resultId/associated-findings", h.GetResultAssociatedFindings)
	api.POST("/:id/results/:resultId/associated-findings/:findingId", h.AssociateResultFinding)
	api.DELETE("/:id/results/:resultId/associated-findings/:findingId", h.DisassociateResultFinding)

	api.GET("/:id/back-matter", h.GetBackMatter)
	api.POST("/:id/back-matter", h.CreateBackMatter)
	api.PUT("/:id/back-matter", h.UpdateBackMatter)
	api.DELETE("/:id/back-matter", h.DeleteBackMatter)
	api.GET("/:id/back-matter/resources", h.GetBackMatterResources)
	api.POST("/:id/back-matter/resources", h.CreateBackMatterResource)
	api.PUT("/:id/back-matter/resources/:resourceId", h.UpdateBackMatterResource)
	api.DELETE("/:id/back-matter/resources/:resourceId", h.DeleteBackMatterResource)
}

// validateAssessmentResultsInput validates Assessment Results input following OSCAL requirements
func (h *AssessmentResultsHandler) validateAssessmentResultsInput(ar *oscalTypes_1_1_3.AssessmentResults) error {
	if ar.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(ar.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if ar.Metadata.Title == "" {
		return fmt.Errorf("metadata.title is required")
	}
	if ar.Metadata.Version == "" {
		return fmt.Errorf("metadata.version is required")
	}
	if ar.ImportAp.Href == "" {
		return fmt.Errorf("import-ap.href is required")
	}
	if len(ar.Results) == 0 {
		return fmt.Errorf("at least one result is required")
	}
	return nil
}

// validateResultInput validates Result input
func (h *AssessmentResultsHandler) validateResultInput(result *oscalTypes_1_1_3.Result) error {
	if result.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(result.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if result.Title == "" {
		return fmt.Errorf("title is required")
	}
	if result.Description == "" {
		return fmt.Errorf("description is required")
	}
	if result.Start.IsZero() {
		return fmt.Errorf("start time is required")
	}
	return nil
}

// validateObservationInput validates observation input
func (h *AssessmentResultsHandler) validateObservationInput(obs *oscalTypes_1_1_3.Observation) error {
	if obs.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(obs.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if obs.Description == "" {
		return fmt.Errorf("description is required")
	}
	if obs.Methods == nil || len(obs.Methods) == 0 {
		return fmt.Errorf("methods are required")
	}
	return nil
}

// validateRiskInput validates risk input
func (h *AssessmentResultsHandler) validateRiskInput(risk *oscalTypes_1_1_3.Risk) error {
	if risk.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(risk.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if risk.Title == "" {
		return fmt.Errorf("title is required")
	}
	if risk.Description == "" {
		return fmt.Errorf("description is required")
	}
	if risk.Statement == "" {
		return fmt.Errorf("statement is required")
	}
	if risk.Status == "" {
		return fmt.Errorf("status is required")
	}
	return nil
}

// validateFindingInput validates finding input
func (h *AssessmentResultsHandler) validateFindingInput(finding *oscalTypes_1_1_3.Finding) error {
	if finding.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(finding.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	if finding.Title == "" {
		return fmt.Errorf("title is required")
	}
	if finding.Description == "" {
		return fmt.Errorf("description is required")
	}
	if finding.Target.Type == "" {
		return fmt.Errorf("target.type is required")
	}
	if finding.Target.TargetId == "" {
		return fmt.Errorf("target.target-id is required")
	}
	return nil
}

// validateAttestationInput validates attestation input
func (h *AssessmentResultsHandler) validateAttestationInput(attestation *oscalTypes_1_1_3.AttestationStatements) error {
	if attestation.Parts == nil || len(attestation.Parts) == 0 {
		return fmt.Errorf("parts are required")
	}
	// Validate each part
	for i, part := range attestation.Parts {
		if part.Name == "" {
			return fmt.Errorf("part[%d].name is required", i)
		}
		if part.Ns == "" {
			return fmt.Errorf("part[%d].ns is required", i)
		}
		if part.Class == "" {
			return fmt.Errorf("part[%d].class is required", i)
		}
	}
	return nil
}

// List godoc
//
//	@Summary		List Assessment Results
//	@Description	Retrieves all Assessment Results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.AssessmentResults]
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results [get]
func (h *AssessmentResultsHandler) List(ctx echo.Context) error {
	var assessmentResults []relational.AssessmentResult
	if err := h.db.Preload("Metadata").Preload("Metadata.Revisions").Find(&assessmentResults).Error; err != nil {
		h.sugar.Errorw("failed to list assessment results", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalARs := make([]oscalTypes_1_1_3.AssessmentResults, len(assessmentResults))
	for i, ar := range assessmentResults {
		oscalARs[i] = *ar.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.AssessmentResults]{Data: oscalARs})
}

// Get godoc
//
//	@Summary		Get an Assessment Results
//	@Description	Retrieves a single Assessment Results by its unique ID.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Results ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentResults]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id} [get]
func (h *AssessmentResultsHandler) Get(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ar relational.AssessmentResult
	if err := h.db.Preload("Metadata").Preload("Metadata.Revisions").First(&ar, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load assessment results", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentResults]{Data: *ar.MarshalOscal()})
}

// Full godoc
//
//	@Summary		Get a complete Assessment Results
//	@Description	Retrieves a complete Assessment Results by its ID, including all metadata and related objects.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Results ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentResults]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/full [get]
func (h *AssessmentResultsHandler) Full(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ar relational.AssessmentResult
	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Preload("Results").
		Preload("Results.Observations").
		Preload("Results.Risks").
		Preload("Results.Findings").
		Preload("BackMatter").
		Preload("BackMatter.Resources").
		First(&ar, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("failed to get assessment results", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentResults]{Data: *ar.MarshalOscal()})
}

// Create godoc
//
//	@Summary		Create an Assessment Results
//	@Description	Creates an Assessment Results from input.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			ar	body		oscalTypes_1_1_3.AssessmentResults	true	"Assessment Results data"
//	@Success		201	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentResults]
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results [post]
func (h *AssessmentResultsHandler) Create(ctx echo.Context) error {
	var oscalAR oscalTypes_1_1_3.AssessmentResults
	if err := ctx.Bind(&oscalAR); err != nil {
		h.sugar.Warnw("Invalid create assessment results request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateAssessmentResultsInput(&oscalAR); err != nil {
		h.sugar.Warnw("Invalid assessment results input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	now := time.Now()
	relAR := &relational.AssessmentResult{}
	relAR.UnmarshalOscal(oscalAR)
	relAR.Metadata.LastModified = &now
	relAR.Metadata.OscalVersion = versioning.GetLatestSupportedVersion()

	if err := h.db.Create(relAR).Error; err != nil {
		h.sugar.Errorf("Failed to create assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentResults]{Data: *relAR.MarshalOscal()})
}

// Update godoc
//
//	@Summary		Update an Assessment Results
//	@Description	Updates an existing Assessment Results.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string								true	"Assessment Results ID"
//	@Param			ar	body		oscalTypes_1_1_3.AssessmentResults	true	"Updated Assessment Results object"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentResults]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id} [put]
func (h *AssessmentResultsHandler) Update(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment results id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalAR oscalTypes_1_1_3.AssessmentResults
	if err := ctx.Bind(&oscalAR); err != nil {
		h.sugar.Warnw("Invalid update assessment results request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate required fields
	if err := h.validateAssessmentResultsInput(&oscalAR); err != nil {
		h.sugar.Warnw("Invalid assessment results input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Begin a transaction
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// Check if assessment results exists and preload metadata
	var existingAR relational.AssessmentResult
	if err := tx.Preload("Metadata").Preload("LocalDefinitions").First(&existingAR, "id = ?", id).Error; err != nil {
		tx.Rollback()
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update assessment results
	now := time.Now()
	relAR := &relational.AssessmentResult{}
	relAR.UnmarshalOscal(oscalAR)
	relAR.ID = &id // Ensure ID is set correctly

	// Update the main assessment results record (only simple fields)
	updateFields := map[string]any{
		"import_ap": relAR.ImportAp,
	}

	if err := tx.Model(&existingAR).Updates(updateFields).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata using the incoming OSCAL metadata fields
	// Build update map with all fields from the incoming metadata
	metadataUpdates := map[string]interface{}{
		"title":         oscalAR.Metadata.Title,
		"version":       oscalAR.Metadata.Version,
		"published":     oscalAR.Metadata.Published,
		"remarks":       oscalAR.Metadata.Remarks,
		"last_modified": &now,
		"oscal_version": versioning.GetLatestSupportedVersion(),
	}

	if err := tx.Model(&relational.Metadata{}).Where("id = ?", existingAR.Metadata.ID).Updates(metadataUpdates).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Handle LocalDefinitions if provided
	if relAR.LocalDefinitions != nil {
		if existingAR.LocalDefinitions != nil {
			// Update existing LocalDefinitions
			relAR.LocalDefinitions.ID = existingAR.LocalDefinitions.ID
			if err := tx.Model(&relational.LocalDefinitions{}).Where("id = ?", existingAR.LocalDefinitions.ID).Updates(relAR.LocalDefinitions).Error; err != nil {
				tx.Rollback()
				h.sugar.Errorf("Failed to update local definitions: %v", err)
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
		} else {
			// Create new LocalDefinitions
			relAR.LocalDefinitions.ParentID = id
			relAR.LocalDefinitions.ParentType = "assessment_results"
			if err := tx.Create(relAR.LocalDefinitions).Error; err != nil {
				tx.Rollback()
				h.sugar.Errorf("Failed to create local definitions: %v", err)
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
		}
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Reload the updated assessment results with all associations
	var updatedAR relational.AssessmentResult
	if err := h.db.Preload("Metadata").
		Preload("LocalDefinitions").
		Preload("BackMatter").
		Where("id = ?", id).
		First(&updatedAR).Error; err != nil {
		h.sugar.Errorf("Failed to reload assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentResults]{Data: *updatedAR.MarshalOscal()})
}

// Delete godoc
//
//	@Summary		Delete an Assessment Results
//	@Description	Deletes an Assessment Results by its ID.
//	@Tags			Assessment Results
//	@Param			id	path	string	true	"Assessment Results ID"
//	@Success		204	"No Content"
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id} [delete]
func (h *AssessmentResultsHandler) Delete(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	if err := h.db.Delete(&relational.AssessmentResult{}, "id = ?", id).Error; err != nil {
		h.sugar.Errorf("Failed to delete assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetMetadata godoc
//
//	@Summary		Get Assessment Results metadata
//	@Description	Retrieves metadata for a given Assessment Results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Results ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/metadata [get]
func (h *AssessmentResultsHandler) GetMetadata(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ar relational.AssessmentResult
	if err := h.db.Preload("Metadata").First(&ar, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get assessment results", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]{Data: *ar.Metadata.MarshalOscal()})
}

// UpdateMetadata godoc
//
//	@Summary		Update Assessment Results metadata
//	@Description	Updates metadata for a given Assessment Results.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Assessment Results ID"
//	@Param			metadata	body		oscalTypes_1_1_3.Metadata	true	"Metadata data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/metadata [put]
func (h *AssessmentResultsHandler) UpdateMetadata(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	var oscalMetadata oscalTypes_1_1_3.Metadata
	if err := ctx.Bind(&oscalMetadata); err != nil {
		h.sugar.Warnw("Invalid update metadata request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate required fields
	if oscalMetadata.Title == "" {
		h.sugar.Warnw("Invalid metadata input", "error", "title is required")
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("title is required")))
	}
	if oscalMetadata.Version == "" {
		h.sugar.Warnw("Invalid metadata input", "error", "version is required")
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("version is required")))
	}

	var ar relational.AssessmentResult
	if err := h.db.Preload("Metadata").First(&ar, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get assessment results", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	// Update metadata with current timestamp
	now := time.Now()
	relMetadata := &relational.Metadata{}
	relMetadata.UnmarshalOscal(oscalMetadata)
	relMetadata.LastModified = &now
	relMetadata.OscalVersion = versioning.GetLatestSupportedVersion()

	// Update the metadata
	if err := h.db.Model(&ar.Metadata).Updates(relMetadata).Error; err != nil {
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Metadata]{Data: *relMetadata.MarshalOscal()})
}

// GetImportAp godoc
//
//	@Summary		Get Assessment Results import-ap
//	@Description	Retrieves import-ap for a given Assessment Results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Results ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ImportAp]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/import-ap [get]
func (h *AssessmentResultsHandler) GetImportAp(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get assessment results", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	importAp := ar.ImportAp.Data()
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ImportAp]{Data: oscalTypes_1_1_3.ImportAp(importAp)})
}

// UpdateImportAp godoc
//
//	@Summary		Update Assessment Results import-ap
//	@Description	Updates import-ap for a given Assessment Results.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Assessment Results ID"
//	@Param			importAp	body		oscalTypes_1_1_3.ImportAp	true	"Import AP data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ImportAp]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/import-ap [put]
func (h *AssessmentResultsHandler) UpdateImportAp(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	var oscalImportAp oscalTypes_1_1_3.ImportAp
	if err := ctx.Bind(&oscalImportAp); err != nil {
		h.sugar.Warnw("Invalid update import-ap request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate required fields
	if oscalImportAp.Href == "" {
		h.sugar.Warnw("Invalid import-ap input", "error", "href is required")
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("href is required")))
	}

	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get assessment results", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	// Convert to relational model
	relImportAp := relational.ImportAp{
		Href:    oscalImportAp.Href,
		Remarks: oscalImportAp.Remarks,
	}

	// Update the import-ap
	if err := h.db.Model(&ar).Update("import_ap", datatypes.NewJSONType(relImportAp)).Error; err != nil {
		h.sugar.Errorf("Failed to update import-ap: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	if err := h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now).Error; err != nil {
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ImportAp]{Data: oscalImportAp})
}

// GetLocalDefinitions godoc
//
//	@Summary		Get Assessment Results local-definitions
//	@Description	Retrieves local-definitions for a given Assessment Results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Results ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.LocalDefinitions]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/local-definitions [get]
func (h *AssessmentResultsHandler) GetLocalDefinitions(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ar relational.AssessmentResult
	if err := h.db.Preload("LocalDefinitions").First(&ar, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get assessment results", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	// LocalDefinitions in AssessmentResult is already a pointer to LocalDefinitions struct
	if ar.LocalDefinitions == nil {
		return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.LocalDefinitions]{Data: oscalTypes_1_1_3.LocalDefinitions{}})
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.LocalDefinitions]{Data: *ar.LocalDefinitions.MarshalOscal()})
}

// UpdateLocalDefinitions godoc
//
//	@Summary		Update Assessment Results local-definitions
//	@Description	Updates local-definitions for a given Assessment Results.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id					path		string								true	"Assessment Results ID"
//	@Param			localDefinitions	body		oscalTypes_1_1_3.LocalDefinitions	true	"Local definitions data"
//	@Success		200					{object}	handler.GenericDataResponse[oscalTypes_1_1_3.LocalDefinitions]
//	@Failure		400					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/local-definitions [put]
func (h *AssessmentResultsHandler) UpdateLocalDefinitions(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	var oscalLocalDefs oscalTypes_1_1_3.LocalDefinitions
	if err := ctx.Bind(&oscalLocalDefs); err != nil {
		h.sugar.Warnw("Invalid update local-definitions request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var ar relational.AssessmentResult
	if err := h.db.Preload("LocalDefinitions").First(&ar, "id = ?", id).Error; err != nil {
		h.sugar.Errorw("failed to get assessment results", "error", err)
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}

	// Convert to relational model
	relLocalDefs := relational.LocalDefinitions{}
	relLocalDefs.UnmarshalOscal(oscalLocalDefs)

	// Set the polymorphic parent relationship
	parentID := id.String()
	parentType := "AssessmentResult"
	relLocalDefs.ParentID = uuid.MustParse(parentID)
	relLocalDefs.ParentType = parentType

	// If there's an existing LocalDefinitions, delete it to avoid orphaned records
	if ar.LocalDefinitions != nil && ar.LocalDefinitions.ID != nil {
		if err := h.db.Delete(&relational.LocalDefinitions{}, "id = ?", ar.LocalDefinitions.ID).Error; err != nil {
			h.sugar.Errorf("Failed to delete existing local-definitions: %v", err)
			// Continue anyway, as we want to create the new one
		}
	}

	// Create new LocalDefinitions
	if err := h.db.Create(&relLocalDefs).Error; err != nil {
		h.sugar.Errorf("Failed to create local-definitions: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update the assessment result to point to the new LocalDefinitions
	if err := h.db.Model(&ar).Update("local_definitions_id", relLocalDefs.ID).Error; err != nil {
		h.sugar.Errorf("Failed to update assessment result local-definitions reference: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	if err := h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now).Error; err != nil {
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.LocalDefinitions]{Data: oscalLocalDefs})
}

// GetResults godoc
//
//	@Summary		Get results for an Assessment Results
//	@Description	Retrieves all results for a given Assessment Results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Results ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Result]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results [get]
func (h *AssessmentResultsHandler) GetResults(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var ar relational.AssessmentResult
	if err := h.db.Preload("Results").First(&ar, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load assessment results", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	oscalResults := make([]oscalTypes_1_1_3.Result, len(ar.Results))
	for i, result := range ar.Results {
		oscalResults[i] = *result.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Result]{Data: oscalResults})
}

// CreateResult godoc
//
//	@Summary		Create a result for an Assessment Results
//	@Description	Creates a new result for a given Assessment Results.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string					true	"Assessment Results ID"
//	@Param			result	body		oscalTypes_1_1_3.Result	true	"Result data"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Result]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results [post]
func (h *AssessmentResultsHandler) CreateResult(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	var oscalResult oscalTypes_1_1_3.Result
	if err := ctx.Bind(&oscalResult); err != nil {
		h.sugar.Warnw("Invalid create result request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateResultInput(&oscalResult); err != nil {
		h.sugar.Warnw("Invalid result input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Convert to relational model
	relResult := relational.Result{}
	relResult.UnmarshalOscal(oscalResult)
	relResult.AssessmentResultID = id

	// Create the result
	if err := h.db.Create(&relResult).Error; err != nil {
		h.sugar.Errorf("Failed to create result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Result]{Data: *relResult.MarshalOscal()})
}

// GetResult godoc
//
//	@Summary		Get a specific result
//	@Description	Retrieves a specific result from an Assessment Results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id			path		string	true	"Assessment Results ID"
//	@Param			resultId	path		string	true	"Result ID"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Result]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId} [get]
func (h *AssessmentResultsHandler) GetResult(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var result relational.Result
	if err := h.db.
		Preload("Observations").
		Preload("Risks").
		Preload("Findings").
		First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load result", "id", resultIdParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Result]{Data: *result.MarshalOscal()})
}

// UpdateResult godoc
//
//	@Summary		Update a result
//	@Description	Updates a specific result in an Assessment Results.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string					true	"Assessment Results ID"
//	@Param			resultId	path		string					true	"Result ID"
//	@Param			result		body		oscalTypes_1_1_3.Result	true	"Result data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Result]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId} [put]
func (h *AssessmentResultsHandler) UpdateResult(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalResult oscalTypes_1_1_3.Result
	if err := ctx.Bind(&oscalResult); err != nil {
		h.sugar.Warnw("Invalid update result request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateResultInput(&oscalResult); err != nil {
		h.sugar.Warnw("Invalid result input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Check if result exists
	var existingResult relational.Result
	if err := h.db.First(&existingResult, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Convert to relational model
	relResult := relational.Result{}
	relResult.UnmarshalOscal(oscalResult)
	relResult.ID = &resultId
	relResult.AssessmentResultID = id

	// Update the result - Result type in relational model doesn't have these fields
	// directly, need to update the whole object
	if err := h.db.Model(&existingResult).Updates(relResult).Error; err != nil {
		h.sugar.Errorf("Failed to update result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Result]{Data: *relResult.MarshalOscal()})
}

// DeleteResult godoc
//
//	@Summary		Delete a result
//	@Description	Deletes a specific result from an Assessment Results.
//	@Tags			Assessment Results
//	@Param			id			path	string	true	"Assessment Results ID"
//	@Param			resultId	path	string	true	"Result ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId} [delete]
func (h *AssessmentResultsHandler) DeleteResult(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Check if result exists
	var result relational.Result
	if err := h.db.First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Delete the result
	if err := h.db.Delete(&result).Error; err != nil {
		h.sugar.Errorf("Failed to delete result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.NoContent(http.StatusNoContent)
}

// Additional endpoint implementations would follow the same pattern for:
// - GetResultObservations, CreateResultObservation, UpdateResultObservation, DeleteResultObservation
// - GetResultRisks, CreateResultRisk, UpdateResultRisk, DeleteResultRisk
// - GetResultFindings, CreateResultFinding, UpdateResultFinding, DeleteResultFinding
// - GetResultAttestations, CreateResultAttestation, UpdateResultAttestation, DeleteResultAttestation
// - GetBackMatter, CreateBackMatter, UpdateBackMatter, DeleteBackMatter
// - GetBackMatterResources, CreateBackMatterResource, UpdateBackMatterResource, DeleteBackMatterResource

// GetResultObservations godoc
//
//	@Summary		Get observations for a result
//	@Description	Retrieves all observations for a given result.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id			path		string	true	"Assessment Results ID"
//	@Param			resultId	path		string	true	"Result ID"
//	@Success		200			{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Observation]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/observations [get]
func (h *AssessmentResultsHandler) GetResultObservations(ctx echo.Context) error {
	idParam := ctx.Param("id")
	_, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var result relational.Result
	if err := h.db.Preload("Observations").First(&result, "id = ?", resultId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load result", "id", resultIdParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalObs := make([]oscalTypes_1_1_3.Observation, len(result.Observations))
	for i, obs := range result.Observations {
		oscalObs[i] = *obs.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Observation]{Data: oscalObs})
}

// CreateResultObservation godoc
//
//	@Summary		Create an observation for a result
//	@Description	Creates a new observation for a given result.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string							true	"Assessment Results ID"
//	@Param			resultId	path		string							true	"Result ID"
//	@Param			observation	body		oscalTypes_1_1_3.Observation	true	"Observation data"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Observation]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/observations [post]
func (h *AssessmentResultsHandler) CreateResultObservation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify result exists and belongs to this assessment results
	var result relational.Result
	if err := h.db.First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result not found")))
		}
		h.sugar.Errorf("Failed to find result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalObs oscalTypes_1_1_3.Observation
	if err := ctx.Bind(&oscalObs); err != nil {
		h.sugar.Warnw("Invalid create observation request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateObservationInput(&oscalObs); err != nil {
		h.sugar.Warnw("Invalid observation input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relObs := &relational.Observation{}
	relObs.UnmarshalOscal(oscalObs)

	// Create the observation through the association
	if err := h.db.Model(&result).Association("Observations").Append(relObs); err != nil {
		h.sugar.Errorf("Failed to create observation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Observation]{Data: *relObs.MarshalOscal()})
}

// UpdateResultObservation godoc
//
//	@Summary		Update an observation
//	@Description	Updates a specific observation in a result.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string							true	"Assessment Results ID"
//	@Param			resultId	path		string							true	"Result ID"
//	@Param			obsId		path		string							true	"Observation ID"
//	@Param			observation	body		oscalTypes_1_1_3.Observation	true	"Observation data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Observation]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/observations/{obsId} [put]
func (h *AssessmentResultsHandler) UpdateResultObservation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	obsIdParam := ctx.Param("obsId")
	obsId, err := uuid.Parse(obsIdParam)
	if err != nil {
		h.sugar.Errorw("invalid observation id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify result exists and belongs to this assessment results
	var result relational.Result
	if err := h.db.First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result not found")))
		}
		h.sugar.Errorf("Failed to find result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Check if observation exists and belongs to this result
	var count int64
	if err := h.db.Table("result_observations").Where("result_id = ? AND observation_id = ?", resultId, obsId).Count(&count).Error; err != nil {
		h.sugar.Errorf("Failed to check observation association: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if count == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("observation not found")))
	}

	var oscalObs oscalTypes_1_1_3.Observation
	if err := ctx.Bind(&oscalObs); err != nil {
		h.sugar.Warnw("Invalid update observation request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateObservationInput(&oscalObs); err != nil {
		h.sugar.Warnw("Invalid observation input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Get the full observation
	var existingObs relational.Observation
	if err := h.db.First(&existingObs, "id = ?", obsId).Error; err != nil {
		h.sugar.Errorf("Failed to get observation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update the observation
	relObs := &relational.Observation{}
	relObs.UnmarshalOscal(oscalObs)
	relObs.ID = &obsId

	if err := h.db.Model(&existingObs).Updates(relObs).Error; err != nil {
		h.sugar.Errorf("Failed to update observation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Observation]{Data: *relObs.MarshalOscal()})
}

// DeleteResultObservation godoc
//
//	@Summary		Delete an observation
//	@Description	Deletes a specific observation from a result.
//	@Tags			Assessment Results
//	@Param			id			path	string	true	"Assessment Results ID"
//	@Param			resultId	path	string	true	"Result ID"
//	@Param			obsId		path	string	true	"Observation ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/observations/{obsId} [delete]
func (h *AssessmentResultsHandler) DeleteResultObservation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	obsIdParam := ctx.Param("obsId")
	obsId, err := uuid.Parse(obsIdParam)
	if err != nil {
		h.sugar.Errorw("invalid observation id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify result exists and belongs to this assessment results
	var result relational.Result
	if err := h.db.First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result not found")))
		}
		h.sugar.Errorf("Failed to find result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Remove the observation from the result
	if err := h.db.Model(&result).Association("Observations").Delete(&relational.Observation{UUIDModel: relational.UUIDModel{ID: &obsId}}); err != nil {
		h.sugar.Errorf("Failed to delete observation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetResultRisks godoc
//
//	@Summary		Get risks for a result
//	@Description	Retrieves all risks for a given result.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id			path		string	true	"Assessment Results ID"
//	@Param			resultId	path		string	true	"Result ID"
//	@Success		200			{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Risk]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/risks [get]
func (h *AssessmentResultsHandler) GetResultRisks(ctx echo.Context) error {
	idParam := ctx.Param("id")
	_, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var result relational.Result
	if err := h.db.Preload("Risks").First(&result, "id = ?", resultId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load result", "id", resultIdParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalRisks := make([]oscalTypes_1_1_3.Risk, len(result.Risks))
	for i, risk := range result.Risks {
		oscalRisks[i] = *risk.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Risk]{Data: oscalRisks})
}

// CreateResultRisk godoc
//
//	@Summary		Create a risk for a result
//	@Description	Creates a new risk for a given result.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string					true	"Assessment Results ID"
//	@Param			resultId	path		string					true	"Result ID"
//	@Param			risk		body		oscalTypes_1_1_3.Risk	true	"Risk data"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Risk]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/risks [post]
func (h *AssessmentResultsHandler) CreateResultRisk(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify result exists and belongs to this assessment results
	var result relational.Result
	if err := h.db.First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result not found")))
		}
		h.sugar.Errorf("Failed to find result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalRisk oscalTypes_1_1_3.Risk
	if err := ctx.Bind(&oscalRisk); err != nil {
		h.sugar.Warnw("Invalid create risk request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateRiskInput(&oscalRisk); err != nil {
		h.sugar.Warnw("Invalid risk input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relRisk := &relational.Risk{}
	relRisk.UnmarshalOscal(oscalRisk)

	// Create the risk through the association
	if err := h.db.Model(&result).Association("Risks").Append(relRisk); err != nil {
		h.sugar.Errorf("Failed to create risk: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Risk]{Data: *relRisk.MarshalOscal()})
}

// UpdateResultRisk godoc
//
//	@Summary		Update a risk
//	@Description	Updates a specific risk in a result.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string					true	"Assessment Results ID"
//	@Param			resultId	path		string					true	"Result ID"
//	@Param			riskId		path		string					true	"Risk ID"
//	@Param			risk		body		oscalTypes_1_1_3.Risk	true	"Risk data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Risk]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/risks/{riskId} [put]
func (h *AssessmentResultsHandler) UpdateResultRisk(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	riskIdParam := ctx.Param("riskId")
	riskId, err := uuid.Parse(riskIdParam)
	if err != nil {
		h.sugar.Errorw("invalid risk id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify result exists and belongs to this assessment results
	var result relational.Result
	if err := h.db.First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result not found")))
		}
		h.sugar.Errorf("Failed to find result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Check if risk exists and belongs to this result
	var count int64
	if err := h.db.Table("result_risks").Where("result_id = ? AND risk_id = ?", resultId, riskId).Count(&count).Error; err != nil {
		h.sugar.Errorf("Failed to check risk association: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if count == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk not found")))
	}

	var oscalRisk oscalTypes_1_1_3.Risk
	if err := ctx.Bind(&oscalRisk); err != nil {
		h.sugar.Warnw("Invalid update risk request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateRiskInput(&oscalRisk); err != nil {
		h.sugar.Warnw("Invalid risk input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Get the full risk
	var existingRisk relational.Risk
	if err := h.db.First(&existingRisk, "id = ?", riskId).Error; err != nil {
		h.sugar.Errorf("Failed to get risk: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update the risk
	relRisk := &relational.Risk{}
	relRisk.UnmarshalOscal(oscalRisk)
	relRisk.ID = &riskId

	if err := h.db.Model(&existingRisk).Updates(relRisk).Error; err != nil {
		h.sugar.Errorf("Failed to update risk: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Risk]{Data: *relRisk.MarshalOscal()})
}

// DeleteResultRisk godoc
//
//	@Summary		Delete a risk
//	@Description	Deletes a specific risk from a result.
//	@Tags			Assessment Results
//	@Param			id			path	string	true	"Assessment Results ID"
//	@Param			resultId	path	string	true	"Result ID"
//	@Param			riskId		path	string	true	"Risk ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/risks/{riskId} [delete]
func (h *AssessmentResultsHandler) DeleteResultRisk(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	riskIdParam := ctx.Param("riskId")
	riskId, err := uuid.Parse(riskIdParam)
	if err != nil {
		h.sugar.Errorw("invalid risk id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify result exists and belongs to this assessment results
	var result relational.Result
	if err := h.db.First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result not found")))
		}
		h.sugar.Errorf("Failed to find result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Remove the risk from the result
	if err := h.db.Model(&result).Association("Risks").Delete(&relational.Risk{UUIDModel: relational.UUIDModel{ID: &riskId}}); err != nil {
		h.sugar.Errorf("Failed to delete risk: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetResultFindings godoc
//
//	@Summary		Get findings for a result
//	@Description	Retrieves all findings for a given result.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id			path		string	true	"Assessment Results ID"
//	@Param			resultId	path		string	true	"Result ID"
//	@Success		200			{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Finding]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/findings [get]
func (h *AssessmentResultsHandler) GetResultFindings(ctx echo.Context) error {
	idParam := ctx.Param("id")
	_, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var result relational.Result
	if err := h.db.Preload("Findings").First(&result, "id = ?", resultId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load result", "id", resultIdParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalFindings := make([]oscalTypes_1_1_3.Finding, len(result.Findings))
	for i, finding := range result.Findings {
		oscalFindings[i] = *finding.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Finding]{Data: oscalFindings})
}

// CreateResultFinding godoc
//
//	@Summary		Create a finding for a result
//	@Description	Creates a new finding for a given result.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Assessment Results ID"
//	@Param			resultId	path		string						true	"Result ID"
//	@Param			finding		body		oscalTypes_1_1_3.Finding	true	"Finding data"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Finding]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/findings [post]
func (h *AssessmentResultsHandler) CreateResultFinding(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify result exists and belongs to this assessment results
	var result relational.Result
	if err := h.db.First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result not found")))
		}
		h.sugar.Errorf("Failed to find result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalFinding oscalTypes_1_1_3.Finding
	if err := ctx.Bind(&oscalFinding); err != nil {
		h.sugar.Warnw("Invalid create finding request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateFindingInput(&oscalFinding); err != nil {
		h.sugar.Warnw("Invalid finding input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relFinding := &relational.Finding{}
	relFinding.UnmarshalOscal(oscalFinding)

	// Create the finding through the association
	if err := h.db.Model(&result).Association("Findings").Append(relFinding); err != nil {
		h.sugar.Errorf("Failed to create finding: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Finding]{Data: *relFinding.MarshalOscal()})
}

// UpdateResultFinding godoc
//
//	@Summary		Update a finding
//	@Description	Updates a specific finding in a result.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Assessment Results ID"
//	@Param			resultId	path		string						true	"Result ID"
//	@Param			findingId	path		string						true	"Finding ID"
//	@Param			finding		body		oscalTypes_1_1_3.Finding	true	"Finding data"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Finding]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/findings/{findingId} [put]
func (h *AssessmentResultsHandler) UpdateResultFinding(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	findingIdParam := ctx.Param("findingId")
	findingId, err := uuid.Parse(findingIdParam)
	if err != nil {
		h.sugar.Errorw("invalid finding id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify result exists and belongs to this assessment results
	var result relational.Result
	if err := h.db.First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result not found")))
		}
		h.sugar.Errorf("Failed to find result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Check if finding exists and belongs to this result
	var count int64
	if err := h.db.Table("result_findings").Where("result_id = ? AND finding_id = ?", resultId, findingId).Count(&count).Error; err != nil {
		h.sugar.Errorf("Failed to check finding association: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if count == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("finding not found")))
	}

	var oscalFinding oscalTypes_1_1_3.Finding
	if err := ctx.Bind(&oscalFinding); err != nil {
		h.sugar.Warnw("Invalid update finding request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateFindingInput(&oscalFinding); err != nil {
		h.sugar.Warnw("Invalid finding input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Get the full finding
	var existingFinding relational.Finding
	if err := h.db.First(&existingFinding, "id = ?", findingId).Error; err != nil {
		h.sugar.Errorf("Failed to get finding: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update the finding
	relFinding := &relational.Finding{}
	relFinding.UnmarshalOscal(oscalFinding)
	relFinding.ID = &findingId

	if err := h.db.Model(&existingFinding).Updates(relFinding).Error; err != nil {
		h.sugar.Errorf("Failed to update finding: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Finding]{Data: *relFinding.MarshalOscal()})
}

// DeleteResultFinding godoc
//
//	@Summary		Delete a finding
//	@Description	Deletes a specific finding from a result.
//	@Tags			Assessment Results
//	@Param			id			path	string	true	"Assessment Results ID"
//	@Param			resultId	path	string	true	"Result ID"
//	@Param			findingId	path	string	true	"Finding ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/findings/{findingId} [delete]
func (h *AssessmentResultsHandler) DeleteResultFinding(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	findingIdParam := ctx.Param("findingId")
	findingId, err := uuid.Parse(findingIdParam)
	if err != nil {
		h.sugar.Errorw("invalid finding id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify result exists and belongs to this assessment results
	var result relational.Result
	if err := h.db.First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result not found")))
		}
		h.sugar.Errorf("Failed to find result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Remove the finding from the result
	if err := h.db.Model(&result).Association("Findings").Delete(&relational.Finding{UUIDModel: relational.UUIDModel{ID: &findingId}}); err != nil {
		h.sugar.Errorf("Failed to delete finding: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetResultAttestations godoc
//
//	@Summary		Get attestations for a result
//	@Description	Retrieves all attestations for a given result.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id			path		string	true	"Assessment Results ID"
//	@Param			resultId	path		string	true	"Result ID"
//	@Success		200			{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.AttestationStatements]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/attestations [get]
func (h *AssessmentResultsHandler) GetResultAttestations(ctx echo.Context) error {
	idParam := ctx.Param("id")
	_, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var result relational.Result
	if err := h.db.Preload("Attestations").Preload("Attestations.ResponsibleParties").First(&result, "id = ?", resultId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load result", "id", resultIdParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalAttestations := make([]oscalTypes_1_1_3.AttestationStatements, len(result.Attestations))
	for i, attestation := range result.Attestations {
		oscalAttestations[i] = *attestation.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.AttestationStatements]{Data: oscalAttestations})
}

// CreateResultAttestation godoc
//
//	@Summary		Create an attestation for a result
//	@Description	Creates a new attestation for a given result.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string									true	"Assessment Results ID"
//	@Param			resultId	path		string									true	"Result ID"
//	@Param			attestation	body		oscalTypes_1_1_3.AttestationStatements	true	"Attestation data"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AttestationStatements]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/attestations [post]
func (h *AssessmentResultsHandler) CreateResultAttestation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify result exists and belongs to this assessment results
	var result relational.Result
	if err := h.db.First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result not found")))
		}
		h.sugar.Errorf("Failed to find result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalAttestation oscalTypes_1_1_3.AttestationStatements
	if err := ctx.Bind(&oscalAttestation); err != nil {
		h.sugar.Warnw("Invalid create attestation request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateAttestationInput(&oscalAttestation); err != nil {
		h.sugar.Warnw("Invalid attestation input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	relAttestation := &relational.Attestation{}
	relAttestation.UnmarshalOscal(oscalAttestation)
	relAttestation.ResultID = resultId

	// Create the attestation
	if err := h.db.Create(relAttestation).Error; err != nil {
		h.sugar.Errorf("Failed to create attestation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.AttestationStatements]{Data: *relAttestation.MarshalOscal()})
}

// UpdateResultAttestation godoc
//
//	@Summary		Update an attestation
//	@Description	Updates a specific attestation in a result.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string									true	"Assessment Results ID"
//	@Param			resultId		path		string									true	"Result ID"
//	@Param			attestationId	path		string									true	"Attestation ID"
//	@Param			attestation		body		oscalTypes_1_1_3.AttestationStatements	true	"Attestation data"
//	@Success		200				{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AttestationStatements]
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/attestations/{attestationId} [put]
func (h *AssessmentResultsHandler) UpdateResultAttestation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	attestationIdParam := ctx.Param("attestationId")
	attestationId, err := uuid.Parse(attestationIdParam)
	if err != nil {
		h.sugar.Errorw("invalid attestation id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify result exists and belongs to this assessment results
	var result relational.Result
	if err := h.db.First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result not found")))
		}
		h.sugar.Errorf("Failed to find result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Check if attestation exists and belongs to this result
	var existingAttestation relational.Attestation
	if err := h.db.First(&existingAttestation, "id = ? AND result_id = ?", attestationId, resultId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("attestation not found")))
		}
		h.sugar.Errorf("Failed to find attestation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var oscalAttestation oscalTypes_1_1_3.AttestationStatements
	if err := ctx.Bind(&oscalAttestation); err != nil {
		h.sugar.Warnw("Invalid update attestation request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateAttestationInput(&oscalAttestation); err != nil {
		h.sugar.Warnw("Invalid attestation input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Update the attestation
	relAttestation := &relational.Attestation{}
	relAttestation.UnmarshalOscal(oscalAttestation)
	relAttestation.ID = &attestationId
	relAttestation.ResultID = resultId

	if err := h.db.Model(&existingAttestation).Updates(relAttestation).Error; err != nil {
		h.sugar.Errorf("Failed to update attestation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.AttestationStatements]{Data: *relAttestation.MarshalOscal()})
}

// DeleteResultAttestation godoc
//
//	@Summary		Delete an attestation
//	@Description	Deletes a specific attestation from a result.
//	@Tags			Assessment Results
//	@Param			id				path	string	true	"Assessment Results ID"
//	@Param			resultId		path	string	true	"Result ID"
//	@Param			attestationId	path	string	true	"Attestation ID"
//	@Success		204				"No Content"
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/attestations/{attestationId} [delete]
func (h *AssessmentResultsHandler) DeleteResultAttestation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Errorw("invalid result id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	attestationIdParam := ctx.Param("attestationId")
	attestationId, err := uuid.Parse(attestationIdParam)
	if err != nil {
		h.sugar.Errorw("invalid attestation id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify result exists and belongs to this assessment results
	var result relational.Result
	if err := h.db.First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result not found")))
		}
		h.sugar.Errorf("Failed to find result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Check if attestation exists and belongs to this result
	var existingAttestation relational.Attestation
	if err := h.db.First(&existingAttestation, "id = ? AND result_id = ?", attestationId, resultId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("attestation not found")))
		}
		h.sugar.Errorf("Failed to find attestation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Delete the attestation
	if err := h.db.Delete(&existingAttestation).Error; err != nil {
		h.sugar.Errorf("Failed to delete attestation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetResultAssociatedObservations godoc
//
//	@Summary		List Associated Observations for a Result
//	@Description	Retrieves all Observations associated with a specific Result in an Assessment Results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id			path		string	true	"Assessment Results ID"
//	@Param			resultId	path		string	true	"Result ID"
//	@Success		200			{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Observation]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/associated-observations [get]
func (h *AssessmentResultsHandler) GetResultAssociatedObservations(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment results id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid result id", "resultId", resultIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	// Load result with observations
	var result relational.Result
	if err := h.db.
		Preload("Observations").
		First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Result not found", "resultId", resultId, "assessmentResultId", id)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result with id %s not found", resultId)))
		}
		h.sugar.Errorf("Failed to retrieve result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	observations := make([]*oscalTypes_1_1_3.Observation, len(result.Observations))
	for i, obs := range result.Observations {
		observations[i] = obs.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[*oscalTypes_1_1_3.Observation]{Data: observations})
}

// AssociateResultObservation godoc
//
//	@Summary		Associate an Observation with a Result
//	@Description	Associates an existing Observation to a Result within an Assessment Results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id				path	string	true	"Assessment Results ID"
//	@Param			resultId		path	string	true	"Result ID"
//	@Param			observationId	path	string	true	"Observation ID"
//	@Success		200				"No Content"
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/associated-observations/{observationId} [post]
func (h *AssessmentResultsHandler) AssociateResultObservation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment results id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid result id", "resultId", resultIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	observationIdParam := ctx.Param("observationId")
	observationId, err := uuid.Parse(observationIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid observation id", "observationId", observationIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	// Verify result exists and belongs to the assessment results
	var result relational.Result
	if err := h.db.Where("id = ? AND assessment_result_id = ?", resultId, id).First(&result).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Result not found in assessment results", "resultId", resultId, "assessmentResultId", id)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result with id %s not found in assessment results %s", resultId, id)))
		}
		h.sugar.Errorf("Failed to retrieve result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Verify observation exists
	var observation relational.Observation
	if err := h.db.First(&observation, "id = ?", observationId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Observation not found", "observationId", observationId)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("observation with id %s not found", observationId)))
		}
		h.sugar.Errorf("Failed to retrieve observation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Associate the observation with the result
	if err := h.db.Model(&result).Association("Observations").Append(&observation); err != nil {
		h.sugar.Errorf("Failed to associate observation with result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.NoContent(http.StatusOK)
}

// DisassociateResultObservation godoc
//
//	@Summary		Disassociate an Observation from a Result
//	@Description	Removes an association of an Observation from a Result within an Assessment Results.
//	@Tags			Assessment Results
//	@Param			id				path	string	true	"Assessment Results ID"
//	@Param			resultId		path	string	true	"Result ID"
//	@Param			observationId	path	string	true	"Observation ID"
//	@Success		204				"No Content"
//	@Failure		400				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/associated-observations/{observationId} [delete]
func (h *AssessmentResultsHandler) DisassociateResultObservation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment results id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid result id", "resultId", resultIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	observationIdParam := ctx.Param("observationId")
	observationId, err := uuid.Parse(observationIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid observation id", "observationId", observationIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	// Verify result exists and belongs to the assessment results
	var result relational.Result
	if err := h.db.Where("id = ? AND assessment_result_id = ?", resultId, id).First(&result).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Result not found in assessment results", "resultId", resultId, "assessmentResultId", id)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result with id %s not found in assessment results %s", resultId, id)))
		}
		h.sugar.Errorf("Failed to retrieve result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Remove association
	if err := h.db.Exec("DELETE FROM result_observations WHERE result_id = ? AND observation_id = ?", resultId, observationId).Error; err != nil {
		h.sugar.Errorf("Failed to disassociate observation from result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetResultAssociatedRisks godoc
//
//	@Summary		List Associated Risks for a Result
//	@Description	Retrieves all Risks associated with a specific Result in an Assessment Results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id			path		string	true	"Assessment Results ID"
//	@Param			resultId	path		string	true	"Result ID"
//	@Success		200			{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Risk]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/associated-risks [get]
func (h *AssessmentResultsHandler) GetResultAssociatedRisks(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment results id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid result id", "resultId", resultIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	// Load result with risks
	var result relational.Result
	if err := h.db.
		Preload("Risks").
		First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Result not found", "resultId", resultId, "assessmentResultId", id)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result with id %s not found", resultId)))
		}
		h.sugar.Errorf("Failed to retrieve result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	risks := make([]*oscalTypes_1_1_3.Risk, len(result.Risks))
	for i, risk := range result.Risks {
		risks[i] = risk.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[*oscalTypes_1_1_3.Risk]{Data: risks})
}

// AssociateResultRisk godoc
//
//	@Summary		Associate a Risk with a Result
//	@Description	Associates an existing Risk to a Result within an Assessment Results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id			path	string	true	"Assessment Results ID"
//	@Param			resultId	path	string	true	"Result ID"
//	@Param			riskId		path	string	true	"Risk ID"
//	@Success		200			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/associated-risks/{riskId} [post]
func (h *AssessmentResultsHandler) AssociateResultRisk(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment results id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid result id", "resultId", resultIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	riskIdParam := ctx.Param("riskId")
	riskId, err := uuid.Parse(riskIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid risk id", "riskId", riskIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	// Verify result exists and belongs to the assessment results
	var result relational.Result
	if err := h.db.Where("id = ? AND assessment_result_id = ?", resultId, id).First(&result).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Result not found in assessment results", "resultId", resultId, "assessmentResultId", id)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result with id %s not found in assessment results %s", resultId, id)))
		}
		h.sugar.Errorf("Failed to retrieve result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Verify risk exists
	var risk relational.Risk
	if err := h.db.First(&risk, "id = ?", riskId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Risk not found", "riskId", riskId)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("risk with id %s not found", riskId)))
		}
		h.sugar.Errorf("Failed to retrieve risk: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Associate the risk with the result
	if err := h.db.Model(&result).Association("Risks").Append(&risk); err != nil {
		h.sugar.Errorf("Failed to associate risk with result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.NoContent(http.StatusOK)
}

// DisassociateResultRisk godoc
//
//	@Summary		Disassociate a Risk from a Result
//	@Description	Removes an association of a Risk from a Result within an Assessment Results.
//	@Tags			Assessment Results
//	@Param			id			path	string	true	"Assessment Results ID"
//	@Param			resultId	path	string	true	"Result ID"
//	@Param			riskId		path	string	true	"Risk ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/associated-risks/{riskId} [delete]
func (h *AssessmentResultsHandler) DisassociateResultRisk(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment results id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid result id", "resultId", resultIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	riskIdParam := ctx.Param("riskId")
	riskId, err := uuid.Parse(riskIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid risk id", "riskId", riskIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	// Verify result exists and belongs to the assessment results
	var result relational.Result
	if err := h.db.Where("id = ? AND assessment_result_id = ?", resultId, id).First(&result).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Result not found in assessment results", "resultId", resultId, "assessmentResultId", id)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result with id %s not found in assessment results %s", resultId, id)))
		}
		h.sugar.Errorf("Failed to retrieve result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Remove association
	if err := h.db.Exec("DELETE FROM result_risks WHERE result_id = ? AND risk_id = ?", resultId, riskId).Error; err != nil {
		h.sugar.Errorf("Failed to disassociate risk from result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetResultAssociatedFindings godoc
//
//	@Summary		List Associated Findings for a Result
//	@Description	Retrieves all Findings associated with a specific Result in an Assessment Results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id			path		string	true	"Assessment Results ID"
//	@Param			resultId	path		string	true	"Result ID"
//	@Success		200			{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Finding]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/associated-findings [get]
func (h *AssessmentResultsHandler) GetResultAssociatedFindings(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment results id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid result id", "resultId", resultIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	// Load result with findings
	var result relational.Result
	if err := h.db.
		Preload("Findings").
		First(&result, "id = ? AND assessment_result_id = ?", resultId, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Result not found", "resultId", resultId, "assessmentResultId", id)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result with id %s not found", resultId)))
		}
		h.sugar.Errorf("Failed to retrieve result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	findings := make([]*oscalTypes_1_1_3.Finding, len(result.Findings))
	for i, finding := range result.Findings {
		findings[i] = finding.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[*oscalTypes_1_1_3.Finding]{Data: findings})
}

// AssociateResultFinding godoc
//
//	@Summary		Associate a Finding with a Result
//	@Description	Associates an existing Finding to a Result within an Assessment Results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id			path	string	true	"Assessment Results ID"
//	@Param			resultId	path	string	true	"Result ID"
//	@Param			findingId	path	string	true	"Finding ID"
//	@Success		200			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/associated-findings/{findingId} [post]
func (h *AssessmentResultsHandler) AssociateResultFinding(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment results id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid result id", "resultId", resultIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	findingIdParam := ctx.Param("findingId")
	findingId, err := uuid.Parse(findingIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid finding id", "findingId", findingIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	// Verify result exists and belongs to the assessment results
	var result relational.Result
	if err := h.db.Where("id = ? AND assessment_result_id = ?", resultId, id).First(&result).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Result not found in assessment results", "resultId", resultId, "assessmentResultId", id)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result with id %s not found in assessment results %s", resultId, id)))
		}
		h.sugar.Errorf("Failed to retrieve result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Verify finding exists
	var finding relational.Finding
	if err := h.db.First(&finding, "id = ?", findingId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Finding not found", "findingId", findingId)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("finding with id %s not found", findingId)))
		}
		h.sugar.Errorf("Failed to retrieve finding: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Associate the finding with the result
	if err := h.db.Model(&result).Association("Findings").Append(&finding); err != nil {
		h.sugar.Errorf("Failed to associate finding with result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.NoContent(http.StatusOK)
}

// DisassociateResultFinding godoc
//
//	@Summary		Disassociate a Finding from a Result
//	@Description	Removes an association of a Finding from a Result within an Assessment Results.
//	@Tags			Assessment Results
//	@Param			id			path	string	true	"Assessment Results ID"
//	@Param			resultId	path	string	true	"Result ID"
//	@Param			findingId	path	string	true	"Finding ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/results/{resultId}/associated-findings/{findingId} [delete]
func (h *AssessmentResultsHandler) DisassociateResultFinding(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment results id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resultIdParam := ctx.Param("resultId")
	resultId, err := uuid.Parse(resultIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid result id", "resultId", resultIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	findingIdParam := ctx.Param("findingId")
	findingId, err := uuid.Parse(findingIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid finding id", "findingId", findingIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	// Verify result exists and belongs to the assessment results
	var result relational.Result
	if err := h.db.Where("id = ? AND assessment_result_id = ?", resultId, id).First(&result).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Result not found in assessment results", "resultId", resultId, "assessmentResultId", id)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("result with id %s not found in assessment results %s", resultId, id)))
		}
		h.sugar.Errorf("Failed to retrieve result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Remove association
	if err := h.db.Exec("DELETE FROM result_findings WHERE result_id = ? AND finding_id = ?", resultId, findingId).Error; err != nil {
		h.sugar.Errorf("Failed to disassociate finding from result: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err == nil {
		h.db.Model(&relational.Metadata{}).Where("id = ?", ar.Metadata.ID).Update("last_modified", now)
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetAllObservations godoc
//
//	@Summary		List all observations available for association
//	@Description	Retrieves all observations in the system that can be associated with results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Results ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Observation]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/observations [get]
func (h *AssessmentResultsHandler) GetAllObservations(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment results id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	// Get all observations in the system (not just those associated with this assessment result)
	var observations []relational.Observation
	if err := h.db.Find(&observations).Error; err != nil {
		h.sugar.Errorf("Failed to retrieve observations: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalObservations := make([]*oscalTypes_1_1_3.Observation, len(observations))
	for i, obs := range observations {
		oscalObservations[i] = obs.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[*oscalTypes_1_1_3.Observation]{Data: oscalObservations})
}

// GetAllRisks godoc
//
//	@Summary		List all risks available for association
//	@Description	Retrieves all risks in the system that can be associated with results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Results ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Risk]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/risks [get]
func (h *AssessmentResultsHandler) GetAllRisks(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment results id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	// Get all risks in the system (not just those associated with this assessment result)
	var risks []relational.Risk
	if err := h.db.Find(&risks).Error; err != nil {
		h.sugar.Errorf("Failed to retrieve risks: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalRisks := make([]*oscalTypes_1_1_3.Risk, len(risks))
	for i, risk := range risks {
		oscalRisks[i] = risk.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[*oscalTypes_1_1_3.Risk]{Data: oscalRisks})
}

// GetAllFindings godoc
//
//	@Summary		List all findings available for association
//	@Description	Retrieves all findings in the system that can be associated with results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Results ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Finding]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/findings [get]
func (h *AssessmentResultsHandler) GetAllFindings(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment results id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	// Get all findings in the system (not just those associated with this assessment result)
	var findings []relational.Finding
	if err := h.db.Find(&findings).Error; err != nil {
		h.sugar.Errorf("Failed to retrieve findings: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalFindings := make([]*oscalTypes_1_1_3.Finding, len(findings))
	for i, finding := range findings {
		oscalFindings[i] = finding.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[*oscalTypes_1_1_3.Finding]{Data: oscalFindings})
}

// GetBackMatter godoc
//
//	@Summary		Get back matter
//	@Description	Retrieves the back matter for an Assessment Results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Results ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/back-matter [get]
func (h *AssessmentResultsHandler) GetBackMatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var assessmentResult relational.AssessmentResult
	if err := h.db.Preload("BackMatter").Preload("BackMatter.Resources").First(&assessmentResult, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Return empty back matter if none exists
	if assessmentResult.BackMatter == nil {
		emptyBackMatter := &oscalTypes_1_1_3.BackMatter{
			Resources: &[]oscalTypes_1_1_3.Resource{},
		}
		return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]{Data: *emptyBackMatter})
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]{Data: *assessmentResult.BackMatter.MarshalOscal()})
}

// CreateBackMatter godoc
//
//	@Summary		Create back matter
//	@Description	Creates or replaces the back matter for an Assessment Results.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Assessment Results ID"
//	@Param			backMatter	body		oscalTypes_1_1_3.BackMatter	true	"Back Matter"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/back-matter [post]
func (h *AssessmentResultsHandler) CreateBackMatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalBackMatter oscalTypes_1_1_3.BackMatter
	if err := ctx.Bind(&oscalBackMatter); err != nil {
		h.sugar.Errorw("invalid back matter", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate resources if present
	if oscalBackMatter.Resources != nil && len(*oscalBackMatter.Resources) > 0 {
		for i, resource := range *oscalBackMatter.Resources {
			if resource.UUID == "" {
				h.sugar.Warnw("Invalid back-matter resource", "error", "resource UUID is required", "index", i)
				return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("resource UUID is required")))
			}
			if _, err := uuid.Parse(resource.UUID); err != nil {
				h.sugar.Warnw("Invalid back-matter resource UUID", "error", err, "index", i)
				return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid resource UUID format: %v", err)))
			}
		}
	}

	// Check if assessment results exists
	var assessmentResult relational.AssessmentResult
	if err := h.db.Preload("BackMatter").First(&assessmentResult, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Delete existing back matter if present
	if assessmentResult.BackMatter != nil {
		if err := h.db.Delete(&relational.BackMatter{}, "id = ?", assessmentResult.BackMatter.ID).Error; err != nil {
			h.sugar.Errorf("Failed to delete existing back matter: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Create new back matter
	backMatter := &relational.BackMatter{}
	backMatter.UnmarshalOscal(oscalBackMatter)

	// BackMatter ID will be auto-generated by the database via BeforeCreate hook

	// Set parent relationship for polymorphic association
	parentID := id.String()
	parentType := "AssessmentResult"
	backMatter.ParentID = &parentID
	backMatter.ParentType = &parentType

	// Update the assessment result with the new back matter
	assessmentResult.BackMatter = backMatter

	// Save the assessment result which will create the back matter and resources
	if err := h.db.Save(&assessmentResult).Error; err != nil {
		h.sugar.Errorf("Failed to save assessment result with back matter: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Reload the back matter with resources for response
	if err := h.db.Preload("Resources").First(backMatter, "id = ?", backMatter.ID).Error; err != nil {
		h.sugar.Errorf("Failed to preload resources: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	h.db.Model(&relational.Metadata{}).Where("id = ?", assessmentResult.Metadata.ID).Update("last_modified", now)

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]{Data: *backMatter.MarshalOscal()})
}

// UpdateBackMatter godoc
//
//	@Summary		Update back matter
//	@Description	Updates the back matter for an Assessment Results.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Assessment Results ID"
//	@Param			backMatter	body		oscalTypes_1_1_3.BackMatter	true	"Back Matter"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/back-matter [put]
func (h *AssessmentResultsHandler) UpdateBackMatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalBackMatter oscalTypes_1_1_3.BackMatter
	if err := ctx.Bind(&oscalBackMatter); err != nil {
		h.sugar.Errorw("invalid back matter", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate resources if present
	if oscalBackMatter.Resources != nil && len(*oscalBackMatter.Resources) > 0 {
		for i, resource := range *oscalBackMatter.Resources {
			if resource.UUID == "" {
				h.sugar.Warnw("Invalid back-matter resource", "error", "resource UUID is required", "index", i)
				return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("resource UUID is required")))
			}
			if _, err := uuid.Parse(resource.UUID); err != nil {
				h.sugar.Warnw("Invalid back-matter resource UUID", "error", err, "index", i)
				return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid resource UUID format: %v", err)))
			}
		}
	}

	// Check if assessment results exists
	var assessmentResult relational.AssessmentResult
	if err := h.db.Preload("BackMatter").First(&assessmentResult, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Check if back matter exists
	if assessmentResult.BackMatter == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("back matter not found")))
	}

	// Update back matter
	backMatter := assessmentResult.BackMatter

	// Delete existing resources and create new ones
	if err := h.db.Delete(&relational.BackMatterResource{}, "back_matter_id = ?", backMatter.ID).Error; err != nil {
		h.sugar.Errorf("Failed to delete existing resources: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Create new resources with proper BackMatterID
	if oscalBackMatter.Resources != nil && len(*oscalBackMatter.Resources) > 0 {
		for _, res := range *oscalBackMatter.Resources {
			resource := &relational.BackMatterResource{}
			resource.UnmarshalOscal(res)
			resource.BackMatterID = *backMatter.ID

			if err := h.db.Create(resource).Error; err != nil {
				h.sugar.Errorf("Failed to create resource: %v", err)
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
		}
	}

	// Preload resources for response
	if err := h.db.Preload("Resources").First(backMatter, "id = ?", backMatter.ID).Error; err != nil {
		h.sugar.Errorf("Failed to preload resources: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	h.db.Model(&relational.Metadata{}).Where("id = ?", assessmentResult.Metadata.ID).Update("last_modified", now)

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]{Data: *backMatter.MarshalOscal()})
}

// DeleteBackMatter godoc
//
//	@Summary		Delete back matter
//	@Description	Deletes the back matter for an Assessment Results.
//	@Tags			Assessment Results
//	@Param			id	path	string	true	"Assessment Results ID"
//	@Success		204	"No Content"
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/back-matter [delete]
func (h *AssessmentResultsHandler) DeleteBackMatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Check if assessment results exists
	var assessmentResult relational.AssessmentResult
	if err := h.db.Preload("BackMatter").First(&assessmentResult, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Check if back matter exists
	if assessmentResult.BackMatter == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("back matter not found")))
	}

	// Delete back matter and its resources
	if err := h.db.Delete(&relational.BackMatter{}, "id = ?", assessmentResult.BackMatter.ID).Error; err != nil {
		h.sugar.Errorf("Failed to delete back matter: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	h.db.Model(&relational.Metadata{}).Where("id = ?", assessmentResult.Metadata.ID).Update("last_modified", now)

	return ctx.NoContent(http.StatusNoContent)
}

// GetBackMatterResources godoc
//
//	@Summary		Get back matter resources
//	@Description	Retrieves all resources from the back matter for an Assessment Results.
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Results ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Resource]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/back-matter/resources [get]
func (h *AssessmentResultsHandler) GetBackMatterResources(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var assessmentResult relational.AssessmentResult
	if err := h.db.Preload("BackMatter").Preload("BackMatter.Resources").First(&assessmentResult, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Return empty list if no back matter
	if assessmentResult.BackMatter == nil {
		return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Resource]{Data: []oscalTypes_1_1_3.Resource{}})
	}

	// Convert resources to OSCAL format
	resources := make([]oscalTypes_1_1_3.Resource, len(assessmentResult.BackMatter.Resources))
	for i, r := range assessmentResult.BackMatter.Resources {
		resources[i] = *r.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Resource]{Data: resources})
}

// CreateBackMatterResource godoc
//
//	@Summary		Create back matter resource
//	@Description	Creates a new resource in the back matter for an Assessment Results.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Assessment Results ID"
//	@Param			resource	body		oscalTypes_1_1_3.Resource	true	"Resource"
//	@Success		201			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Resource]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/back-matter/resources [post]
func (h *AssessmentResultsHandler) CreateBackMatterResource(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalResource oscalTypes_1_1_3.Resource
	if err := ctx.Bind(&oscalResource); err != nil {
		h.sugar.Errorw("invalid resource", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate resource
	if err := h.validateResourceInput(&oscalResource); err != nil {
		h.sugar.Warnw("Invalid resource input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Check if assessment results exists
	var assessmentResult relational.AssessmentResult
	if err := h.db.Preload("BackMatter").First(&assessmentResult, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Create back matter if it doesn't exist
	if assessmentResult.BackMatter == nil {
		// BackMatter ID will be auto-generated by the database via BeforeCreate hook
		backMatter := &relational.BackMatter{}
		parentID := id.String()
		parentType := "AssessmentResult"
		backMatter.ParentID = &parentID
		backMatter.ParentType = &parentType

		// Update the assessment result with the new back matter
		assessmentResult.BackMatter = backMatter
		if err := h.db.Save(&assessmentResult).Error; err != nil {
			h.sugar.Errorf("Failed to save assessment result with back matter: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Create the resource
	resource := &relational.BackMatterResource{}
	resource.UnmarshalOscal(oscalResource)
	resource.BackMatterID = *assessmentResult.BackMatter.ID

	if err := h.db.Create(resource).Error; err != nil {
		h.sugar.Errorf("Failed to create resource: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	h.db.Model(&relational.Metadata{}).Where("id = ?", assessmentResult.Metadata.ID).Update("last_modified", now)

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Resource]{Data: *resource.MarshalOscal()})
}

// UpdateBackMatterResource godoc
//
//	@Summary		Update back matter resource
//	@Description	Updates a specific resource in the back matter for an Assessment Results.
//	@Tags			Assessment Results
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Assessment Results ID"
//	@Param			resourceId	path		string						true	"Resource ID"
//	@Param			resource	body		oscalTypes_1_1_3.Resource	true	"Resource"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Resource]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/back-matter/resources/{resourceId} [put]
func (h *AssessmentResultsHandler) UpdateBackMatterResource(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resourceIdParam := ctx.Param("resourceId")
	resourceId, err := uuid.Parse(resourceIdParam)
	if err != nil {
		h.sugar.Errorw("invalid resource id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalResource oscalTypes_1_1_3.Resource
	if err := ctx.Bind(&oscalResource); err != nil {
		h.sugar.Errorw("invalid resource", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate resource
	if err := h.validateResourceInput(&oscalResource); err != nil {
		h.sugar.Warnw("Invalid resource input", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Check if assessment results exists and has back matter
	var assessmentResult relational.AssessmentResult
	if err := h.db.Preload("BackMatter").First(&assessmentResult, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if assessmentResult.BackMatter == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("back matter not found")))
	}

	// Check if resource exists
	var existingResource relational.BackMatterResource
	if err := h.db.First(&existingResource, "id = ? AND back_matter_id = ?", resourceId, assessmentResult.BackMatter.ID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find resource: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update the resource
	resource := &relational.BackMatterResource{}
	resource.UnmarshalOscal(oscalResource)
	resource.ID = resourceId
	resource.BackMatterID = *assessmentResult.BackMatter.ID

	if err := h.db.Save(resource).Error; err != nil {
		h.sugar.Errorf("Failed to update resource: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	h.db.Model(&relational.Metadata{}).Where("id = ?", assessmentResult.Metadata.ID).Update("last_modified", now)

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Resource]{Data: *resource.MarshalOscal()})
}

// DeleteBackMatterResource godoc
//
//	@Summary		Delete back matter resource
//	@Description	Deletes a specific resource from the back matter for an Assessment Results.
//	@Tags			Assessment Results
//	@Param			id			path	string	true	"Assessment Results ID"
//	@Param			resourceId	path	string	true	"Resource ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/back-matter/resources/{resourceId} [delete]
func (h *AssessmentResultsHandler) DeleteBackMatterResource(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	resourceIdParam := ctx.Param("resourceId")
	resourceId, err := uuid.Parse(resourceIdParam)
	if err != nil {
		h.sugar.Errorw("invalid resource id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Check if assessment results exists and has back matter
	var assessmentResult relational.AssessmentResult
	if err := h.db.Preload("BackMatter").First(&assessmentResult, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if assessmentResult.BackMatter == nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("back matter not found")))
	}

	// Check if resource exists
	var resource relational.BackMatterResource
	if err := h.db.First(&resource, "id = ? AND back_matter_id = ?", resourceId, assessmentResult.BackMatter.ID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find resource: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Delete the resource
	if err := h.db.Delete(&resource).Error; err != nil {
		h.sugar.Errorf("Failed to delete resource: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata last-modified
	now := time.Now()
	h.db.Model(&relational.Metadata{}).Where("id = ?", assessmentResult.Metadata.ID).Update("last_modified", now)

	return ctx.NoContent(http.StatusNoContent)
}

// validateResourceInput validates Resource input following OSCAL requirements
func (h *AssessmentResultsHandler) validateResourceInput(r *oscalTypes_1_1_3.Resource) error {
	if r.UUID == "" {
		return fmt.Errorf("UUID is required")
	}
	if _, err := uuid.Parse(r.UUID); err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}
	return nil
}

// GetAvailableControls godoc
//
//	@Summary		Get available controls for findings
//	@Description	Retrieves controls that can be referenced in findings
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Results ID"
//	@Success		200	{object}	handler.GenericDataListResponse[[]oscalTypes_1_1_3.Control]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/available-controls [get]
func (h *AssessmentResultsHandler) GetAvailableControls(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	// Get the assessment results to potentially find associated catalog
	var ar relational.AssessmentResult
	if err := h.db.First(&ar, "id = ?", id).Error; err != nil {
		h.sugar.Errorf("Failed to get assessment results: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// For now, we'll get all controls from all catalogs
	// In the future, this could be filtered based on the assessment's system
	var controls []relational.Control
	if err := h.db.Find(&controls).Error; err != nil {
		h.sugar.Errorf("Failed to get controls: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalControls := make([]*oscalTypes_1_1_3.Control, len(controls))
	for i, control := range controls {
		oscalControls[i] = control.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[*oscalTypes_1_1_3.Control]{Data: oscalControls})
}

// GetControlDetails godoc
//
//	@Summary		Get control details with statements and objectives
//	@Description	Retrieves a control with all its parts for reference in findings
//	@Tags			Assessment Results
//	@Produce		json
//	@Param			id			path		string	true	"Assessment Results ID"
//	@Param			controlId	path		string	true	"Control ID"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Control]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/assessment-results/{id}/control/{controlId} [get]
func (h *AssessmentResultsHandler) GetControlDetails(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("invalid assessment results id", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	controlId := ctx.Param("controlId")

	// Verify assessment results exists
	if err := h.verifyAssessmentResultsExists(ctx, id); err != nil {
		return err
	}

	// Get the control with all its parts
	var control relational.Control
	if err := h.db.
		Where("id = ?", controlId).
		First(&control).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("control not found")))
		}
		h.sugar.Errorf("Failed to get control: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.Control]{Data: control.MarshalOscal()})
}
