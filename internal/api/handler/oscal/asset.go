package oscal

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

// validateAssessmentAssetInput validates assessment asset input
func (h *AssessmentPlanHandler) validateAssessmentAssetInput(asset *oscalTypes_1_1_3.AssessmentAssets) error {
	// Basic validation - at least one assessment platform should be provided
	if len(asset.AssessmentPlatforms) == 0 {
		return fmt.Errorf("at least one assessment platform is required")
	}
	return nil
}

// GetAssessmentAssets godoc
//
//	@Summary		Get Assessment Plan Assets
//	@Description	Retrieves all assessment assets for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[[]oscalTypes_1_1_3.AssessmentAssets]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/assessment-assets [get]
func (h *AssessmentPlanHandler) GetAssessmentAssets(ctx echo.Context) error {
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

	var assets []relational.AssessmentAsset
	if err := h.db.Preload("AssessmentPlatforms").Preload("Components").Where("parent_id = ? AND parent_type = ?", id, "AssessmentPlan").Find(&assets).Error; err != nil {
		h.sugar.Errorf("Failed to retrieve assessment assets: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalAssets := make([]*oscalTypes_1_1_3.AssessmentAssets, len(assets))
	for i, asset := range assets {
		oscalAssets[i] = asset.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[[]*oscalTypes_1_1_3.AssessmentAssets]{Data: oscalAssets})
}

// CreateAssessmentAsset godoc
//
//	@Summary		Create Assessment Plan Asset
//	@Description	Creates a new assessment asset for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string								true	"Assessment Plan ID"
//	@Param			asset	body		oscalTypes_1_1_3.AssessmentAssets	true	"Assessment Asset object"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentAssets]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/assessment-assets [post]
func (h *AssessmentPlanHandler) CreateAssessmentAsset(ctx echo.Context) error {
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

	var asset oscalTypes_1_1_3.AssessmentAssets
	if err := ctx.Bind(&asset); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateAssessmentAssetInput(&asset); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Convert to relational model
	relationalAsset := &relational.AssessmentAsset{}
	relationalAsset.UnmarshalOscal(asset)
	relationalAsset.ParentID = id
	relationalAsset.ParentType = "AssessmentPlan"

	// Save to database
	if err := h.db.Create(relationalAsset).Error; err != nil {
		h.sugar.Errorf("Failed to create assessment asset: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Create response with both OSCAL data and database ID for tests
	response := struct {
		*oscalTypes_1_1_3.AssessmentAssets
		ID string `json:"id"` // Database ID for UPDATE/DELETE operations
	}{
		AssessmentAssets: relationalAsset.MarshalOscal(),
		ID:               relationalAsset.ID.String(),
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[interface{}]{Data: response})
}

// UpdateAssessmentAsset godoc
//
//	@Summary		Update Assessment Plan Asset
//	@Description	Updates an existing assessment asset for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string								true	"Assessment Plan ID"
//	@Param			assetId	path		string								true	"Assessment Asset ID"
//	@Param			asset	body		oscalTypes_1_1_3.AssessmentAssets	true	"Assessment Asset object"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentAssets]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/assessment-assets/{assetId} [put]
func (h *AssessmentPlanHandler) UpdateAssessmentAsset(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	assetIdParam := ctx.Param("assetId")
	assetId, err := uuid.Parse(assetIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid asset id", "assetId", assetIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify plan exists
	if err := h.verifyAssessmentPlanExists(ctx, id); err != nil {
		return err
	}

	var asset oscalTypes_1_1_3.AssessmentAssets
	if err := ctx.Bind(&asset); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateAssessmentAssetInput(&asset); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Convert to relational model
	relationalAsset := &relational.AssessmentAsset{}
	relationalAsset.UnmarshalOscal(asset)
	relationalAsset.ID = &assetId
	relationalAsset.ParentID = id
	relationalAsset.ParentType = "AssessmentPlan"

	// Update in database and check if resource exists
	result := h.db.Where("id = ? AND parent_id = ? AND parent_type = ?", assetId, id, "AssessmentPlan").Updates(relationalAsset)
	if result.Error != nil {
		h.sugar.Errorf("Failed to update assessment asset: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	// Check if the asset was found and updated
	if result.RowsAffected == 0 {
		h.sugar.Warnw("Assessment asset not found for update", "assetId", assetId, "planId", id)
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("assessment asset with id %s not found in plan %s", assetId, id)))
	}

	// Create response with both OSCAL data and database ID for tests
	response := struct {
		*oscalTypes_1_1_3.AssessmentAssets
		ID string `json:"id"` // Database ID for UPDATE/DELETE operations
	}{
		AssessmentAssets: relationalAsset.MarshalOscal(),
		ID:               relationalAsset.ID.String(),
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[interface{}]{Data: response})
}

// DeleteAssessmentAsset godoc
//
//	@Summary		Delete Assessment Plan Asset
//	@Description	Deletes an assessment asset from an Assessment Plan.
//	@Tags			Assessment Plans
//	@Param			id		path	string	true	"Assessment Plan ID"
//	@Param			assetId	path	string	true	"Assessment Asset ID"
//	@Success		204		"No Content"
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/assessment-assets/{assetId} [delete]
func (h *AssessmentPlanHandler) DeleteAssessmentAsset(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	assetIdParam := ctx.Param("assetId")
	assetId, err := uuid.Parse(assetIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid asset id", "assetId", assetIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify plan exists
	if err := h.verifyAssessmentPlanExists(ctx, id); err != nil {
		return err
	}

	// Delete assessment asset and check if resource exists
	result := h.db.Where("id = ? AND parent_id = ? AND parent_type = ?", assetId, id, "AssessmentPlan").Delete(&relational.AssessmentAsset{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete assessment asset: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	// Check if the asset was found and deleted
	if result.RowsAffected == 0 {
		h.sugar.Warnw("Assessment asset not found for deletion", "assetId", assetId, "planId", id)
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("assessment asset with id %s not found in plan %s", assetId, id)))
	}

	return ctx.NoContent(http.StatusNoContent)
}
