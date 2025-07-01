package oscal

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/defenseunicorns/go-oscal/src/pkg/versioning"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
)

type ComponentDefinitionHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

func NewComponentDefinitionHandler(sugar *zap.SugaredLogger, db *gorm.DB) *ComponentDefinitionHandler {
	return &ComponentDefinitionHandler{
		sugar: sugar,
		db:    db,
	}
}

func (h *ComponentDefinitionHandler) Register(api *echo.Group) {
	api.GET("", h.List)                                                                                                                // manually tested
	api.POST("", h.Create)                                                                                                             // manually tested
	api.GET("/:id", h.Get)                                                                                                             // integration tested
	api.PUT("/:id", h.Update)                                                                                                          // integration tested
	api.GET("/:id/full", h.Full)                                                                                                       // manually tested
	api.GET("/:id/import-component-definitions", h.GetImportComponentDefinitions)                                                      // manually tested
	api.POST("/:id/import-component-definitions", h.CreateImportComponentDefinitions)                                                  // integration tested
	api.PUT("/:id/import-component-definitions", h.UpdateImportComponentDefinitions)                                                   // to test
	api.GET("/:id/components", h.GetComponents)                                                                                        // manually tested
	api.POST("/:id/components", h.CreateComponents)                                                                                    // integration tested
	api.PUT("/:id/components", h.UpdateComponents)                                                                                     // integration tested
	api.GET("/:id/components/:defined-component", h.GetDefinedComponent)                                                               // manually tested
	api.POST("/:id/components/:defined-component", h.CreateDefinedComponent)                                                           // integration tested
	api.PUT("/:id/components/:defined-component", h.UpdateDefinedComponent)                                                            // integration tested
	api.GET("/:id/components/:defined-component/control-implementations", h.GetControlImplementations)                                 // manually tested
	api.POST("/:id/components/:defined-component/control-implementations", h.CreateControlImplementations)                             // integration tested
	api.PUT("/:id/components/:defined-component/control-implementations", h.UpdateControlImplementations)                              // integration tested
	api.PUT("/:id/components/:defined-component/control-implementations/:control-implementation", h.UpdateSingleControlImplementation) // integration tested
	api.GET("/:id/components/:defined-component/control-implementations/implemented-requirements", h.GetImplementedRequirements)       // manually tested
	// api.POST("/:id/components/:defined-component/control-implementations/implemented-requirements", h.CreateImplementedRequirements)
	// api.PUT("/:id/components/:defined-component/control-implementations/implemented-requirements", h.UpdateImplementedRequirements)
	api.GET("/:id/components/:defined-component/control-implementations/implemented-requirements/statements", h.GetStatements) // manually tested
	// api.POST("/:id/components/:defined-component/control-implementations/:control-implementation/implemented-requirements/:implemented-requirement/statements", h.CreateStatements)
	// api.PUT("/:id/components/:defined-component/control-implementations/:statement", h.UpdateSingleStatement)
	api.GET("/:id/capabilities", h.GetCapabilities)                                       // manually tested
	api.POST("/:id/capabilities", h.CreateCapabilities)                                   // integration tested
	api.PUT("/:id/capabilities/:capability", h.UpdateCapability)                          // integration tested
	api.GET("/:id/capabilities/incorporates-components", h.GetIncorporatesComponents)     // manually tested
	api.POST("/:id/capabilities/incorporates-components", h.CreateIncorporatesComponents) // integration tested
	api.GET("/:id/back-matter", h.GetBackMatter)                                          // manually tested
	api.POST("/:id/back-matter", h.CreateBackMatter)                                      // integration tested
}

// List godoc
//
//	@Summary		List component definitions
//	@Description	Retrieves all component definitions.
//	@Tags			Oscal
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[oscal.List.responseComponentDefinition]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions [get]
func (h *ComponentDefinitionHandler) List(ctx echo.Context) error {
	type responseComponentDefinition struct {
		UUID     uuid.UUID                 `json:"uuid"`
		Metadata oscalTypes_1_1_3.Metadata `json:"metadata"`
	}

	var componentDefinitions []relational.ComponentDefinition
	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Find(&componentDefinitions).Error; err != nil {
		h.sugar.Warnw("Failed to load component definitions", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	oscalComponentDefinitions := []oscalTypes_1_1_3.ComponentDefinition{}
	for _, componentDefinition := range componentDefinitions {
		oscalComponentDefinitions = append(oscalComponentDefinitions, *componentDefinition.MarshalOscal())
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ComponentDefinition]{Data: oscalComponentDefinitions})
}

// Get godoc
//
//	@Summary		Get a component definition
//	@Description	Retrieves a single component definition by its unique ID.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id	path		string	true	"Component Definition ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscal.Get.responseComponentDefinition]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id} [get]
func (h *ComponentDefinitionHandler) Get(ctx echo.Context) error {
	type responseComponentDefinition struct {
		UUID     uuid.UUID                 `json:"uuid"`
		Metadata oscalTypes_1_1_3.Metadata `json:"metadata"`
	}

	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Warnw("Component definition not found", "id", idParam)
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	response := responseComponentDefinition{
		UUID:     *componentDefinition.ID,
		Metadata: *componentDefinition.Metadata.MarshalOscal(),
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[responseComponentDefinition]{Data: response})
}

// Create godoc
//
//	@Summary		Create a component definition
//	@Description	Creates a new component definition.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			componentDefinition	body		oscalTypes_1_1_3.ComponentDefinition	true	"Component Definition"
//	@Success		201					{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ComponentDefinition]
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions [post]
func (h *ComponentDefinitionHandler) Create(ctx echo.Context) error {
	now := time.Now()

	var oscalCat oscalTypes_1_1_3.ComponentDefinition
	if err := ctx.Bind(&oscalCat); err != nil {
		h.sugar.Warnw("Invalid create component definition request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	relCat := &relational.ComponentDefinition{}
	relCat.UnmarshalOscal(oscalCat)
	relCat.Metadata.LastModified = &now
	relCat.Metadata.OscalVersion = versioning.GetLatestSupportedVersion()
	if err := h.db.Create(relCat).Error; err != nil {
		h.sugar.Errorf("Failed to create component definition: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.ComponentDefinition]{Data: *relCat.MarshalOscal()})
}

// Update godoc
//
//	@Summary		Update a component definition
//	@Description	Updates an existing component definition.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id					path		string									true	"Component Definition ID"
//	@Param			componentDefinition	body		oscalTypes_1_1_3.ComponentDefinition	true	"Updated Component Definition object"
//	@Success		200					{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ComponentDefinition]
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id} [put]
func (h *ComponentDefinitionHandler) Update(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalCat oscalTypes_1_1_3.ComponentDefinition
	if err := ctx.Bind(&oscalCat); err != nil {
		h.sugar.Warnw("Invalid update component definition request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate required fields
	if oscalCat.UUID == "" {
		h.sugar.Warnw("Missing required field: UUID")
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("UUID is required")))
	}

	// Begin a transaction
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// Check if component definition exists
	var existingComponent relational.ComponentDefinition
	if err := tx.First(&existingComponent, "id = ?", id).Error; err != nil {
		tx.Rollback()
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorf("Failed to find component definition: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update component definition
	now := time.Now()
	relCat := &relational.ComponentDefinition{}
	relCat.UnmarshalOscal(oscalCat)
	relCat.ID = &id // Ensure ID is set correctly

	// Validate the unmarshaled data
	if relCat.Metadata.Title == "" {
		tx.Rollback()
		h.sugar.Warnw("Missing required field: Metadata.Title")
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("Metadata.Title is required")))
	}

	// Update component definition with import_component_definitions
	if err := tx.Model(&existingComponent).Where("id = ?", id).Update("import_component_definitions", relCat.ImportComponentDefinitions).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update component definition: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata
	now = time.Now()
	metadataUpdates := &relational.Metadata{
		LastModified: &now,
		OscalVersion: versioning.GetLatestSupportedVersion(),
	}
	if err := tx.Model(&relational.Metadata{}).Where("id = ?", existingComponent.Metadata.ID).Updates(metadataUpdates).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ComponentDefinition]{Data: *relCat.MarshalOscal()})
}

// Full godoc
//
//	@Summary		Get a complete Component Definition
//	@Description	Retrieves a complete Component Definition by its ID, including all metadata and revisions.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id	path		string	true	"Component Definition ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ComponentDefinition]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/full [get]
func (h *ComponentDefinitionHandler) Full(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Preload("BackMatter").
		Preload("BackMatter.Resources").
		First(&componentDefinition, "id = ?", id).Error; err != nil {
		if err == nil {
			// Load Components and their nested relationships dynamically
			h.db.Preload("Components.ResponsibleRoles").
				Preload("Components.ControlImplementations").
				Preload("Components.ControlImplementations.ImplementedRequirements").
				Preload("Components.ControlImplementations.ImplementedRequirements.ResponsibleRoles").
				Preload("Components.ControlImplementations.ImplementedRequirements.Statements").
				Preload("Components.ControlImplementations.ImplementedRequirements.Statements.ResponsibleRoles").
				Find(&componentDefinition.Components)

			// Load Capabilities and their nested relationships dynamically
			h.db.Preload("Capabilities.ControlImplementations").
				Preload("Capabilities.ControlImplementations.ImplementedRequirements").
				Preload("Capabilities.ControlImplementations.ImplementedRequirements.ResponsibleRoles").
				Preload("Capabilities.ControlImplementations.ImplementedRequirements.Statements").
				Preload("Capabilities.ControlImplementations.ImplementedRequirements.Statements.ResponsibleRoles").
				Find(&componentDefinition.Capabilities)
		}
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ComponentDefinition]{Data: *componentDefinition.MarshalOscal()})
}

// GetImportComponentDefinitions godoc
//
//	@Summary		Get import component definitions for a defined component
//	@Description	Retrieves all import component definitions for a given defined component.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id					path		string	true	"Component Definition ID"
//	@Param			defined-component	path		string	true	"Defined Component ID"
//	@Success		200					{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ImportComponentDefinition]
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/import-component-definitions [get]
func (h *ComponentDefinitionHandler) GetImportComponentDefinitions(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalImportComponentDefinitions []oscalTypes_1_1_3.ImportComponentDefinition
	for _, importComponentDefinition := range componentDefinition.ImportComponentDefinitions {
		oscalImportComponentDefinitions = append(oscalImportComponentDefinitions, *importComponentDefinition.MarshalOscal())
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ImportComponentDefinition]{Data: oscalImportComponentDefinitions})
}

// CreateImportComponentDefinitions godoc
//
//	@Summary		Create import component definitions for a component definition
//	@Description	Creates new import component definitions for a given component definition.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id								path		string											true	"Component Definition ID"
//	@Param			import-component-definitions	body		[]oscalTypes_1_1_3.ImportComponentDefinition	true	"Import Component Definitions"
//	@Success		200								{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ImportComponentDefinition]
//	@Failure		400								{object}	api.Error
//	@Failure		401								{object}	api.Error
//	@Failure		404								{object}	api.Error
//	@Failure		500								{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/import-component-definitions [post]
func (h *ComponentDefinitionHandler) CreateImportComponentDefinitions(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.Preload("Metadata").First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var importComponentDefinitions []oscalTypes_1_1_3.ImportComponentDefinition
	if err := ctx.Bind(&importComponentDefinitions); err != nil {
		h.sugar.Warnw("Failed to bind import component definitions", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Begin a transaction
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// Convert to relational model
	var newImportDefs []relational.ImportComponentDefinition
	for _, importDef := range importComponentDefinitions {
		relationalImportDef := relational.ImportComponentDefinition{}
		relationalImportDef.UnmarshalOscal(importDef)
		newImportDefs = append(newImportDefs, relationalImportDef)
	}

	// Append new import definitions to existing ones
	existingImports := componentDefinition.ImportComponentDefinitions
	updatedImports := append(existingImports, newImportDefs...)

	// Update the component definition with the new import definitions
	if err := tx.Model(&componentDefinition).Update("import_component_definitions", updatedImports).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update import component definitions: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata
	now := time.Now()
	metadataUpdates := &relational.Metadata{
		LastModified: &now,
		OscalVersion: versioning.GetLatestSupportedVersion(),
	}
	if err := tx.Model(&relational.Metadata{}).Where("id = ?", componentDefinition.Metadata.ID).Updates(metadataUpdates).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ImportComponentDefinition]{
		Data: importComponentDefinitions,
	})
}

// UpdateImportComponentDefinitions godoc
//
//	@Summary		Update import component definitions for a component definition
//	@Description	Updates the import component definitions for a given component definition.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id								path		string											true	"Component Definition ID"
//	@Param			import-component-definitions	body		[]oscalTypes_1_1_3.ImportComponentDefinition	true	"Import Component Definitions"
//	@Success		200								{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ImportComponentDefinition]
//	@Failure		400								{object}	api.Error
//	@Failure		401								{object}	api.Error
//	@Failure		404								{object}	api.Error
//	@Failure		500								{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/import-component-definitions [put]
func (h *ComponentDefinitionHandler) UpdateImportComponentDefinitions(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var importComponentDefinitions []oscalTypes_1_1_3.ImportComponentDefinition
	if err := ctx.Bind(&importComponentDefinitions); err != nil {
		h.sugar.Warnw("Failed to bind import component definitions", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Begin a transaction
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// Convert to relational model
	var newImportDefs []relational.ImportComponentDefinition
	for _, importDef := range importComponentDefinitions {
		relationalImportDef := relational.ImportComponentDefinition{}
		relationalImportDef.UnmarshalOscal(importDef)
		newImportDefs = append(newImportDefs, relationalImportDef)
	}

	// Wrap in JSONSlice for GORM
	jsonSlice := datatypes.NewJSONSlice[relational.ImportComponentDefinition](newImportDefs)

	// Update the import component definitions
	if err := tx.Model(&componentDefinition).Update("import_component_definitions", jsonSlice).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update import component definitions: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata
	now := time.Now()
	metadataUpdates := &relational.Metadata{
		LastModified: &now,
		OscalVersion: versioning.GetLatestSupportedVersion(),
	}
	if err := tx.Model(&relational.Metadata{}).Where("id = ?", componentDefinition.Metadata.ID).Updates(metadataUpdates).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ImportComponentDefinition]{
		Data: importComponentDefinitions,
	})
}

// GetComponents godoc
//
//	@Summary		Get components for a component definition
//	@Description	Retrieves all components for a given component definition.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id	path		string	true	"Component Definition ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.DefinedComponent]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/components [get]
func (h *ComponentDefinitionHandler) GetComponents(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.
		Preload("Components").
		First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	oscalComponents := make([]oscalTypes_1_1_3.DefinedComponent, len(componentDefinition.Components))
	for i, component := range componentDefinition.Components {
		oscalComponents[i] = *component.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.DefinedComponent]{Data: oscalComponents})
}

// CreateComponents godoc
//
//	@Summary		Create components for a component definition
//	@Description	Creates new components for a given component definition.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string								true	"Component Definition ID"
//	@Param			components	body		[]oscalTypes_1_1_3.DefinedComponent	true	"Components to create"
//	@Success		200			{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.DefinedComponent]
//	@Failure		400			{object}	api.Error
//	@Failure		401			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/components [post]
func (h *ComponentDefinitionHandler) CreateComponents(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var components []oscalTypes_1_1_3.DefinedComponent
	if err := ctx.Bind(&components); err != nil {
		h.sugar.Warnw("Failed to bind components", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate required fields for each component
	for _, component := range components {
		if component.Type == "" {
			return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("component type is required")))
		}
		if component.Title == "" {
			return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("component title is required")))
		}
		if component.Description == "" {
			return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("component description is required")))
		}
		if component.Purpose == "" {
			return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("component purpose is required")))
		}
	}

	// Begin a transaction
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// Convert to relational model
	var newComponents []relational.DefinedComponent
	for _, component := range components {
		relationalComponent := relational.DefinedComponent{}
		relationalComponent.UnmarshalOscal(component)
		relationalComponent.ComponentDefinitionID = &id
		newComponents = append(newComponents, relationalComponent)
	}

	// Create each component individually
	for _, component := range newComponents {
		if err := tx.Create(&component).Error; err != nil {
			tx.Rollback()
			h.sugar.Errorf("Failed to create component: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Update metadata
	now := time.Now()
	metadataUpdates := &relational.Metadata{
		LastModified: &now,
		OscalVersion: versioning.GetLatestSupportedVersion(),
	}
	if err := tx.Model(&relational.Metadata{}).Where("id = ?", componentDefinition.Metadata.ID).Updates(metadataUpdates).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.DefinedComponent]{
		Data: components,
	})
}

// UpdateComponents godoc
//
//	@Summary		Update components for a component definition
//	@Description	Updates the components for a given component definition.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string								true	"Component Definition ID"
//	@Param			components	body		[]oscalTypes_1_1_3.DefinedComponent	true	"Components to update"
//	@Success		200			{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.DefinedComponent]
//	@Failure		400			{object}	api.Error
//	@Failure		401			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/components [put]
func (h *ComponentDefinitionHandler) UpdateComponents(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalComponents []oscalTypes_1_1_3.DefinedComponent
	if err := ctx.Bind(&oscalComponents); err != nil {
		h.sugar.Warnw("Failed to bind components", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Begin a transaction to ensure data consistency
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// Update each component individually to preserve existing data
	for _, oscalComponent := range oscalComponents {
		relationalComponent := relational.DefinedComponent{}
		relationalComponent.UnmarshalOscal(oscalComponent)
		relationalComponent.ComponentDefinitionID = &id

		// Check if the component exists first
		var existingComponent relational.DefinedComponent
		result := tx.First(&existingComponent, "id = ?", relationalComponent.ID)

		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				// Component doesn't exist, create it
				if err := tx.Create(&relationalComponent).Error; err != nil {
					tx.Rollback()
					h.sugar.Errorf("Failed to create new component: %v", err)
					return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
				}
			} else {
				tx.Rollback()
				h.sugar.Errorf("Failed to check if component exists: %v", result.Error)
				return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
			}
		} else {
			// Component exists, update it using a map instead of struct to handle zero values
			updateFields := map[string]any{
				"component_definition_id": id,
				"title":                   relationalComponent.Title,
				"description":             relationalComponent.Description,
				"purpose":                 relationalComponent.Purpose,
				"type":                    relationalComponent.Type,
				"remarks":                 relationalComponent.Remarks,
			}

			// Include related elements if they exist
			if relationalComponent.Props != nil {
				updateFields["props"] = relationalComponent.Props
			}
			if relationalComponent.Links != nil {
				updateFields["links"] = relationalComponent.Links
			}
			if relationalComponent.ResponsibleRoles != nil {
				updateFields["responsible_roles"] = relationalComponent.ResponsibleRoles
			}
			if relationalComponent.Protocols != nil {
				updateFields["protocols"] = relationalComponent.Protocols
			}

			if err := tx.Model(&relational.DefinedComponent{}).Where("id = ?", relationalComponent.ID).Updates(updateFields).Error; err != nil {
				tx.Rollback()
				h.sugar.Errorf("Failed to update component: %v", err)
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
		}
	}

	// Update metadata
	now := time.Now()
	metadataUpdates := &relational.Metadata{
		LastModified: &now,
		OscalVersion: versioning.GetLatestSupportedVersion(),
	}
	if err := tx.Model(&relational.Metadata{}).Where("id = ?", componentDefinition.Metadata.ID).Updates(metadataUpdates).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.DefinedComponent]{
		Data: oscalComponents,
	})
}

// GetDefinedComponent godoc
//
//	@Summary		Get a defined component for a component definition
//	@Description	Retrieves a defined component for a given component definition.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id					path		string	true	"Component Definition ID"
//	@Param			defined-component	path		string	true	"Defined Component ID"
//	@Success		200					{object}	handler.GenericDataResponse[oscalTypes_1_1_3.DefinedComponent]
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/components/{defined-component} [get]
func (h *ComponentDefinitionHandler) GetDefinedComponent(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.
		Preload("Components").
		First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	definedComponentID := ctx.Param("defined-component")
	var definedComponent relational.DefinedComponent
	if err := h.db.
		Preload("ControlImplementations").
		First(&definedComponent, "id = ?", definedComponentID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load defined component", "id", definedComponentID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.DefinedComponent]{Data: *definedComponent.MarshalOscal()})
}

// CreateDefinedComponent godoc
//
//	@Summary		Create a defined component for a component definition
//	@Description	Creates a new defined component for a given component definition.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id					path		string								true	"Component Definition ID"
//	@Param			defined-component	body		oscalTypes_1_1_3.DefinedComponent	true	"Defined Component to create"
//	@Success		200					{object}	handler.GenericDataResponse[oscalTypes_1_1_3.DefinedComponent]
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/components/{defined-component} [post]
func (h *ComponentDefinitionHandler) CreateDefinedComponent(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalDefinedComponent oscalTypes_1_1_3.DefinedComponent
	if err := ctx.Bind(&oscalDefinedComponent); err != nil {
		h.sugar.Warnw("Failed to bind defined component", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate required fields
	if oscalDefinedComponent.Type == "" || oscalDefinedComponent.Title == "" {
		h.sugar.Warnw("Missing required fields in defined component", "component", oscalDefinedComponent)
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("type and title are required fields")))
	}

	// Begin transaction
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// Convert OSCAL to relational model
	relationalComponent := relational.DefinedComponent{}
	relationalComponent.UnmarshalOscal(oscalDefinedComponent)

	// Create the defined component
	if err := tx.Create(&relationalComponent).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to create defined component: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata
	now := time.Now()
	metadataUpdates := &relational.Metadata{
		LastModified: &now,
		OscalVersion: versioning.GetLatestSupportedVersion(),
	}
	if err := tx.Model(&componentDefinition.Metadata).Where("id = ?", componentDefinition.Metadata.ID).Updates(metadataUpdates).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.DefinedComponent]{
		Data: oscalDefinedComponent,
	})
}

// UpdateDefinedComponent godoc
//
//	@Summary		Update a defined component for a component definition
//	@Description	Updates a defined component for a given component definition.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id					path		string								true	"Component Definition ID"
//	@Param			defined-component	path		string								true	"Defined Component ID"
//	@Param			defined-component	body		oscalTypes_1_1_3.DefinedComponent	true	"Defined Component to update"
//	@Success		200					{object}	handler.GenericDataResponse[oscalTypes_1_1_3.DefinedComponent]
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/components/{defined-component} [put]
func (h *ComponentDefinitionHandler) UpdateDefinedComponent(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	definedComponentID := ctx.Param("defined-component")
	var definedComponent relational.DefinedComponent
	if err := h.db.First(&definedComponent, "id = ?", definedComponentID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load defined component", "id", definedComponentID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalDefinedComponent oscalTypes_1_1_3.DefinedComponent
	if err := ctx.Bind(&oscalDefinedComponent); err != nil {
		h.sugar.Warnw("Failed to bind defined component", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Begin a transaction
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// Update only the fields that are provided in the request
	definedComponent.UnmarshalOscal(oscalDefinedComponent)
	definedComponent.ComponentDefinitionID = &id // Ensure proper association

	// Convert struct to map for updates to properly handle zero values
	updateFields := map[string]any{
		"component_definition_id": id,
		"title":                   definedComponent.Title,
		"description":             definedComponent.Description,
		"purpose":                 definedComponent.Purpose,
		"type":                    definedComponent.Type,
		"remarks":                 definedComponent.Remarks,
	}

	// Include related elements if they exist
	if definedComponent.Props != nil {
		updateFields["props"] = definedComponent.Props
	}
	if definedComponent.Links != nil {
		updateFields["links"] = definedComponent.Links
	}
	if definedComponent.ResponsibleRoles != nil {
		updateFields["responsible_roles"] = definedComponent.ResponsibleRoles
	}
	if definedComponent.Protocols != nil {
		updateFields["protocols"] = definedComponent.Protocols
	}

	// Use explicit WHERE clause with the primary key
	if err := tx.Model(&relational.DefinedComponent{}).Where("id = ?", definedComponentID).Updates(updateFields).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update defined component: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata
	now := time.Now()
	metadataUpdates := &relational.Metadata{
		LastModified: &now,
		OscalVersion: versioning.GetLatestSupportedVersion(),
	}
	if err := tx.Model(&componentDefinition.Metadata).Where("id = ?", componentDefinition.Metadata.ID).Updates(metadataUpdates).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.DefinedComponent]{Data: *definedComponent.MarshalOscal()})
}

// GetControlImplementations godoc
//
//	@Summary		Get control implementations for a defined component
//	@Description	Retrieves all control implementations for a given defined component.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id					path		string	true	"Component Definition ID"
//	@Param			defined-component	path		string	true	"Defined Component ID"
//	@Success		200					{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ControlImplementationSet]
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/components/{defined-component}/control-implementations [get]
func (h *ComponentDefinitionHandler) GetControlImplementations(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.Preload("Capabilities").First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	definedComponentID := ctx.Param("defined-component")
	var definedComponent relational.DefinedComponent
	if err := h.db.First(&definedComponent, "id = ?", definedComponentID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load defined component", "id", definedComponentID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Get the control implementation set IDs from the join table
	var controlImplSetIDs []string
	if err := h.db.Table("defined_components_control_implementation_sets").
		Where("defined_component_id = ?", definedComponentID).
		Pluck("control_implementation_set_id", &controlImplSetIDs).Error; err != nil {
		h.sugar.Warnw("Failed to load control implementation set IDs", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Create a result array for valid control implementation sets
	var oscalControlImplementations []oscalTypes_1_1_3.ControlImplementationSet

	// For each control implementation set ID, try to load and marshal it
	for _, controlImplSetID := range controlImplSetIDs {
		var controlImplSet relational.ControlImplementationSet

		// Try to get the control implementation set and preload its implemented requirements
		if err := h.db.
			Preload("ImplementedRequirements").
			Preload("ImplementedRequirements.Statements").
			First(&controlImplSet, "id = ?", controlImplSetID).Error; err != nil {
			// Log the error but continue with other control implementation sets
			h.sugar.Warnw("Failed to load control implementation set", "id", controlImplSetID, "error", err)
			continue
		}

		// Try to marshal it to OSCAL format
		oscalImpl := controlImplSet.MarshalOscal()
		if oscalImpl != nil {
			oscalControlImplementations = append(oscalControlImplementations, *oscalImpl)
		}
	}

	// Ensure we always return an array, even if empty
	if oscalControlImplementations == nil {
		oscalControlImplementations = []oscalTypes_1_1_3.ControlImplementationSet{}
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ControlImplementationSet]{
		Data: oscalControlImplementations,
	})
}

// CreateControlImplementations godoc
//
//	@Summary		Create control implementations for a defined component
//	@Description	Creates new control implementations for a given defined component.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id						path		string										true	"Component Definition ID"
//	@Param			defined-component		path		string										true	"Defined Component ID"
//	@Param			control-implementations	body		[]oscalTypes_1_1_3.ControlImplementationSet	true	"Control Implementations"
//	@Success		200						{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ControlImplementationSet]
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		404						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/components/{defined-component}/control-implementations [post]
func (h *ComponentDefinitionHandler) CreateControlImplementations(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	definedComponentID := ctx.Param("defined-component")
	var definedComponent relational.DefinedComponent
	if err := h.db.First(&definedComponent, "id = ?", definedComponentID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load defined component", "id", definedComponentID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var controlImplementations []oscalTypes_1_1_3.ControlImplementationSet
	if err := ctx.Bind(&controlImplementations); err != nil {
		h.sugar.Warnw("Failed to bind control implementations", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Begin a transaction
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// Convert to relational model
	var newControlImpls []relational.ControlImplementationSet
	for _, controlImpl := range controlImplementations {
		relationalControlImpl := relational.ControlImplementationSet{}
		relationalControlImpl.UnmarshalOscal(controlImpl)
		newControlImpls = append(newControlImpls, relationalControlImpl)
	}

	// Create the control implementations and associate them with the defined component
	if err := tx.Model(&definedComponent).Association("ControlImplementations").Append(newControlImpls); err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to create control implementations: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ControlImplementationSet]{
		Data: controlImplementations,
	})
}

// GetImplementedRequirements godoc
//
//	@Summary		Get implemented requirements for a defined component
//	@Description	Retrieves all implemented requirements for a given defined component.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id					path		string	true	"Component Definition ID"
//	@Param			defined-component	path		string	true	"Defined Component ID"
//	@Success		200					{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ImplementedRequirementControlImplementation]
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/components/{defined-component}/control-implementations/implemented-requirements [get]
func (h *ComponentDefinitionHandler) GetImplementedRequirements(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	definedComponentID := ctx.Param("defined-component")
	var definedComponent relational.DefinedComponent
	if err := h.db.
		Preload("ControlImplementations").
		Preload("ControlImplementations.ImplementedRequirements").
		First(&definedComponent, "id = ?", definedComponentID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load defined component", "id", definedComponentID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalImplementedRequirements []oscalTypes_1_1_3.ImplementedRequirementControlImplementation
	for _, controlImpl := range definedComponent.ControlImplementations {
		for _, implementedRequirement := range controlImpl.ImplementedRequirements {
			oscalImplementedRequirements = append(oscalImplementedRequirements, *implementedRequirement.MarshalOscal())
		}
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ImplementedRequirementControlImplementation]{Data: oscalImplementedRequirements})
}

// // CreateImplementedRequirements godoc
// //
// //	@Summary		Create implemented requirements for a control implementation
// //	@Description	Creates new implemented requirements for a given control implementation.
// //	@Tags			Oscal
// //	@Accept			json
// //	@Produce		json
// //	@Param			id							path		string															true	"Component Definition ID"
// //	@Param			defined-component			path		string															true	"Defined Component ID"
// //	@Param			implemented-requirements	body		[]oscalTypes_1_1_3.ImplementedRequirementControlImplementation	true	"Implemented Requirements"
// //	@Success		200							{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ImplementedRequirementControlImplementation]
// //	@Failure		400							{object}	api.Error
//	@Failure	401	{object}	api.Error
// //	@Failure		404							{object}	api.Error
// //	@Failure		500							{object}	api.Error
// //  @Security		OAuth2Password
// //	@Router			/oscal/component-definitions/{id}/components/{defined-component}/control-implementations/implemented-requirements [post]
// func (h *ComponentDefinitionHandler) CreateImplementedRequirements(ctx echo.Context) error {
// 	idParam := ctx.Param("id")
// 	id, err := uuid.Parse(idParam)
// 	if err != nil {
// 		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
// 		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
// 	}

// 	var componentDefinition relational.ComponentDefinition
// 	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return ctx.JSON(http.StatusNotFound, api.NewError(err))
// 		}
// 		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
// 		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
// 	}

// 	definedComponentID := ctx.Param("defined-component")
// 	var definedComponent relational.DefinedComponent
// 	if err := h.db.First(&definedComponent, "id = ?", definedComponentID).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return ctx.JSON(http.StatusNotFound, api.NewError(err))
// 		}
// 		h.sugar.Warnw("Failed to load defined component", "id", definedComponentID, "error", err)
// 		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
// 	}

// 	var implementedRequirements []oscalTypes_1_1_3.ImplementedRequirementControlImplementation
// 	if err := ctx.Bind(&implementedRequirements); err != nil {
// 		h.sugar.Warnw("Failed to bind implemented requirements", "error", err)
// 		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
// 	}

// 	// Begin a transaction
// 	tx := h.db.Begin()
// 	if tx.Error != nil {
// 		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
// 		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
// 	}

// 	// Convert to relational model
// 	var newImplementedReqs []relational.ImplementedRequirementControlImplementation
// 	for _, implReq := range implementedRequirements {
// 		relationalImplReq := relational.ImplementedRequirementControlImplementation{}
// 		relationalImplReq.UnmarshalOscal(implReq)
// 		newImplementedReqs = append(newImplementedReqs, relationalImplReq)
// 	}

// 	// Create the implemented requirements
// 	for _, implReq := range newImplementedReqs {
// 		if err := tx.Create(&implReq).Error; err != nil {
// 			tx.Rollback()
// 			h.sugar.Errorf("Failed to create implemented requirement: %v", err)
// 			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
// 		}
// 	}

// 	// Commit the transaction
// 	if err := tx.Commit().Error; err != nil {
// 		h.sugar.Errorf("Failed to commit transaction: %v", err)
// 		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
// 	}

// 	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ImplementedRequirementControlImplementation]{
// 		Data: implementedRequirements,
// 	})
// }

// GetStatements godoc
//
//	@Summary		Get statements for a defined component
//	@Description	Retrieves all statements for a given defined component.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id					path		string	true	"Component Definition ID"
//	@Param			defined-component	path		string	true	"Defined Component ID"
//	@Success		200					{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ControlStatementImplementation]
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		404					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/components/{defined-component}/control-implementations/implemented-requirements/statements [get]
func (h *ComponentDefinitionHandler) GetStatements(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	definedComponentID := ctx.Param("defined-component")
	var definedComponent relational.DefinedComponent
	if err := h.db.
		Preload("ControlImplementations").
		Preload("ControlImplementations.ImplementedRequirements").
		Preload("ControlImplementations.ImplementedRequirements.Statements").
		First(&definedComponent, "id = ?", definedComponentID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load defined component", "id", definedComponentID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalStatements []oscalTypes_1_1_3.ControlStatementImplementation
	for _, controlImpl := range definedComponent.ControlImplementations {
		for _, implementedReq := range controlImpl.ImplementedRequirements {
			for _, stmt := range implementedReq.Statements {
				oscalStatements = append(oscalStatements, *stmt.MarshalOscal())
			}
		}
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ControlStatementImplementation]{Data: oscalStatements})
}

// // CreateStatements godoc
// //
// //	@Summary		Create statements for a control implementation
// //	@Description	Creates new statements for a given control implementation.
// //	@Tags			Oscal
// //	@Accept			json
// //	@Produce		json
// //	@Param			id						path		string												true	"Component Definition ID"
// //	@Param			defined-component		path		string												true	"Defined Component ID"
// //	@Param			control-implementation	path		string												true	"Control Implementation ID"
// //	@Param			implemented-requirement	path		string												true	"Implemented Requirement ID"
// //	@Param			statements				body		[]oscalTypes_1_1_3.ControlStatementImplementation	true	"Statements"
// //	@Success		200						{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ControlStatementImplementation]
// //	@Failure		400						{object}	api.Error
// //	@Failure		401		{object}	api.Error
// //	@Failure		404						{object}	api.Error
// //	@Failure		500						{object}	api.Error
// //  @Security		OAuth2Password
// //	@Router			/oscal/component-definitions/{id}/components/{defined-component}/control-implementations/statements [post]
// func (h *ComponentDefinitionHandler) CreateStatements(ctx echo.Context) error {
// 	idParam := ctx.Param("id")
// 	id, err := uuid.Parse(idParam)
// 	if err != nil {
// 		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
// 		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
// 	}

// 	var componentDefinition relational.ComponentDefinition
// 	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return ctx.JSON(http.StatusNotFound, api.NewError(err))
// 		}
// 		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
// 		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
// 	}

// 	definedComponentID := ctx.Param("defined-component")
// 	var definedComponent relational.DefinedComponent
// 	if err := h.db.First(&definedComponent, "id = ?", definedComponentID).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return ctx.JSON(http.StatusNotFound, api.NewError(err))
// 		}
// 		h.sugar.Warnw("Failed to load defined component", "id", definedComponentID, "error", err)
// 		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
// 	}

// 	controlImplementationID := ctx.Param("control-implementation")
// 	var controlImplementation relational.ControlImplementation
// 	if err := h.db.First(&controlImplementation, "id = ?", controlImplementationID).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return ctx.JSON(http.StatusNotFound, api.NewError(err))
// 		}
// 		h.sugar.Warnw("Failed to load control implementation", "id", controlImplementationID, "error", err)
// 		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
// 	}

// 	implementedRequirementID := ctx.Param("implemented-requirement")
// 	var implementedRequirement relational.ImplementedRequirement
// 	if err := h.db.First(&implementedRequirement, "id = ?", implementedRequirementID).Error; err != nil {
// 		if errors.Is(err, gorm.ErrRecordNotFound) {
// 			return ctx.JSON(http.StatusNotFound, api.NewError(err))
// 		}
// 		h.sugar.Warnw("Failed to load implemented requirement", "id", implementedRequirementID, "error", err)
// 		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
// 	}

// 	var statements []oscalTypes_1_1_3.ControlStatementImplementation
// 	if err := ctx.Bind(&statements); err != nil {
// 		h.sugar.Warnw("Failed to bind statements", "error", err)
// 		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
// 	}

// 	// Begin a transaction
// 	tx := h.db.Begin()
// 	if tx.Error != nil {
// 		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
// 		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
// 	}

// 	// Convert to relational model
// 	var newStatements []relational.ControlStatementImplementation
// 	for _, statement := range statements {
// 		relationalStatement := relational.ControlStatementImplementation{}
// 		relationalStatement.UnmarshalOscal(statement)
// 		relationalStatement.ImplementedRequirementControlImplementationId = *implementedRequirement.ID
// 		newStatements = append(newStatements, relationalStatement)
// 	}

// 	// Create the statements
// 	for _, statement := range newStatements {
// 		if err := tx.Create(&statement).Error; err != nil {
// 			tx.Rollback()
// 			h.sugar.Errorf("Failed to create statement: %v", err)
// 			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
// 		}
// 	}

// 	// Commit the transaction
// 	if err := tx.Commit().Error; err != nil {
// 		h.sugar.Errorf("Failed to commit transaction: %v", err)
// 		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
// 	}

// 	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ControlStatementImplementation]{
// 		Data: statements,
// 	})
// }

// GetCapabilities godoc
//
//	@Summary		Get capabilities for a component definition
//	@Description	Retrieves all capabilities for a given component definition.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id	path		string	true	"Component Definition ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Capability]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/capabilities [get]
func (h *ComponentDefinitionHandler) GetCapabilities(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.
		Preload("Capabilities").
		First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	oscalCapabilities := make([]oscalTypes_1_1_3.Capability, len(componentDefinition.Capabilities))
	for i, capability := range componentDefinition.Capabilities {
		oscalCapabilities[i] = *capability.MarshalOscal()
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Capability]{Data: oscalCapabilities})
}

// CreateCapabilities godoc
//
//	@Summary		Create capabilities for a component definition
//	@Description	Creates new capabilities for a given component definition.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id				path		string							true	"Component Definition ID"
//	@Param			capabilities	body		[]oscalTypes_1_1_3.Capability	true	"Capabilities"
//	@Success		200				{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Capability]
//	@Failure		400				{object}	api.Error
//	@Failure		401				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/capabilities [post]
func (h *ComponentDefinitionHandler) CreateCapabilities(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var capabilities []oscalTypes_1_1_3.Capability
	if err := ctx.Bind(&capabilities); err != nil {
		h.sugar.Warnw("Failed to bind capabilities", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate required fields
	for _, capability := range capabilities {
		if capability.Name == "" {
			return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("capability name is required")))
		}
		if capability.Description == "" {
			return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("capability description is required")))
		}
		if capability.ControlImplementations != nil {
			for _, impl := range *capability.ControlImplementations {
				if impl.Description == "" {
					return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("control implementation description is required")))
				}
				for _, req := range impl.ImplementedRequirements {
					if req.ControlId == "" {
						return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("control ID is required")))
					}
				}
			}
		}
		if capability.IncorporatesComponents != nil {
			for _, component := range *capability.IncorporatesComponents {
				if component.ComponentUuid == "" {
					return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("component UUID is required for incorporates component")))
				}
				if component.Description == "" {
					return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("description is required for incorporates component")))
				}
			}
		}
	}

	// Begin a transaction
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// Convert to relational model
	var newCapabilities []relational.Capability
	for _, capability := range capabilities {
		relationalCapability := relational.Capability{}
		relationalCapability.UnmarshalOscal(capability)
		relationalCapability.ComponentDefinitionId = id
		newCapabilities = append(newCapabilities, relationalCapability)
	}

	// Create the capabilities
	for _, capability := range newCapabilities {
		if err := tx.Create(&capability).Error; err != nil {
			tx.Rollback()
			h.sugar.Errorf("Failed to create capability: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Capability]{
		Data: capabilities,
	})
}

// GetIncorporatesComponents godoc
//
//	@Summary		Get incorporates components for a component definition
//	@Description	Retrieves all incorporates components for a given component definition.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id	path		string	true	"Component Definition ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.IncorporatesComponent]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/capabilities/incorporates-components [get]
func (h *ComponentDefinitionHandler) GetIncorporatesComponents(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.
		Preload("Capabilities").
		First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Debug logging
	h.sugar.Infow("Loaded component definition",
		"id", id,
		"capabilities_count", len(componentDefinition.Capabilities))

	var oscalIncorporatesComponents []oscalTypes_1_1_3.IncorporatesComponent
	for _, capability := range componentDefinition.Capabilities {
		h.sugar.Infow("Processing capability",
			"capability_id", capability.ID,
			"incorporates_components", capability.IncorporatesComponents)

		for _, component := range capability.IncorporatesComponents {
			oscalIncorporatesComponents = append(oscalIncorporatesComponents, oscalTypes_1_1_3.IncorporatesComponent(component))
		}
	}

	// Debug logging
	h.sugar.Infow("Returning incorporates components",
		"count", len(oscalIncorporatesComponents),
		"components", oscalIncorporatesComponents)

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.IncorporatesComponent]{Data: oscalIncorporatesComponents})
}

// CreateIncorporatesComponents godoc
//
//	@Summary		Create incorporates components for a component definition
//	@Description	Creates new incorporates components for a given component definition.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id						path		string										true	"Component Definition ID"
//	@Param			incorporates-components	body		[]oscalTypes_1_1_3.IncorporatesComponent	true	"Incorporates Components"
//	@Success		200						{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.IncorporatesComponent]
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		404						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/capabilities/incorporates-components [post]
func (h *ComponentDefinitionHandler) CreateIncorporatesComponents(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var incorporatesComponents []oscalTypes_1_1_3.IncorporatesComponent
	if err := ctx.Bind(&incorporatesComponents); err != nil {
		h.sugar.Warnw("Failed to bind incorporates components", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Begin a transaction
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// Convert to relational model
	var newIncorporatesComponents []relational.IncorporatesComponents
	for _, component := range incorporatesComponents {
		relationalComponent := relational.IncorporatesComponents{}
		relationalComponent.UnmarshalOscal(component)
		newIncorporatesComponents = append(newIncorporatesComponents, relationalComponent)
	}

	// Create the incorporates components
	for _, component := range newIncorporatesComponents {
		if err := tx.Create(&component).Error; err != nil {
			tx.Rollback()
			h.sugar.Errorf("Failed to create incorporates component: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.IncorporatesComponent]{
		Data: incorporatesComponents,
	})
}

// GetBackMatter godoc
//
//	@Summary		Get back-matter for a Component Definition
//	@Description	Retrieves the back-matter for a given Component Definition.
//	@Tags			Oscal
//	@Produce		json
//	@Param			id	path		string	true	"Component Definition ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/back-matter [get]
func (h *ComponentDefinitionHandler) GetBackMatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.
		Preload("BackMatter").
		Preload("BackMatter.Resources").
		First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	//handler.GenericDataResponse[struct {
	//			UUID     uuid.UUID           `json:"uuid"`
	//			Metadata relational.Metadata `json:"metadata"`
	//		}]{}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.BackMatter]{Data: componentDefinition.BackMatter.MarshalOscal()})
}

// CreateBackMatter godoc
//
//	@Summary		Create back-matter for a component definition
//	@Description	Creates new back-matter for a given component definition.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Component Definition ID"
//	@Param			back-matter	body		oscalTypes_1_1_3.BackMatter	true	"Back Matter"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
//	@Failure		400			{object}	api.Error
//	@Failure		401			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/back-matter [post]
func (h *ComponentDefinitionHandler) CreateBackMatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var backMatter oscalTypes_1_1_3.BackMatter
	if err := ctx.Bind(&backMatter); err != nil {
		h.sugar.Warnw("Failed to bind back-matter", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate required fields for each resource
	if backMatter.Resources != nil {
		for i, resource := range *backMatter.Resources {
			if resource.Title == "" {
				errMsg := fmt.Sprintf("resource at index %d is missing required field: title", i)
				h.sugar.Warnw(errMsg)
				return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New(errMsg)))
			}
			if resource.Description == "" {
				errMsg := fmt.Sprintf("resource at index %d is missing required field: description", i)
				h.sugar.Warnw(errMsg)
				return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New(errMsg)))
			}
		}
	}

	// Begin a transaction
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// Convert to relational model
	relationalBackMatter := relational.BackMatter{}
	relationalBackMatter.UnmarshalOscal(backMatter)

	// Set the parent relationship
	parentID := componentDefinition.UUIDModel.ID.String()
	relationalBackMatter.ParentID = &parentID
	parentType := "ComponentDefinition"
	relationalBackMatter.ParentType = &parentType

	// Create the back-matter
	if err := tx.Create(&relationalBackMatter).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to create back-matter: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update the component definition's back matter association
	if err := tx.Model(&componentDefinition).Association("BackMatter").Replace(&relationalBackMatter); err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update component definition with back-matter: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]{
		Data: backMatter,
	})
}

// UpdateControlImplementations godoc
//
//	@Summary		Update control implementations for a defined component
//	@Description	Updates control implementations for a given defined component.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id						path		string										true	"Component Definition ID"
//	@Param			defined-component		path		string										true	"Defined Component ID"
//	@Param			control-implementations	body		[]oscalTypes_1_1_3.ControlImplementationSet	true	"Control Implementations"
//	@Success		200						{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.ControlImplementationSet]
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		404						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/components/{defined-component}/control-implementations [put]
func (h *ComponentDefinitionHandler) UpdateControlImplementations(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	definedComponentID := ctx.Param("defined-component")
	var definedComponent relational.DefinedComponent
	if err := h.db.First(&definedComponent, "id = ?", definedComponentID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load defined component", "id", definedComponentID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var controlImplementations []oscalTypes_1_1_3.ControlImplementationSet
	if err := ctx.Bind(&controlImplementations); err != nil {
		h.sugar.Warnw("Failed to bind control implementations", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Begin a transaction
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// Convert to relational model
	var newControlImpls []relational.ControlImplementationSet
	for _, controlImpl := range controlImplementations {
		relationalControlImpl := relational.ControlImplementationSet{}
		relationalControlImpl.UnmarshalOscal(controlImpl)
		newControlImpls = append(newControlImpls, relationalControlImpl)
	}

	// Clear existing control implementations and add new ones
	if err := tx.Model(&definedComponent).Association("ControlImplementations").Clear(); err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to clear existing control implementations: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := tx.Model(&definedComponent).Association("ControlImplementations").Append(newControlImpls); err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update control implementations: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata
	now := time.Now()
	metadataUpdates := &relational.Metadata{
		LastModified: &now,
		OscalVersion: versioning.GetLatestSupportedVersion(),
	}
	if err := tx.Model(&relational.Metadata{}).Where("id = ?", componentDefinition.Metadata.ID).Updates(metadataUpdates).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.ControlImplementationSet]{
		Data: controlImplementations,
	})
}

// UpdateSingleControlImplementation godoc
//
//	@Summary		Update a single control implementation for a defined component
//	@Description	Updates a specific control implementation for a given defined component.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id						path		string										true	"Component Definition ID"
//	@Param			defined-component		path		string										true	"Defined Component ID"
//	@Param			control-implementation	path		string										true	"Control Implementation ID"
//	@Param			control-implementation	body		oscalTypes_1_1_3.ControlImplementationSet	true	"Control Implementation"
//	@Success		200						{object}	handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementationSet]
//	@Failure		400						{object}	api.Error
//	@Failure		401						{object}	api.Error
//	@Failure		404						{object}	api.Error
//	@Failure		500						{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/components/{defined-component}/control-implementations/{control-implementation} [put]
func (h *ComponentDefinitionHandler) UpdateSingleControlImplementation(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	definedComponentID := ctx.Param("defined-component")
	var definedComponent relational.DefinedComponent
	if err := h.db.First(&definedComponent, "id = ?", definedComponentID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load defined component", "id", definedComponentID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	controlImplID := ctx.Param("control-implementation")
	var existingControlImpl relational.ControlImplementationSet
	if err := h.db.First(&existingControlImpl, "id = ?", controlImplID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load control implementation", "id", controlImplID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var controlImplementation oscalTypes_1_1_3.ControlImplementationSet
	if err := ctx.Bind(&controlImplementation); err != nil {
		h.sugar.Warnw("Failed to bind control implementation", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Begin a transaction
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// Convert to relational model
	relationalControlImpl := relational.ControlImplementationSet{}
	relationalControlImpl.UnmarshalOscal(controlImplementation)
	relationalControlImpl.ID = existingControlImpl.ID // Preserve the existing ID

	// Update the control implementation (only simple fields)
	if err := tx.Model(&relational.ControlImplementationSet{}).Where("id = ?", controlImplID).Updates(map[string]any{
		"source":         relationalControlImpl.Source,
		"description":    relationalControlImpl.Description,
		"set_parameters": relationalControlImpl.SetParameters,
		"props":          relationalControlImpl.Props,
		"links":          relationalControlImpl.Links,
	}).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update control implementation: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update metadata
	now := time.Now()
	metadataUpdates := &relational.Metadata{
		LastModified: &now,
		OscalVersion: versioning.GetLatestSupportedVersion(),
	}
	if err := tx.Model(&relational.Metadata{}).Where("id = ?", componentDefinition.Metadata.ID).Updates(metadataUpdates).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.ControlImplementationSet]{
		Data: controlImplementation,
	})
}

// UpdateCapability godoc
//
//	@Summary		Update a capability for a component definition
//	@Description	Updates a single capability for a given component definition.
//	@Tags			Oscal
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string						true	"Component Definition ID"
//	@Param			capability	path		string						true	"Capability ID (UUID)"
//	@Param			capability	body		oscalTypes_1_1_3.Capability	true	"Capability to update"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Capability]
//	@Failure		400			{object}	api.Error
//	@Failure		401			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/component-definitions/{id}/capabilities/{capability} [put]
func (h *ComponentDefinitionHandler) UpdateCapability(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid component definition id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	capabilityParam := ctx.Param("capability")
	capabilityID, err := uuid.Parse(capabilityParam)
	if err != nil {
		h.sugar.Warnw("Invalid capability id", "capability", capabilityParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var componentDefinition relational.ComponentDefinition
	if err := h.db.Preload("Capabilities").First(&componentDefinition, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load component definition", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var oscalCapability oscalTypes_1_1_3.Capability
	if err := ctx.Bind(&oscalCapability); err != nil {
		h.sugar.Warnw("Failed to bind capability", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Find the existing capability
	found := false
	for _, cap := range componentDefinition.Capabilities {
		if cap.UUIDModel.ID != nil && *cap.UUIDModel.ID == capabilityID {
			found = true
			break
		}
	}
	if !found {
		h.sugar.Warnw("Capability not found", "capability", capabilityParam)
		return ctx.JSON(http.StatusNotFound, api.NewError(errors.New("capability not found")))
	}

	// Unmarshal and update fields
	relationalCapability := relational.Capability{}
	relationalCapability.UnmarshalOscal(oscalCapability)
	relationalCapability.ID = &capabilityID
	relationalCapability.ComponentDefinitionId = id

	// Begin a transaction
	tx := h.db.Begin()
	if tx.Error != nil {
		h.sugar.Errorf("Failed to begin transaction: %v", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}

	// First, clear the existing many-to-many relationships
	if err := tx.Model(&relationalCapability).Association("ControlImplementations").Clear(); err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to clear control implementations: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Update the basic fields
	updateFields := map[string]any{
		"name":                    relationalCapability.Name,
		"description":             relationalCapability.Description,
		"remarks":                 relationalCapability.Remarks,
		"links":                   relationalCapability.Links,
		"props":                   relationalCapability.Props,
		"incorporates_components": relationalCapability.IncorporatesComponents,
	}

	if err := tx.Model(&relational.Capability{}).Where("id = ?", capabilityID).Updates(updateFields).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update capability: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Now add the new control implementations
	if len(relationalCapability.ControlImplementations) > 0 {
		if err := tx.Model(&relationalCapability).Association("ControlImplementations").Replace(relationalCapability.ControlImplementations); err != nil {
			tx.Rollback()
			h.sugar.Errorf("Failed to update control implementations: %v", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Update metadata
	now := time.Now()
	metadataUpdates := &relational.Metadata{
		LastModified: &now,
		OscalVersion: versioning.GetLatestSupportedVersion(),
	}
	if err := tx.Model(&relational.Metadata{}).Where("id = ?", componentDefinition.Metadata.ID).Updates(metadataUpdates).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to update metadata: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Capability]{Data: oscalCapability})
}
