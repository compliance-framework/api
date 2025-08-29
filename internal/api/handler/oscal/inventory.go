package oscal

import (
	"fmt"
	"net/http"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// InventoryHandler handles inventory-related endpoints
type InventoryHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

// NewInventoryHandler creates a new InventoryHandler
func NewInventoryHandler(sugar *zap.SugaredLogger, db *gorm.DB) *InventoryHandler {
	return &InventoryHandler{
		sugar: sugar,
		db:    db,
	}
}

// Register registers inventory routes
func (h *InventoryHandler) Register(api *echo.Group) {
	api.GET("", h.GetAllInventoryItems)
	api.GET("/:id", h.GetInventoryItem)
	api.POST("", h.CreateInventoryItem)
}

// InventoryItemWithSource represents an inventory item with its source information
type InventoryItemWithSource struct {
	oscalTypes_1_1_3.InventoryItem
	Source     string `json:"source"`
	SourceID   string `json:"source_id"`
	SourceType string `json:"source_type"`
}

// CreateInventoryItemRequest represents the request for creating an inventory item
type CreateInventoryItemRequest struct {
	Destination   string                          `json:"destination"` // "ssp", "poam", or "unattached"
	DestinationID string                          `json:"destination_id,omitempty"`
	InventoryItem oscalTypes_1_1_3.InventoryItem `json:"inventory_item"`
}

// GetAllInventoryItemsRequest represents the request for getting all inventory items
type GetAllInventoryItemsRequest struct {
	IncludeSSP      string `query:"include_ssp" json:"include_ssp,omitempty"`
	IncludeEvidence string `query:"include_evidence" json:"include_evidence,omitempty"`
	IncludePOAM     string `query:"include_poam" json:"include_poam,omitempty"`
	IncludeAP       string `query:"include_ap" json:"include_ap,omitempty"`
	IncludeAR       string `query:"include_ar" json:"include_ar,omitempty"`
	ItemType        string `query:"item_type" json:"item_type,omitempty"`
	AttachedToSSP   string `query:"attached_to_ssp" json:"attached_to_ssp,omitempty"`
}

// GetAllInventoryItems godoc
//
//	@Summary		Get All Inventory Items
//	@Description	Retrieves all inventory items from all sources (SSP, Evidence, POAM, AP, AR)
//	@Tags			Inventory
//	@Produce		json
//	@Param			include_ssp			query		string	false	"Include items from System Security Plans"
//	@Param			include_evidence	query		string	false	"Include items from Evidence"
//	@Param			include_poam		query		string	false	"Include items from Plan of Action and Milestones"
//	@Param			include_ap			query		string	false	"Include items from Assessment Plans"
//	@Param			include_ar			query		string	false	"Include items from Assessment Results"
//	@Param			item_type			query		string	false	"Filter by item type (e.g., operating-system, database, web-server)"
//	@Param			attached_to_ssp		query		string	false	"Filter by SSP attachment status"
//	@Success		200					{object}	handler.GenericDataListResponse[InventoryItemWithSource]
//	@Failure		400					{object}	api.Error
//	@Failure		401					{object}	api.Error
//	@Failure		500					{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/inventory [get]
func (h *InventoryHandler) GetAllInventoryItems(ctx echo.Context) error {
	// Get query parameters directly
	req := GetAllInventoryItemsRequest{
		IncludeSSP:      ctx.QueryParam("include_ssp"),
		IncludeEvidence: ctx.QueryParam("include_evidence"),
		IncludePOAM:     ctx.QueryParam("include_poam"),
		IncludeAP:       ctx.QueryParam("include_ap"),
		IncludeAR:       ctx.QueryParam("include_ar"),
		ItemType:        ctx.QueryParam("item_type"),
		AttachedToSSP:   ctx.QueryParam("attached_to_ssp"),
	}

	// Parse boolean values from strings
	includeSSP := req.IncludeSSP == "" || req.IncludeSSP == "true"
	includeEvidence := req.IncludeEvidence == "" || req.IncludeEvidence == "true"  
	includePOAM := req.IncludePOAM == "" || req.IncludePOAM == "true"
	includeAP := req.IncludeAP == "true"
	includeAR := req.IncludeAR == "true"

	// Default to including main sources if all are empty
	if req.IncludeSSP == "" && req.IncludeEvidence == "" && req.IncludePOAM == "" {
		includeSSP = true
		includeEvidence = true
		includePOAM = true
	}

	allItems := []InventoryItemWithSource{}

	// Fetch from SSPs
	if includeSSP {
		if err := h.fetchSSPInventoryItems(&allItems, req); err != nil {
			h.sugar.Errorw("Failed to fetch SSP inventory items", "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Fetch from Evidence
	if includeEvidence {
		if err := h.fetchEvidenceInventoryItems(&allItems, req); err != nil {
			h.sugar.Errorw("Failed to fetch Evidence inventory items", "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Fetch from POAMs
	if includePOAM {
		if err := h.fetchPOAMInventoryItems(&allItems, req); err != nil {
			h.sugar.Errorw("Failed to fetch POAM inventory items", "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Fetch from Assessment Plans
	if includeAP {
		if err := h.fetchAPInventoryItems(&allItems, req); err != nil {
			h.sugar.Errorw("Failed to fetch AP inventory items", "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Fetch from Assessment Results
	if includeAR {
		if err := h.fetchARInventoryItems(&allItems, req); err != nil {
			h.sugar.Errorw("Failed to fetch AR inventory items", "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	// Apply additional filters
	filteredItems := h.applyFilters(allItems, req)

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[InventoryItemWithSource]{
		Data: filteredItems,
	})
}

func (h *InventoryHandler) fetchSSPInventoryItems(items *[]InventoryItemWithSource, req GetAllInventoryItemsRequest) error {
	var ssps []relational.SystemSecurityPlan
	query := h.db.Preload("SystemImplementation.InventoryItems.ImplementedComponents")
	
	if err := query.Find(&ssps).Error; err != nil {
		return err
	}

	for _, ssp := range ssps {
		oscalSSP := ssp.MarshalOscal()
		if oscalSSP.SystemImplementation.InventoryItems == nil {
			continue
		}

		for _, item := range *oscalSSP.SystemImplementation.InventoryItems {
			*items = append(*items, InventoryItemWithSource{
				InventoryItem: item,
				Source:       "System Security Plan",
				SourceID:     ssp.ID.String(),
				SourceType:   "ssp",
			})
		}
	}

	return nil
}

func (h *InventoryHandler) fetchEvidenceInventoryItems(items *[]InventoryItemWithSource, req GetAllInventoryItemsRequest) error {
	var evidenceItems []relational.InventoryItem
	
	// Query inventory items that come from evidence
	// We want items that are linked to evidence but may not have a system_implementation_id
	query := h.db.Table("inventory_items").
		Joins("JOIN evidence_inventory_items ON evidence_inventory_items.inventory_item_id = inventory_items.id").
		Distinct("inventory_items.*").
		Preload("ImplementedComponents")
	
	// Only filter by SSP attachment if explicitly requested
	if req.AttachedToSSP == "false" {
		query = query.Where("inventory_items.system_implementation_id IS NULL")
	}
	
	if err := query.Find(&evidenceItems).Error; err != nil {
		return err
	}

	for _, item := range evidenceItems {
		oscalItem := item.MarshalOscal()
		*items = append(*items, InventoryItemWithSource{
			InventoryItem: oscalItem,
			Source:       "Evidence Collection",
			SourceID:     item.ID.String(),
			SourceType:   "evidence",
		})
	}

	return nil
}

func (h *InventoryHandler) fetchPOAMInventoryItems(items *[]InventoryItemWithSource, req GetAllInventoryItemsRequest) error {
	// First, get items from POAM documents themselves
	var poams []relational.PlanOfActionAndMilestones
	query := h.db.Find(&poams)
	
	if err := query.Error; err != nil {
		return err
	}

	for _, poam := range poams {
		oscalPOAM := poam.MarshalOscal()
		if oscalPOAM.LocalDefinitions == nil || oscalPOAM.LocalDefinitions.InventoryItems == nil {
			continue
		}

		for _, item := range *oscalPOAM.LocalDefinitions.InventoryItems {
			*items = append(*items, InventoryItemWithSource{
				InventoryItem: item,
				Source:       "Plan of Action and Milestones",
				SourceID:     poam.ID.String(),
				SourceType:   "poam",
			})
		}
	}
	
	// Also get inventory items with "planned-for" property
	// Note: Props are stored as JSON in the inventory_items table, not as a separate table
	// For now, we'll skip this as it requires complex JSON querying

	return nil
}

func (h *InventoryHandler) fetchAPInventoryItems(items *[]InventoryItemWithSource, req GetAllInventoryItemsRequest) error {
	// Fetch inventory items linked to Assessment Plans through LocalDefinitions
	var apInventoryItems []struct {
		relational.InventoryItem
		AssessmentPlanID uuid.UUID `gorm:"column:assessment_plan_id"`
	}
	
	query := h.db.Table("inventory_items").
		Select("inventory_items.*, ap.id as assessment_plan_id").
		Joins("JOIN local_definition_inventory_items ldi ON inventory_items.id = ldi.inventory_item_id").
		Joins("JOIN local_definitions ld ON ld.id = ldi.local_definitions_id").
		Joins("JOIN assessment_plans ap ON ap.id = ld.parent_id").
		Where("ld.parent_type = ?", "assessment_plans")
	
	if err := query.Find(&apInventoryItems).Error; err != nil {
		h.sugar.Errorf("Failed to fetch AP inventory items: %v", err)
		return err
	}
	
	// Convert to InventoryItemWithSource
	for _, item := range apInventoryItems {
		*items = append(*items, InventoryItemWithSource{
			InventoryItem: item.InventoryItem.MarshalOscal(),
			SourceID:      item.AssessmentPlanID.String(),
			SourceType:    "assessment-plan",
		})
	}
	
	return nil
}

func (h *InventoryHandler) fetchARInventoryItems(items *[]InventoryItemWithSource, req GetAllInventoryItemsRequest) error {
	// Fetch inventory items linked to Assessment Results through LocalDefinitions
	var arInventoryItems []struct {
		relational.InventoryItem
		AssessmentResultID uuid.UUID `gorm:"column:assessment_result_id"`
	}
	
	query := h.db.Table("inventory_items").
		Select("inventory_items.*, ar.id as assessment_result_id").
		Joins("JOIN local_definition_inventory_items ldi ON inventory_items.id = ldi.inventory_item_id").
		Joins("JOIN local_definitions ld ON ld.id = ldi.local_definitions_id").
		Joins("JOIN assessment_results ar ON ar.id = ld.parent_id").
		Where("ld.parent_type = ?", "assessment_results")
	
	if err := query.Find(&arInventoryItems).Error; err != nil {
		h.sugar.Errorf("Failed to fetch AR inventory items: %v", err)
		return err
	}
	
	// Convert to InventoryItemWithSource
	for _, item := range arInventoryItems {
		*items = append(*items, InventoryItemWithSource{
			InventoryItem: item.InventoryItem.MarshalOscal(),
			SourceID:      item.AssessmentResultID.String(),
			SourceType:    "assessment-results",
		})
	}
	
	return nil
}

func (h *InventoryHandler) applyFilters(items []InventoryItemWithSource, req GetAllInventoryItemsRequest) []InventoryItemWithSource {
	filtered := items

	// Filter by item type if specified
	if req.ItemType != "" {
		var typeFiltered []InventoryItemWithSource
		for _, item := range filtered {
			// Check if the item has a property with the name "asset-type" matching the requested type
			if item.Props != nil {
				for _, prop := range *item.Props {
					if prop.Name == "asset-type" && prop.Value == req.ItemType {
						typeFiltered = append(typeFiltered, item)
						break
					}
				}
			}
		}
		filtered = typeFiltered
	}

	// Additional filtering by SSP attachment status
	if req.AttachedToSSP != "" {
		var attachmentFiltered []InventoryItemWithSource
		attachToSSP := req.AttachedToSSP == "true"
		for _, item := range filtered {
			isAttached := item.SourceType == "ssp"
			if (attachToSSP && isAttached) || (!attachToSSP && !isAttached) {
				attachmentFiltered = append(attachmentFiltered, item)
			}
		}
		filtered = attachmentFiltered
	}

	return filtered
}

// GetInventoryItem godoc
//
//	@Summary		Get Inventory Item by ID
//	@Description	Retrieves a specific inventory item by its ID
//	@Tags			Inventory
//	@Produce		json
//	@Param			id	path		string	true	"Inventory Item ID"
//	@Success		200	{object}	InventoryItemWithSource
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/inventory/{id} [get]
func (h *InventoryHandler) GetInventoryItem(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid inventory item id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var item relational.InventoryItem
	if err := h.db.Preload("ImplementedComponents").First(&item, "id = ?", id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("Failed to get inventory item", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalItem := item.MarshalOscal()
	
	// Determine source
	source := "Unknown"
	sourceType := "unknown"
	if item.SystemImplementationId != uuid.Nil {
		source = "System Security Plan"
		sourceType = "ssp"
	} else {
		// Check if it's from evidence
		var count int64
		h.db.Table("evidence_inventory_items").Where("inventory_item_id = ?", id).Count(&count)
		if count > 0 {
			source = "Evidence Collection"
			sourceType = "evidence"
		}
	}

	response := InventoryItemWithSource{
		InventoryItem: oscalItem,
		Source:       source,
		SourceID:     item.ID.String(),
		SourceType:   sourceType,
	}

	return ctx.JSON(http.StatusOK, response)
}

// CreateInventoryItem godoc
//
//	@Summary		Create Inventory Item
//	@Description	Creates a new inventory item with optional attachment to SSP or POAM
//	@Tags			Inventory
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateInventoryItemRequest	true	"Create Inventory Item Request"
//	@Success		201		{object}	handler.GenericDataResponse[InventoryItemWithSource]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/inventory [post]
func (h *InventoryHandler) CreateInventoryItem(ctx echo.Context) error {
	var req CreateInventoryItemRequest
	if err := ctx.Bind(&req); err != nil {
		h.sugar.Warnw("Invalid create inventory item request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate destination
	validDestinations := map[string]bool{
		"ssp": true,
		"poam": true,
		"assessment-plan": true,
		"assessment-results": true,
		"unattached": true,
	}
	if !validDestinations[req.Destination] {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid destination: %s", req.Destination)))
	}

	// Ensure UUID is set
	if req.InventoryItem.UUID == "" {
		req.InventoryItem.UUID = uuid.New().String()
	}

	// Create the relational inventory item
	item := relational.InventoryItem{}
	item.UnmarshalOscal(req.InventoryItem)
	
	// Set destination-specific fields
	switch req.Destination {
	case "ssp":
		if req.DestinationID == "" {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("destination_id required for SSP")))
		}
		
		// Get the system implementation ID
		var systemImpl relational.SystemImplementation
		destID, err := uuid.Parse(req.DestinationID)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(err))
		}
		
		if err := h.db.Where("system_security_plan_id = ?", destID).First(&systemImpl).Error; err != nil {
			h.sugar.Errorw("Failed to find system implementation", "ssp_id", req.DestinationID, "error", err)
			return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSP not found")))
		}
		
		if systemImpl.ID != nil {
			item.SystemImplementationId = *systemImpl.ID
		}
		
	case "poam":
		// For POAM, store as unattached with a property indicating POAM destination
		if req.InventoryItem.Props == nil {
			props := []oscalTypes_1_1_3.Property{}
			req.InventoryItem.Props = &props
		}
		*req.InventoryItem.Props = append(*req.InventoryItem.Props, oscalTypes_1_1_3.Property{
			Name:  "planned-for",
			Value: "poam:" + req.DestinationID,
		})
		item.UnmarshalOscal(req.InventoryItem)
		
	case "assessment-plan":
		// For Assessment Plan, store as unattached with a property indicating AP destination
		if req.InventoryItem.Props == nil {
			props := []oscalTypes_1_1_3.Property{}
			req.InventoryItem.Props = &props
		}
		*req.InventoryItem.Props = append(*req.InventoryItem.Props, oscalTypes_1_1_3.Property{
			Name:  "discovered-in",
			Value: "assessment-plan:" + req.DestinationID,
		})
		item.UnmarshalOscal(req.InventoryItem)
		
	case "assessment-results":
		// For Assessment Results, store as unattached with a property indicating AR destination
		if req.InventoryItem.Props == nil {
			props := []oscalTypes_1_1_3.Property{}
			req.InventoryItem.Props = &props
		}
		*req.InventoryItem.Props = append(*req.InventoryItem.Props, oscalTypes_1_1_3.Property{
			Name:  "found-in",
			Value: "assessment-results:" + req.DestinationID,
		})
		item.UnmarshalOscal(req.InventoryItem)
		
	case "unattached":
		// No additional fields needed
	}

	// Save to database
	if err := h.db.Create(&item).Error; err != nil {
		h.sugar.Errorw("Failed to create inventory item", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Prepare response
	oscalItem := item.MarshalOscal()
	source := "Manual Creation"
	sourceType := req.Destination
	
	switch req.Destination {
	case "ssp":
		source = "System Security Plan"
	case "poam":
		source = "Plan of Action and Milestones"
	case "assessment-plan":
		source = "Assessment Plan"
	case "assessment-results":
		source = "Assessment Results"
	}
	
	response := InventoryItemWithSource{
		InventoryItem: oscalItem,
		Source:       source,
		SourceID:     item.ID.String(),
		SourceType:   sourceType,
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[InventoryItemWithSource]{
		Data: response,
	})
}