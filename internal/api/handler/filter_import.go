package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/datatypes"
	"gorm.io/gorm/clause"
)

type FilterImportFileResult struct {
	Filename string `json:"filename"`
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	Count    int    `json:"count,omitempty"`
}

type FilterImportResponse struct {
	TotalFiles      int                      `json:"total_files"`
	SuccessfulCount int                      `json:"successful_count"`
	FailedCount     int                      `json:"failed_count"`
	TotalDashboards int                      `json:"total_dashboards"`
	Results         []FilterImportFileResult `json:"results"`
}

type dashboardJSON struct {
	ID       *uuid.UUID          `json:"id,omitempty"`
	Name     string              `json:"name,omitempty"`
	Filter   *labelfilter.Filter `json:"filter"`
	Controls []controlRef        `json:"controls,omitempty"`
}

type controlRef struct {
	CatalogID uuid.UUID `json:"catalog_id,omitempty"`
	ID        string    `json:"id,omitempty"`
}

// ImportFilters godoc
//
//	@Summary		Import dashboard filters
//	@Description	Import multiple dashboard filter JSON files
//	@Tags			Filters
//	@Accept			multipart/form-data
//	@Produce		json
//	@Param			files	formData	file	true	"Dashboard filter JSON files to import"
//	@Success		200		{object}	GenericDataResponse[FilterImportResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/filters/import [post]
func (h *FilterHandler) ImportFilters(ctx echo.Context) error {
	form, err := ctx.MultipartForm()
	if err != nil {
		h.sugar.Errorw("Failed to parse multipart form", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("failed to parse multipart form: %w", err)))
	}

	files := form.File["files"]
	if len(files) == 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("no files provided")))
	}

	response := FilterImportResponse{
		TotalFiles: len(files),
		Results:    make([]FilterImportFileResult, 0, len(files)),
	}

	for _, fileHeader := range files {
		result := h.processFilterFile(fileHeader)
		response.Results = append(response.Results, result)
		if result.Success {
			response.SuccessfulCount++
			response.TotalDashboards += result.Count
		} else {
			response.FailedCount++
		}
	}

	statusCode := http.StatusOK
	if response.SuccessfulCount == 0 {
		statusCode = http.StatusBadRequest
	}

	return ctx.JSON(statusCode, GenericDataResponse[FilterImportResponse]{Data: response})
}

func (h *FilterHandler) processFilterFile(fileHeader *multipart.FileHeader) FilterImportFileResult {
	result := FilterImportFileResult{
		Filename: fileHeader.Filename,
		Success:  false,
	}

	file, err := fileHeader.Open()
	if err != nil {
		result.Message = fmt.Sprintf("Failed to open file: %v", err)
		return result
	}
	defer func() {
		if err := file.Close(); err != nil {
			h.sugar.Errorw("Failed to close file", "error", err)
		}
	}()

	data, err := io.ReadAll(file)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to read file: %v", err)
		return result
	}

	var inputs []dashboardJSON
	if err := json.Unmarshal(data, &inputs); err != nil {
		result.Message = fmt.Sprintf("Failed to parse JSON: %v", err)
		return result
	}

	if len(inputs) == 0 {
		result.Message = "No dashboards found in file"
		return result
	}

	created := 0
	for _, in := range inputs {
		rec := relational.Filter{
			Name: in.Name,
		}
		if in.ID != nil {
			rec.ID = in.ID
		}

		// Build filter JSON if provided
		if in.Filter != nil {
			lf := labelfilter.Filter{Scope: in.Filter.Scope}
			rec.Filter = datatypes.NewJSONType(lf)
		}

		if err := h.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&rec).Error; err != nil {
			result.Message = fmt.Sprintf("Failed to create filter '%s': %v", in.Name, err)
			return result
		}

		// Resolve and link controls if provided
		if len(in.Controls) > 0 {
			controls := make([]relational.Control, 0, len(in.Controls))
			for _, cr := range in.Controls {
				var ctl relational.Control
				if err := h.db.Where("catalog_id = ? AND id = ?", cr.CatalogID, cr.ID).First(&ctl).Error; err != nil {
					h.sugar.Warnw("Control not found for dashboard, skipping", "catalog_id", cr.CatalogID, "control_id", cr.ID, "dashboard", in.Name)
					continue
				}
				controls = append(controls, ctl)
			}
			if len(controls) > 0 {
				if err := h.db.Model(&rec).Association("Controls").Replace(controls); err != nil {
					result.Message = fmt.Sprintf("Failed linking controls for filter '%s': %v", in.Name, err)
					return result
				}
			}
		}

		created++
	}

	result.Success = true
	result.Count = created
	result.Message = fmt.Sprintf("Successfully imported %d dashboard(s)", created)
	return result
}
