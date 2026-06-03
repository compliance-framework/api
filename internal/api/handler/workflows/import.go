package workflows

import (
	"fmt"
	"mime/multipart"
	"net/http"

	"github.com/compliance-framework/api/internal/api"
	workflowseed "github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type WorkflowImportHandler struct {
	*BaseHandler
	db *gorm.DB
}

func NewWorkflowImportHandler(sugar *zap.SugaredLogger, db *gorm.DB) *WorkflowImportHandler {
	return &WorkflowImportHandler{
		BaseHandler: NewBaseHandler(sugar),
		db:          db,
	}
}

type WorkflowImportFileResult struct {
	Filename string                   `json:"filename"`
	Success  bool                     `json:"success"`
	Message  string                   `json:"message"`
	Summary  workflowseed.SeedSummary `json:"summary,omitempty"`
}

type WorkflowImportResponse struct {
	TotalFiles      int                        `json:"total_files"`
	SuccessfulFiles int                        `json:"successful_files"`
	FailedFiles     int                        `json:"failed_files"`
	Summary         workflowseed.SeedSummary   `json:"summary"`
	Results         []WorkflowImportFileResult `json:"results"`
}

type WorkflowImportDataResponse struct {
	Data WorkflowImportResponse `json:"data"`
}

// Import godoc
//
//	@Summary		Import workflow seed definitions
//	@Description	Import one or more SOC 2 CCF workflow seed JSON files
//	@Tags			Workflows
//	@Accept			multipart/form-data
//	@Produce		json
//	@Param			files	formData	file	true	"Workflow seed JSON files to import"
//	@Success		200		{object}	WorkflowImportDataResponse
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		403		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/workflows/import [post]
func (h *WorkflowImportHandler) Import(ctx echo.Context) error {
	form, err := ctx.MultipartForm()
	if err != nil {
		h.sugar.Errorw("Failed to parse multipart form", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("failed to parse multipart form: %w", err)))
	}

	files := form.File["files"]
	if len(files) == 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("no files provided")))
	}

	response := WorkflowImportResponse{
		TotalFiles: len(files),
		Results:    make([]WorkflowImportFileResult, 0, len(files)),
	}

	for _, fileHeader := range files {
		result := h.processWorkflowSeedFile(ctx, fileHeader)
		response.Results = append(response.Results, result)
		if result.Success {
			response.SuccessfulFiles++
			workflowseed.MergeSeedSummary(&response.Summary, result.Summary)
		} else {
			response.FailedFiles++
		}
	}

	statusCode := http.StatusOK
	if response.SuccessfulFiles == 0 {
		statusCode = http.StatusBadRequest
	}

	return ctx.JSON(statusCode, WorkflowImportDataResponse{Data: response})
}

func (h *WorkflowImportHandler) processWorkflowSeedFile(ctx echo.Context, fileHeader *multipart.FileHeader) WorkflowImportFileResult {
	result := WorkflowImportFileResult{
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

	definitions, err := workflowseed.DecodeSeedDefinitions(file)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to parse JSON: %v", err)
		return result
	}

	result.Summary = workflowseed.ImportSeedDefinitions(ctx.Request().Context(), h.db, h.sugar, definitions)
	result.Success = true
	result.Message = workflowImportMessage(len(definitions), result.Summary)
	return result
}

func workflowImportMessage(definitions int, summary workflowseed.SeedSummary) string {
	message := fmt.Sprintf("imported %d definition(s)", definitions)
	if summary.Failed > 0 {
		message = fmt.Sprintf("%s, %d failed", message, summary.Failed)
	}
	if summary.Skipped > 0 {
		message = fmt.Sprintf("%s, %d skipped", message, summary.Skipped)
	}
	return message
}
