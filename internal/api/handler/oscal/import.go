package oscal

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
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

type ImportHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

func NewImportHandler(l *zap.SugaredLogger, db *gorm.DB) *ImportHandler {
	return &ImportHandler{
		sugar: l,
		db:    db,
	}
}

func (h *ImportHandler) Register(api *echo.Group) {
	api.POST("", h.ImportOSCAL)
}

type ImportFileResult struct {
	Filename string `json:"filename"`
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	Type     string `json:"type,omitempty"`
	Title    string `json:"title,omitempty"`
}

type ImportResponse struct {
	TotalFiles      int                `json:"total_files"`
	SuccessfulCount int                `json:"successful_count"`
	FailedCount     int                `json:"failed_count"`
	Results         []ImportFileResult `json:"results"`
}

// ImportOSCAL godoc
//
//	@Summary		Import OSCAL files
//	@Description	Import multiple OSCAL JSON files (catalogs, profiles, SSPs, etc.)
//	@Tags			OSCAL
//	@Accept			multipart/form-data
//	@Produce		json
//	@Param			files	formData	file	true	"OSCAL JSON files to import"
//	@Success		200		{object}	handler.GenericDataResponse[ImportResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/oscal/import [post]
func (h *ImportHandler) ImportOSCAL(ctx echo.Context) error {
	form, err := ctx.MultipartForm()
	if err != nil {
		h.sugar.Errorw("Failed to parse multipart form", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("failed to parse multipart form: %w", err)))
	}

	files := form.File["files"]
	if len(files) == 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("no files provided")))
	}

	response := ImportResponse{
		TotalFiles: len(files),
		Results:    make([]ImportFileResult, 0, len(files)),
	}

	for _, fileHeader := range files {
		result := h.processOSCALFile(fileHeader)
		response.Results = append(response.Results, result)
		if result.Success {
			response.SuccessfulCount++
		} else {
			response.FailedCount++
		}
	}

	statusCode := http.StatusOK
	if response.SuccessfulCount == 0 {
		statusCode = http.StatusBadRequest
	}

	return ctx.JSON(statusCode, handler.GenericDataResponse[ImportResponse]{Data: response})
}

func (h *ImportHandler) processOSCALFile(fileHeader *multipart.FileHeader) ImportFileResult {
	result := ImportFileResult{
		Filename: fileHeader.Filename,
		Success:  false,
	}

	file, err := fileHeader.Open()
	if err != nil {
		result.Message = fmt.Sprintf("Failed to open file: %v", err)
		return result
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to read file: %v", err)
		return result
	}

	input := &struct {
		ComponentDefinition       *oscalTypes_1_1_3.ComponentDefinition       `json:"component-definition"`
		Catalog                   *oscalTypes_1_1_3.Catalog                   `json:"catalog"`
		SystemSecurityPlan        *oscalTypes_1_1_3.SystemSecurityPlan        `json:"system-security-plan"`
		AssessmentPlan            *oscalTypes_1_1_3.AssessmentPlan            `json:"assessment-plan"`
		AssessmentResult          *oscalTypes_1_1_3.AssessmentResults         `json:"assessment-results"`
		Profile                   *oscalTypes_1_1_3.Profile                   `json:"profile"`
		PlanOfActionAndMilestones *oscalTypes_1_1_3.PlanOfActionAndMilestones `json:"plan-of-action-and-milestones"`
	}{}

	if err := json.Unmarshal(data, input); err != nil {
		result.Message = fmt.Sprintf("Failed to parse JSON: %v", err)
		return result
	}

	imported := false

	if input.Catalog != nil {
		def := &relational.Catalog{}
		def.UnmarshalOscal(*input.Catalog)
		out := h.db.FirstOrCreate(def)
		if out.Error != nil {
			result.Message = fmt.Sprintf("Failed to import catalog: %v", out.Error)
			return result
		}
		result.Type = "Catalog"
		result.Title = def.Metadata.Title
		result.Success = true
		result.Message = "Successfully imported catalog"
		imported = true
	}

	if input.ComponentDefinition != nil {
		def := &relational.ComponentDefinition{}
		def.UnmarshalOscal(*input.ComponentDefinition)
		out := h.db.FirstOrCreate(def)
		if out.Error != nil {
			result.Message = fmt.Sprintf("Failed to import component definition: %v", out.Error)
			return result
		}
		result.Type = "Component Definition"
		result.Title = def.Metadata.Title
		result.Success = true
		result.Message = "Successfully imported component definition"
		imported = true
	}

	if input.SystemSecurityPlan != nil {
		def := &relational.SystemSecurityPlan{}
		def.UnmarshalOscal(*input.SystemSecurityPlan)
		out := h.db.FirstOrCreate(def)
		if out.Error != nil {
			result.Message = fmt.Sprintf("Failed to import system security plan: %v", out.Error)
			return result
		}
		result.Type = "System Security Plan"
		result.Title = def.Metadata.Title
		result.Success = true
		result.Message = "Successfully imported system security plan"
		imported = true
	}

	if input.AssessmentPlan != nil {
		def := &relational.AssessmentPlan{}
		def.UnmarshalOscal(*input.AssessmentPlan)
		out := h.db.FirstOrCreate(def)
		if out.Error != nil {
			result.Message = fmt.Sprintf("Failed to import assessment plan: %v", out.Error)
			return result
		}
		result.Type = "Assessment Plan"
		result.Title = def.Metadata.Title
		result.Success = true
		result.Message = "Successfully imported assessment plan"
		imported = true
	}

	if input.AssessmentResult != nil {
		def := &relational.AssessmentResult{}
		def.UnmarshalOscal(*input.AssessmentResult)
		out := h.db.FirstOrCreate(def)
		if out.Error != nil {
			result.Message = fmt.Sprintf("Failed to import assessment result: %v", out.Error)
			return result
		}
		result.Type = "Assessment Result"
		result.Title = def.Metadata.Title
		result.Success = true
		result.Message = "Successfully imported assessment result"
		imported = true
	}

	if input.Profile != nil {
		def := &relational.Profile{}
		def.UnmarshalOscal(*input.Profile)
		out := h.db.FirstOrCreate(def)
		if out.Error != nil {
			result.Message = fmt.Sprintf("Failed to import profile: %v", out.Error)
			return result
		}

		// Sync ProfileControl pivot table
		_, err := SyncProfileControls(h.db, uuid.MustParse(input.Profile.UUID))
		if err != nil {
			result.Message = fmt.Sprintf("Failed to sync profile controls: %v", err)
			return result
		}

		result.Type = "Profile"
		result.Title = def.Metadata.Title
		result.Success = true
		result.Message = "Successfully imported profile"
		imported = true
	}

	if input.PlanOfActionAndMilestones != nil {
		def := &relational.PlanOfActionAndMilestones{}
		def.UnmarshalOscal(*input.PlanOfActionAndMilestones)
		out := h.db.FirstOrCreate(def)
		if out.Error != nil {
			result.Message = fmt.Sprintf("Failed to import POA&M: %v", out.Error)
			return result
		}
		result.Type = "Plan of Action and Milestones"
		result.Title = def.Metadata.Title
		result.Success = true
		result.Message = "Successfully imported POA&M"
		imported = true
	}

	if !imported {
		// Try to detect what type of document this is
		var rawDoc map[string]interface{}
		if err := json.Unmarshal(data, &rawDoc); err == nil {
			for key := range rawDoc {
				result.Message = fmt.Sprintf("Unsupported OSCAL document type: %s", key)
				return result
			}
		}
		result.Message = "Failed to detect OSCAL document type"
	}

	return result
}
