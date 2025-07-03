package assessmentplan

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

// validateAssessmentSubjectInput validates assessment subject input
func (h *AssessmentPlanHandler) validateAssessmentSubjectInput(subject *oscalTypes_1_1_3.AssessmentSubject) error {
	if subject.Type == "" {
		return fmt.Errorf("type is required")
	}
	return nil
}

// GetAssessmentSubjects godoc
//
//	@Summary		Get Assessment Plan Subjects
//	@Description	Retrieves all assessment subjects for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Produce		json
//	@Param			id	path		string	true	"Assessment Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[[]oscalTypes_1_1_3.AssessmentSubject]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/assessment-subjects [get]
func (h *AssessmentPlanHandler) GetAssessmentSubjects(ctx echo.Context) error {
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

	var subjects []relational.AssessmentSubject
	if err := h.db.Joins("JOIN task_subjects ON assessment_subjects.id = task_subjects.assessment_subject_id").
		Joins("JOIN tasks ON task_subjects.task_id = tasks.id").
		Where("tasks.parent_id = ? AND tasks.parent_type = ?", id, "AssessmentPlan").
		Find(&subjects).Error; err != nil {
		h.sugar.Errorf("Failed to retrieve assessment subjects: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalSubjects := make([]*oscalTypes_1_1_3.AssessmentSubject, len(subjects))
	for i, subject := range subjects {
		oscalSubjects[i] = subject.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[[]*oscalTypes_1_1_3.AssessmentSubject]{Data: oscalSubjects})
}

// CreateAssessmentSubject godoc
//
//	@Summary		Create Assessment Plan Subject
//	@Description	Creates a new assessment subject for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string								true	"Assessment Plan ID"
//	@Param			subject	body		oscalTypes_1_1_3.AssessmentSubject	true	"Assessment Subject object"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentSubject]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/assessment-subjects [post]
func (h *AssessmentPlanHandler) CreateAssessmentSubject(ctx echo.Context) error {
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

	var subject oscalTypes_1_1_3.AssessmentSubject
	if err := ctx.Bind(&subject); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateAssessmentSubjectInput(&subject); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Convert to a relational model
	relationalSubject := &relational.AssessmentSubject{}
	relationalSubject.UnmarshalOscal(subject)

	// Start a transaction to ensure consistency
	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Save the assessment subject to database
	if err := tx.Create(relationalSubject).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to create assessment subject: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Create a task to link this subject to the assessment plan
	task := &relational.Task{
		Type:        "action", // Default type for subject tasks
		Title:       fmt.Sprintf("Task for Subject: %s", subject.Type),
		Description: &subject.Description,
		ParentID:    &id,
		ParentType:  "AssessmentPlan",
	}

	if err := tx.Create(task).Error; err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to create task for subject: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Create the many-to-many relationship between task and subject
	if err := tx.Model(task).Association("Subjects").Append(relationalSubject); err != nil {
		tx.Rollback()
		h.sugar.Errorf("Failed to associate subject with task: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		h.sugar.Errorf("Failed to commit subject creation transaction: %v", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[*oscalTypes_1_1_3.AssessmentSubject]{Data: relationalSubject.MarshalOscal()})
}

// UpdateAssessmentSubject godoc
//
//	@Summary		Update Assessment Plan Subject
//	@Description	Updates an existing assessment subject for an Assessment Plan.
//	@Tags			Assessment Plans
//	@Accept			json
//	@Produce		json
//	@Param			id			path		string								true	"Assessment Plan ID"
//	@Param			subjectId	path		string								true	"Assessment Subject ID"
//	@Param			subject		body		oscalTypes_1_1_3.AssessmentSubject	true	"Assessment Subject object"
//	@Success		200			{object}	handler.GenericDataResponse[oscalTypes_1_1_3.AssessmentSubject]
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/assessment-subjects/{subjectId} [put]
func (h *AssessmentPlanHandler) UpdateAssessmentSubject(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	subjectIdParam := ctx.Param("subjectId")
	subjectId, err := uuid.Parse(subjectIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid subject id", "subjectId", subjectIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify plan exists
	if err := h.verifyAssessmentPlanExists(ctx, id); err != nil {
		return err
	}

	var subject oscalTypes_1_1_3.AssessmentSubject
	if err := ctx.Bind(&subject); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Validate input
	if err := h.validateAssessmentSubjectInput(&subject); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Convert to relational model
	relationalSubject := &relational.AssessmentSubject{}
	relationalSubject.UnmarshalOscal(subject)
	relationalSubject.ID = &subjectId

	// Update in database and check if resource exists
	result := h.db.Where("id = ?", subjectId).Updates(relationalSubject)
	if result.Error != nil {
		h.sugar.Errorf("Failed to update assessment subject: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	// Check if the subject was found and updated
	if result.RowsAffected == 0 {
		h.sugar.Warnw("Assessment subject not found for update", "subjectId", subjectId)
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("assessment subject with id %s not found", subjectId)))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[*oscalTypes_1_1_3.AssessmentSubject]{Data: relationalSubject.MarshalOscal()})
}

// DeleteAssessmentSubject godoc
//
//	@Summary		Delete Assessment Plan Subject
//	@Description	Deletes an assessment subject from an Assessment Plan.
//	@Tags			Assessment Plans
//	@Param			id			path	string	true	"Assessment Plan ID"
//	@Param			subjectId	path	string	true	"Assessment Subject ID"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		404			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscalTypes_1_1_3/assessment-plans/{id}/assessment-subjects/{subjectId} [delete]
func (h *AssessmentPlanHandler) DeleteAssessmentSubject(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid assessment plan id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	subjectIdParam := ctx.Param("subjectId")
	subjectId, err := uuid.Parse(subjectIdParam)
	if err != nil {
		h.sugar.Warnw("Invalid subject id", "subjectId", subjectIdParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Verify plan exists
	if err := h.verifyAssessmentPlanExists(ctx, id); err != nil {
		return err
	}

	// Delete assessment subject and check if resource exists
	result := h.db.Where("id = ?", subjectId).Delete(&relational.AssessmentSubject{})
	if result.Error != nil {
		h.sugar.Errorf("Failed to delete assessment subject: %v", result.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(result.Error))
	}

	// Check if the subject was found and deleted
	if result.RowsAffected == 0 {
		h.sugar.Warnw("Assessment subject not found for deletion", "subjectId", subjectId)
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("assessment subject with id %s not found", subjectId)))
	}

	return ctx.NoContent(http.StatusNoContent)
}
