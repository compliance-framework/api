package workflow

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// StepTransitionService handles user-driven step transitions with role verification
type StepTransitionService struct {
	stepExecutionService      StepExecutionServiceInterface
	stepDefinitionService     WorkflowStepDefinitionServiceInterface
	workflowExecutionService  WorkflowExecutionServiceInterface
	roleAssignmentService     RoleAssignmentServiceInterface
	workflowInstanceService   WorkflowInstanceServiceInterface
	workflowDefinitionService WorkflowDefinitionServiceInterface
	executor                  *DAGExecutor
	db                        *gorm.DB
	evidenceIntegration       *EvidenceIntegration
}

var ErrInvalidStepTransition = errors.New("invalid step transition")

// WorkflowDefinitionServiceInterface defines the interface for workflow definition operations
type WorkflowDefinitionServiceInterface interface {
	GetByID(id *uuid.UUID) (*workflows.WorkflowDefinition, error)
}

// RoleAssignmentServiceInterface defines the interface for role assignment operations
type RoleAssignmentServiceInterface interface {
	FindAssigneeForRole(instanceID *uuid.UUID, roleName string) (*workflows.RoleAssignment, error)
	GetByWorkflowInstanceID(instanceID *uuid.UUID) ([]workflows.RoleAssignment, error)
}

// NewStepTransitionService creates a new StepTransitionService
func NewStepTransitionService(
	stepExecutionService StepExecutionServiceInterface,
	stepDefinitionService WorkflowStepDefinitionServiceInterface,
	workflowExecutionService WorkflowExecutionServiceInterface,
	roleAssignmentService RoleAssignmentServiceInterface,
	workflowInstanceService WorkflowInstanceServiceInterface,
	workflowDefinitionService WorkflowDefinitionServiceInterface,
	executor *DAGExecutor,
	db *gorm.DB,
	evidenceIntegration *EvidenceIntegration,
) *StepTransitionService {
	return &StepTransitionService{
		stepExecutionService:      stepExecutionService,
		stepDefinitionService:     stepDefinitionService,
		workflowExecutionService:  workflowExecutionService,
		roleAssignmentService:     roleAssignmentService,
		workflowInstanceService:   workflowInstanceService,
		workflowDefinitionService: workflowDefinitionService,
		executor:                  executor,
		db:                        db,
		evidenceIntegration:       evidenceIntegration,
	}
}

// EvidenceRequirement represents a required evidence type for a step
type EvidenceRequirement struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// StepTransitionRequest represents a request to transition a step
type StepTransitionRequest struct {
	Status   string               `json:"status"` // "in_progress" or "completed"
	Evidence []EvidenceSubmission `json:"evidence,omitempty"`
	Notes    string               `json:"notes,omitempty"`
	UserID   string               `json:"user_id"`   // ID of the user making the transition
	UserType string               `json:"user_type"` // "user", "group", "email"
}

// EvidenceSubmission represents evidence being submitted with a step transition
type EvidenceSubmission struct {
	EvidenceID   *uuid.UUID `json:"evidence-id"`
	EvidenceType string     `json:"evidence-type"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	FilePath     string     `json:"file-path,omitempty"`
	FileSize     int64      `json:"file-size,omitempty"`
	FileHash     string     `json:"file-hash,omitempty"`
	FileContent  string     `json:"file-content,omitempty"` // Base64 encoded file content
	MediaType    string     `json:"media-type,omitempty"`   // MIME type (e.g., "application/pdf", "image/png")
	Metadata     string     `json:"metadata,omitempty"`
}

// TransitionStepStatus handles user-driven step status transitions with role verification
func (s *StepTransitionService) TransitionStepStatus(ctx context.Context, stepExecutionID *uuid.UUID, request *StepTransitionRequest) error {
	// Get the step execution
	stepExecution, err := s.stepExecutionService.GetByID(stepExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get step execution: %w", err)
	}

	// Get the step definition to check responsible role and evidence requirements
	stepDef, err := s.getStepDefinition(stepExecution.WorkflowStepDefinitionID)
	if err != nil {
		return fmt.Errorf("failed to get step definition: %w", err)
	}

	// Get the workflow execution to access the workflow instance
	workflowExecution, err := s.workflowExecutionService.GetByID(stepExecution.WorkflowExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get workflow execution: %w", err)
	}

	// Verify user has permission to transition this step
	if err := s.verifyUserPermission(workflowExecution.WorkflowInstanceID, stepDef.ResponsibleRole, request.UserID, request.UserType); err != nil {
		return fmt.Errorf("permission denied: %w", err)
	}

	// Validate the transition based on current status
	if err := s.validateTransition(stepExecution.Status, request.Status); err != nil {
		return err
	}

	// If transitioning to completed, validate evidence requirements
	if request.Status == StatusCompleted.String() {
		if err := s.validateEvidenceRequirements(stepDef, request.Evidence); err != nil {
			return err
		}
	}

	// Update the step status
	if err := s.stepExecutionService.UpdateStatus(ctx, stepExecutionID, request.Status); err != nil {
		return fmt.Errorf("failed to update step status: %w", err)
	}

	// If transitioning to completed, process the completion
	if request.Status == StatusCompleted.String() {
		// Store submitted evidence
		if err := s.storeStepEvidence(stepExecutionID, request.Evidence, request.UserID); err != nil {
			return fmt.Errorf("failed to store evidence: %w", err)
		}

		// Process step completion (unblock dependent steps, check workflow completion)
		if err := s.executor.ProcessStepCompletion(ctx, stepExecutionID); err != nil {
			return fmt.Errorf("failed to process step completion: %w", err)
		}

		// Check automatic triggers (Phase 5 hook)
		if err := s.executor.CheckAutomaticTriggers(ctx, stepExecutionID); err != nil {
			// Log but don't fail - triggers are optional
			fmt.Printf("Warning: failed to check automatic triggers: %v\n", err)
		}
	}

	return nil
}

// FailStep marks a step as failed and propagates failure through dependent steps.
func (s *StepTransitionService) FailStep(ctx context.Context, stepExecutionID *uuid.UUID, reason string) error {
	if err := s.stepExecutionService.Fail(stepExecutionID, reason); err != nil {
		return err
	}
	if s.executor != nil {
		if err := s.executor.ProcessStepFailure(ctx, stepExecutionID); err != nil {
			return err
		}
	}
	return nil
}

// verifyUserPermission checks if the user has permission to transition the step
func (s *StepTransitionService) verifyUserPermission(instanceID *uuid.UUID, responsibleRole, userID, userType string) error {
	// Find the role assignment for the responsible role
	assignment, err := s.roleAssignmentService.FindAssigneeForRole(instanceID, responsibleRole)
	if err != nil {
		return fmt.Errorf("no assignment found for role %s: %w", responsibleRole, err)
	}

	// Check if the user matches the assignment
	if assignment.AssignedToType != userType || assignment.AssignedToID != userID {
		return fmt.Errorf("user %s (%s) is not assigned to role %s (assigned to: %s %s)",
			userID, userType, responsibleRole, assignment.AssignedToType, assignment.AssignedToID)
	}

	// Check if the assignment is active
	if !assignment.IsActive {
		return fmt.Errorf("role assignment for %s is not active", responsibleRole)
	}

	return nil
}

// validateTransition validates that the requested status transition is allowed
func (s *StepTransitionService) validateTransition(currentStatus, newStatus string) error {
	// Define allowed transitions
	allowedTransitions := map[string][]string{
		StatusPending.String():    {StatusInProgress.String()},
		StatusInProgress.String(): {StatusCompleted.String()},
		StatusOverdue.String():    {StatusCompleted.String()},
		StatusBlocked.String():    {}, // Blocked steps cannot be manually transitioned
		StatusCompleted.String():  {}, // Completed steps cannot be changed
		StatusFailed.String():     {}, // Failed steps cannot be manually changed (only by executor)
	}

	allowed, exists := allowedTransitions[currentStatus]
	if !exists {
		return fmt.Errorf("%w: invalid current status: %s", ErrInvalidStepTransition, currentStatus)
	}

	// Check if the new status is in the allowed list
	for _, allowedStatus := range allowed {
		if allowedStatus == newStatus {
			return nil
		}
	}

	return fmt.Errorf("%w: transition from %s to %s is not allowed", ErrInvalidStepTransition, currentStatus, newStatus)
}

// validateEvidenceRequirements validates that all required evidence has been submitted
func (s *StepTransitionService) validateEvidenceRequirements(stepDef *workflows.WorkflowStepDefinition, submittedEvidence []EvidenceSubmission) error {

	// Build a map of submitted evidence types
	submittedTypes := make(map[string]int)
	for _, evidence := range submittedEvidence {
		submittedTypes[evidence.EvidenceType]++
	}

	// Check that all required evidence types have at least one submission
	var missingTypes []string
	for _, req := range stepDef.EvidenceRequired {
		if req.Required {
			if count, exists := submittedTypes[req.Type]; !exists || count == 0 {
				missingTypes = append(missingTypes, req.Type)
			}
		}
	}

	if len(missingTypes) > 0 {
		return fmt.Errorf("missing required evidence types: %v", missingTypes)
	}

	return nil
}

// storeStepEvidence stores the submitted evidence for a step execution as relational.Evidence
// with BackMatter resources for uploaded files and proper labels for the workflow execution stream
func (s *StepTransitionService) storeStepEvidence(stepExecutionID *uuid.UUID, evidenceSubmissions []EvidenceSubmission, completedBy string) error {
	if len(evidenceSubmissions) == 0 {
		return nil
	}

	// Gather all workflow context needed for evidence creation
	ctx, err := s.gatherWorkflowContext(stepExecutionID)
	if err != nil {
		return err
	}

	// Get or create the execution evidence stream
	stream, err := s.evidenceIntegration.GetOrCreateExecutionStream(context.Background(), ctx.workflowExecution.ID)
	if err != nil {
		return fmt.Errorf("failed to get or create execution stream: %w", err)
	}

	// Build BackMatter resources and Links from evidence submissions
	backMatter, evidenceLinks := s.buildBackMatterFromSubmissions(evidenceSubmissions)

	// Create the evidence record
	evidence := s.createEvidenceRecord(ctx, stream, backMatter, evidenceLinks, len(evidenceSubmissions))

	// Save evidence to database
	if err := s.db.Create(evidence).Error; err != nil {
		return fmt.Errorf("failed to create step evidence: %w", err)
	}

	// Build and attach labels
	labels := s.buildEvidenceLabels(ctx, completedBy, len(evidenceSubmissions))
	if err := s.db.Model(evidence).Association("Labels").Append(labels); err != nil {
		return fmt.Errorf("failed to add labels to evidence: %w", err)
	}

	return nil
}

// workflowContext holds all workflow-related entities needed for evidence creation
type workflowContext struct {
	stepExecution     *workflows.StepExecution
	stepDef           *workflows.WorkflowStepDefinition
	workflowExecution *workflows.WorkflowExecution
	instance          *workflows.WorkflowInstance
	definition        *workflows.WorkflowDefinition
}

// gatherWorkflowContext retrieves all workflow entities needed for evidence creation
func (s *StepTransitionService) gatherWorkflowContext(stepExecutionID *uuid.UUID) (*workflowContext, error) {
	stepExecution, err := s.stepExecutionService.GetByID(stepExecutionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get step execution: %w", err)
	}

	stepDef, err := s.stepDefinitionService.GetByID(stepExecution.WorkflowStepDefinitionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get step definition: %w", err)
	}

	workflowExecution, err := s.workflowExecutionService.GetByID(stepExecution.WorkflowExecutionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow execution: %w", err)
	}

	instance, err := s.workflowInstanceService.GetByID(workflowExecution.WorkflowInstanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow instance: %w", err)
	}

	definition, err := s.workflowDefinitionService.GetByID(instance.WorkflowDefinitionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow definition: %w", err)
	}

	return &workflowContext{
		stepExecution:     stepExecution,
		stepDef:           stepDef,
		workflowExecution: workflowExecution,
		instance:          instance,
		definition:        definition,
	}, nil
}

// buildBackMatterFromSubmissions creates BackMatter resources and Links from evidence submissions
func (s *StepTransitionService) buildBackMatterFromSubmissions(evidenceSubmissions []EvidenceSubmission) (*relational.BackMatter, []relational.Link) {
	var backMatterResources []relational.BackMatterResource
	var evidenceLinks []relational.Link

	for _, ev := range evidenceSubmissions {
		resourceID := uuid.New()
		resource := s.createBackMatterResource(ev, resourceID)
		backMatterResources = append(backMatterResources, resource)

		// Add a Link to this resource so the UI can find and display it
		evidenceLinks = append(evidenceLinks, relational.Link{
			Href: fmt.Sprintf("#%s", resourceID.String()),
			Rel:  "attachment",
			Text: ev.Name,
		})
	}

	var backMatter *relational.BackMatter
	if len(backMatterResources) > 0 {
		backMatter = &relational.BackMatter{
			Resources: backMatterResources,
		}
	}

	return backMatter, evidenceLinks
}

// createBackMatterResource creates a single BackMatter resource from an evidence submission
func (s *StepTransitionService) createBackMatterResource(ev EvidenceSubmission, resourceID uuid.UUID) relational.BackMatterResource {
	resource := relational.BackMatterResource{
		ID:          resourceID,
		Title:       &ev.Name,
		Description: &ev.Description,
	}

	// Store file content as base64 if present
	if ev.FileContent != "" {
		filename := ev.Name
		if ev.FilePath != "" {
			parts := strings.Split(ev.FilePath, "/")
			if len(parts) > 0 {
				filename = parts[len(parts)-1]
			}
		}

		base64Data := relational.Base64{
			Filename:  filename,
			MediaType: ev.MediaType,
			Value:     ev.FileContent,
		}
		resource.Base64 = &datatypes.JSONType[relational.Base64]{}
		*resource.Base64 = datatypes.NewJSONType(base64Data)
	}

	// Add file hash as a document ID if present
	if ev.FileHash != "" {
		resource.DocumentIDs = []relational.DocumentID{
			{
				Scheme:     "sha256",
				Identifier: ev.FileHash,
			},
		}
	}

	// Add metadata as props if present
	if ev.Metadata != "" {
		resource.Props = []relational.Prop{
			{
				Name:  "metadata",
				Value: ev.Metadata,
			},
		}
	}

	return resource
}

// createEvidenceRecord creates the evidence record with all required fields
func (s *StepTransitionService) createEvidenceRecord(ctx *workflowContext, stream *relational.Evidence, backMatter *relational.BackMatter, evidenceLinks []relational.Link, submissionCount int) *relational.Evidence {
	description := fmt.Sprintf("Step '%s' completed successfully with %d evidence submission(s)",
		ctx.stepDef.Name, submissionCount)

	// Determine start and end times
	startTime := time.Now()
	if ctx.stepExecution.StartedAt != nil {
		startTime = *ctx.stepExecution.StartedAt
	}
	endTime := time.Now()
	if ctx.stepExecution.CompletedAt != nil {
		endTime = *ctx.stepExecution.CompletedAt
	}

	// Create the evidence record
	evidence := &relational.Evidence{
		UUID:        stream.UUID,
		Title:       fmt.Sprintf("Step '%s' completed successfully", ctx.stepDef.Name),
		Description: description,
		Start:       startTime,
		End:         endTime,
		BackMatter:  backMatter,
		Props:       datatypes.JSONSlice[relational.Prop]{},
	}

	// Add Links if we have resources
	if len(evidenceLinks) > 0 {
		evidence.Links = evidenceLinks
	}

	// Set status based on step execution status
	status := oscalTypes_1_1_3.ObjectiveStatus{
		State: "satisfied",
	}
	if ctx.stepExecution.Status != "completed" {
		status.State = "not-satisfied"
	}
	evidence.Status = datatypes.NewJSONType(status)

	// Generate unique ID
	id := uuid.New()
	evidence.ID = &id

	return evidence
}

// buildEvidenceLabels creates labels for the evidence record
func (s *StepTransitionService) buildEvidenceLabels(ctx *workflowContext, completedBy string, submissionCount int) []relational.Labels {
	labels := []relational.Labels{
		{Name: "workflow.definition.id", Value: ctx.definition.ID.String()},
		{Name: "workflow.definition.name", Value: ctx.definition.Name},
		{Name: "workflow.instance.id", Value: ctx.instance.ID.String()},
		{Name: "workflow.execution.id", Value: ctx.workflowExecution.ID.String()},
		{Name: "step.execution.id", Value: ctx.stepExecution.ID.String()},
		{Name: "step.definition.id", Value: ctx.stepDef.ID.String()},
		{Name: "step.name", Value: ctx.stepDef.Name},
		{Name: "step.status", Value: ctx.stepExecution.Status},
		{Name: "evidence.type", Value: "step_submission"},
		{Name: "evidence.submitted_by", Value: completedBy},
		{Name: "evidence.submission_count", Value: fmt.Sprintf("%d", submissionCount)},
	}

	// Add system ID if available
	if ctx.instance.SystemSecurityPlanID != nil {
		labels = append(labels, relational.Labels{
			Name:  "system.id",
			Value: ctx.instance.SystemSecurityPlanID.String(),
		})
	}

	return labels
}

// getStepDefinition retrieves a step definition by ID
func (s *StepTransitionService) getStepDefinition(stepDefID *uuid.UUID) (*workflows.WorkflowStepDefinition, error) {
	return s.stepDefinitionService.GetByID(stepDefID)
}

// GetStepExecutionService returns the underlying step execution service
func (s *StepTransitionService) GetStepExecutionService() *workflows.StepExecutionService {
	if svc, ok := s.stepExecutionService.(*workflows.StepExecutionService); ok {
		return svc
	}
	return nil
}

// CanUserTransitionStep checks if a user can transition a specific step
func (s *StepTransitionService) CanUserTransitionStep(stepExecutionID *uuid.UUID, userID, userType string) (bool, error) {
	// Get the step execution
	stepExecution, err := s.stepExecutionService.GetByID(stepExecutionID)
	if err != nil {
		return false, fmt.Errorf("failed to get step execution: %w", err)
	}

	// Get the step definition
	stepDef, err := s.getStepDefinition(stepExecution.WorkflowStepDefinitionID)
	if err != nil {
		return false, fmt.Errorf("failed to get step definition: %w", err)
	}

	// Get the workflow execution
	workflowExecution, err := s.workflowExecutionService.GetByID(stepExecution.WorkflowExecutionID)
	if err != nil {
		return false, fmt.Errorf("failed to get workflow execution: %w", err)
	}

	// Verify user permission
	if err := s.verifyUserPermission(workflowExecution.WorkflowInstanceID, stepDef.ResponsibleRole, userID, userType); err != nil {
		return false, nil // No error, just not permitted
	}

	return true, nil
}

// GetEvidenceRequirements returns the evidence requirements for a step
func (s *StepTransitionService) GetEvidenceRequirements(stepExecutionID *uuid.UUID) ([]workflows.EvidenceRequirement, error) {
	// Get the step execution
	stepExecution, err := s.stepExecutionService.GetByID(stepExecutionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get step execution: %w", err)
	}

	// Get the step definition
	stepDef, err := s.getStepDefinition(stepExecution.WorkflowStepDefinitionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get step definition: %w", err)
	}

	return stepDef.EvidenceRequired, nil
}
