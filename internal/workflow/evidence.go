package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// EvidenceIntegration handles evidence stream creation and management for workflow executions
// Design:
// - 1 evidence stream per workflow execution (accumulates step completion evidence)
// - 1 evidence stream per workflow instance (accumulates execution completion evidence)
// - Streams use label-seeded UUIDs for deterministic identification
type EvidenceIntegration struct {
	db                    *gorm.DB
	logger                *zap.SugaredLogger
	workflowExecutionSvc  *workflows.WorkflowExecutionService
	stepExecutionSvc      *workflows.StepExecutionService
	workflowInstanceSvc   *workflows.WorkflowInstanceService
	workflowDefinitionSvc *workflows.WorkflowDefinitionService
	stepDefinitionSvc     *workflows.WorkflowStepDefinitionService
}

// NewEvidenceIntegration creates a new evidence integration service
func NewEvidenceIntegration(
	db *gorm.DB,
	logger *zap.SugaredLogger,
) *EvidenceIntegration {
	return &EvidenceIntegration{
		db:                    db,
		logger:                logger,
		workflowExecutionSvc:  workflows.NewWorkflowExecutionService(db),
		stepExecutionSvc:      workflows.NewStepExecutionService(db),
		workflowInstanceSvc:   workflows.NewWorkflowInstanceService(db),
		workflowDefinitionSvc: workflows.NewWorkflowDefinitionService(db),
		stepDefinitionSvc:     workflows.NewWorkflowStepDefinitionService(db),
	}
}

// GetOrCreateExecutionStream gets or creates the evidence stream for a workflow execution
// This stream accumulates all step completion evidence for this execution
func (e *EvidenceIntegration) GetOrCreateExecutionStream(ctx context.Context, workflowExecutionID *uuid.UUID) (*relational.Evidence, error) {
	// Get workflow execution
	execution, err := e.workflowExecutionSvc.GetByID(workflowExecutionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow execution: %w", err)
	}

	// Get workflow instance
	instance, err := e.workflowInstanceSvc.GetByID(execution.WorkflowInstanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow instance: %w", err)
	}

	// Get workflow definition
	definition, err := e.workflowDefinitionSvc.GetByID(instance.WorkflowDefinitionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow definition: %w", err)
	}

	// Generate label-seeded UUID for this execution stream
	streamUUID := e.generateExecutionStreamUUID(definition, instance, execution)

	// Check if stream already exists
	var existingStream relational.Evidence
	err = e.db.Where("uuid = ?", streamUUID).First(&existingStream).Error
	if err == nil {
		// Stream exists, return it
		return &existingStream, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("failed to check for existing stream: %w", err)
	}

	// Create new evidence stream
	labels := e.buildExecutionStreamLabels(definition, instance, execution)

	var systemID string
	if instance.SystemSecurityPlanID != nil {
		systemID = instance.SystemSecurityPlanID.String()
	} else {
		systemID = "unknown"
	}

	stream := &relational.Evidence{
		UUID:  streamUUID,
		Title: fmt.Sprintf("Workflow Execution: %s", definition.Name),
		Description: fmt.Sprintf("Evidence stream for execution %s of workflow %s (v%s) on system %s",
			execution.ID, definition.Name, definition.Version, systemID),
		Start: time.Now(),
		End:   time.Now(),
	}

	// Generate unique ID for the stream record
	id := uuid.New()
	stream.ID = &id

	if err := e.db.Create(stream).Error; err != nil {
		return nil, fmt.Errorf("failed to create evidence stream: %w", err)
	}

	// Add labels via association
	if err := e.db.Model(stream).Association("Labels").Append(labels); err != nil {
		return nil, fmt.Errorf("failed to add labels to stream: %w", err)
	}

	e.logger.Infow("Execution evidence stream created",
		"stream_uuid", streamUUID,
		"stream_id", stream.ID,
		"workflow_execution_id", workflowExecutionID,
	)

	return stream, nil
}

// GetOrCreateInstanceStream gets or creates the evidence stream for a workflow instance
// This stream accumulates all execution completion evidence for this instance
func (e *EvidenceIntegration) GetOrCreateInstanceStream(ctx context.Context, workflowInstanceID *uuid.UUID) (*relational.Evidence, error) {
	// Get workflow instance
	instance, err := e.workflowInstanceSvc.GetByID(workflowInstanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow instance: %w", err)
	}

	// Get workflow definition
	definition, err := e.workflowDefinitionSvc.GetByID(instance.WorkflowDefinitionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow definition: %w", err)
	}

	// Generate label-seeded UUID for this instance stream
	streamUUID := e.generateInstanceStreamUUID(definition, instance)

	// Check if stream already exists
	var existingStream relational.Evidence
	err = e.db.Where("uuid = ?", streamUUID).First(&existingStream).Error
	if err == nil {
		// Stream exists, return it
		return &existingStream, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("failed to check for existing stream: %w", err)
	}

	// Create new evidence stream
	labels := e.buildInstanceStreamLabels(definition, instance)

	var systemID string
	if instance.SystemSecurityPlanID != nil {
		systemID = instance.SystemSecurityPlanID.String()
	} else {
		systemID = "unknown"
	}

	stream := &relational.Evidence{
		UUID:  streamUUID,
		Title: fmt.Sprintf("Workflow Instance: %s", instance.Name),
		Description: fmt.Sprintf("Evidence stream for workflow instance %s of %s (v%s) on system %s",
			instance.Name, definition.Name, definition.Version, systemID),
		Start: time.Now(),
		End:   time.Now(),
	}

	// Generate unique ID for the stream record
	id := uuid.New()
	stream.ID = &id

	if err := e.db.Create(stream).Error; err != nil {
		return nil, fmt.Errorf("failed to create evidence stream: %w", err)
	}

	// Add labels via association
	if err := e.db.Model(stream).Association("Labels").Append(labels); err != nil {
		return nil, fmt.Errorf("failed to add labels to stream: %w", err)
	}

	e.logger.Infow("Instance evidence stream created",
		"stream_uuid", streamUUID,
		"stream_id", stream.ID,
		"workflow_instance_id", workflowInstanceID,
	)

	return stream, nil
}

// AddStepCompletionEvidence adds a step completion evidence record to the execution stream
// and links any user-submitted StepEvidence records to it
func (e *EvidenceIntegration) AddStepCompletionEvidence(ctx context.Context, stepExecutionID *uuid.UUID) error {
	// Get step execution
	stepExecution, err := e.stepExecutionSvc.GetByID(stepExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get step execution: %w", err)
	}

	// Get or create execution stream
	stream, err := e.GetOrCreateExecutionStream(ctx, stepExecution.WorkflowExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get execution stream: %w", err)
	}

	// Get step definition
	stepDef, err := e.stepDefinitionSvc.GetByID(stepExecution.WorkflowStepDefinitionID)
	if err != nil {
		return fmt.Errorf("failed to get step definition: %w", err)
	}

	// Get user-submitted step evidence
	var stepEvidences []workflows.StepEvidence
	if err := e.db.Where("step_execution_id = ?", stepExecutionID).Find(&stepEvidences).Error; err != nil {
		e.logger.Warnw("Failed to get step evidence", "error", err)
	}

	// Create individual evidence record for this step completion
	description := fmt.Sprintf("Step '%s' completed\nStatus: %s\nStarted: %s\nCompleted: %s",
		stepDef.Name,
		stepExecution.Status,
		stepExecution.StartedAt.Format(time.RFC3339),
		stepExecution.CompletedAt.Format(time.RFC3339),
	)

	if len(stepEvidences) > 0 {
		description += fmt.Sprintf("\nEvidence Submitted: %d items", len(stepEvidences))
	}

	// Build links to user-submitted evidence
	var links []relational.Link
	for _, stepEvidence := range stepEvidences {
		links = append(links, relational.Link{
			Href: fmt.Sprintf("#/evidence/%s", stepEvidence.ID.String()),
			Rel:  "related",
			Text: stepEvidence.Name,
		})
	}

	evidence := &relational.Evidence{
		UUID:        stream.UUID, // Same stream UUID
		Title:       fmt.Sprintf("Step Completion: %s", stepDef.Name),
		Description: description,
		Start:       *stepExecution.StartedAt,
		End:         *stepExecution.CompletedAt,
	}

	// Add links if we have any
	if len(links) > 0 {
		evidence.Links = links
	}

	// Generate unique ID for this evidence record
	id := uuid.New()
	evidence.ID = &id

	if err := e.db.Create(evidence).Error; err != nil {
		return fmt.Errorf("failed to create step evidence: %w", err)
	}

	// Add labels
	labels := []relational.Labels{
		{Name: "step.execution.id", Value: stepExecution.ID.String()},
		{Name: "step.definition.id", Value: stepDef.ID.String()},
		{Name: "step.name", Value: stepDef.Name},
		{Name: "step.status", Value: stepExecution.Status},
		{Name: "evidence.type", Value: "step_completion"},
		{Name: "evidence.submitted_count", Value: fmt.Sprintf("%d", len(stepEvidences))},
	}

	if err := e.db.Model(evidence).Association("Labels").Append(labels); err != nil {
		return fmt.Errorf("failed to add labels: %w", err)
	}

	e.logger.Infow("Step completion evidence added to stream",
		"stream_uuid", stream.UUID,
		"evidence_id", evidence.ID,
		"step_execution_id", stepExecutionID,
		"linked_evidence_count", len(stepEvidences),
	)

	return nil
}

// AddExecutionCompletionEvidence adds an execution completion evidence record to the instance stream
func (e *EvidenceIntegration) AddExecutionCompletionEvidence(ctx context.Context, workflowExecutionID *uuid.UUID) error {
	// Get workflow execution
	execution, err := e.workflowExecutionSvc.GetByID(workflowExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get workflow execution: %w", err)
	}

	// Only add completion evidence for completed executions
	if execution.Status != "completed" {
		return fmt.Errorf("workflow execution is not completed, status: %s", execution.Status)
	}

	// Get or create instance stream
	stream, err := e.GetOrCreateInstanceStream(ctx, execution.WorkflowInstanceID)
	if err != nil {
		return fmt.Errorf("failed to get instance stream: %w", err)
	}

	// Get step executions for metrics
	stepExecutions, err := e.stepExecutionSvc.GetByWorkflowExecutionID(workflowExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get step executions: %w", err)
	}

	// Build completion evidence description
	description := fmt.Sprintf("Workflow Execution Completed\nExecution ID: %s\nStarted: %s\nCompleted: %s\nTotal Steps: %d",
		execution.ID,
		execution.StartedAt.Format(time.RFC3339),
		execution.CompletedAt.Format(time.RFC3339),
		len(stepExecutions),
	)

	if execution.CompletedAt != nil {
		duration := execution.CompletedAt.Sub(*execution.StartedAt)
		description += fmt.Sprintf("\nDuration: %s", duration)
	}

	evidence := &relational.Evidence{
		UUID:        stream.UUID, // Same stream UUID
		Title:       "Workflow Execution Completed",
		Description: description,
		Start:       *execution.StartedAt,
		End:         *execution.CompletedAt,
	}

	// Generate unique ID for this evidence record
	id := uuid.New()
	evidence.ID = &id

	if err := e.db.Create(evidence).Error; err != nil {
		return fmt.Errorf("failed to create execution evidence: %w", err)
	}

	// Add labels
	labels := []relational.Labels{
		{Name: "workflow.execution.id", Value: execution.ID.String()},
		{Name: "workflow.execution.status", Value: execution.Status},
		{Name: "workflow.triggered_by", Value: execution.TriggeredBy},
		{Name: "workflow.step_count", Value: fmt.Sprintf("%d", len(stepExecutions))},
		{Name: "evidence.type", Value: "execution_completion"},
	}

	if err := e.db.Model(evidence).Association("Labels").Append(labels); err != nil {
		return fmt.Errorf("failed to add labels: %w", err)
	}

	e.logger.Infow("Execution completion evidence added to stream",
		"stream_uuid", stream.UUID,
		"evidence_id", evidence.ID,
		"workflow_execution_id", workflowExecutionID,
	)

	return nil
}

// generateExecutionStreamUUID generates a deterministic UUID for an execution stream based on labels
func (e *EvidenceIntegration) generateExecutionStreamUUID(
	definition *workflows.WorkflowDefinition,
	instance *workflows.WorkflowInstance,
	execution *workflows.WorkflowExecution,
) uuid.UUID {
	// Create a deterministic seed from execution context
	seed := fmt.Sprintf("execution:%s:%s:%s:%s",
		definition.ID.String(),
		instance.ID.String(),
		execution.ID.String(),
		"v1", // Version for future compatibility
	)

	hash := sha256.Sum256([]byte(seed))
	hashStr := hex.EncodeToString(hash[:16])

	// Parse as UUID
	streamUUID, _ := uuid.Parse(hashStr[:8] + "-" + hashStr[8:12] + "-" + hashStr[12:16] + "-" + hashStr[16:20] + "-" + hashStr[20:32])
	return streamUUID
}

// generateInstanceStreamUUID generates a deterministic UUID for an instance stream based on labels
func (e *EvidenceIntegration) generateInstanceStreamUUID(
	definition *workflows.WorkflowDefinition,
	instance *workflows.WorkflowInstance,
) uuid.UUID {
	// Create a deterministic seed from instance context
	seed := fmt.Sprintf("instance:%s:%s:%s",
		definition.ID.String(),
		instance.ID.String(),
		"v1", // Version for future compatibility
	)

	hash := sha256.Sum256([]byte(seed))
	hashStr := hex.EncodeToString(hash[:16])

	// Parse as UUID
	streamUUID, _ := uuid.Parse(hashStr[:8] + "-" + hashStr[8:12] + "-" + hashStr[12:16] + "-" + hashStr[16:20] + "-" + hashStr[20:32])
	return streamUUID
}

// buildExecutionStreamLabels builds labels for an execution stream
func (e *EvidenceIntegration) buildExecutionStreamLabels(
	definition *workflows.WorkflowDefinition,
	instance *workflows.WorkflowInstance,
	execution *workflows.WorkflowExecution,
) []relational.Labels {
	var systemID string
	if instance.SystemSecurityPlanID != nil {
		systemID = instance.SystemSecurityPlanID.String()
	} else {
		systemID = "unknown"
	}

	return []relational.Labels{
		{Name: "stream.type", Value: "workflow_execution"},
		{Name: "workflow.definition.id", Value: definition.ID.String()},
		{Name: "workflow.definition.name", Value: definition.Name},
		{Name: "workflow.definition.version", Value: definition.Version},
		{Name: "workflow.instance.id", Value: instance.ID.String()},
		{Name: "workflow.instance.name", Value: instance.Name},
		{Name: "workflow.instance.system_security_plan_id", Value: systemID},
		{Name: "workflow.execution.id", Value: execution.ID.String()},
		{Name: "workflow.triggered_by", Value: execution.TriggeredBy},
	}
}

// buildInstanceStreamLabels builds labels for an instance stream
func (e *EvidenceIntegration) buildInstanceStreamLabels(
	definition *workflows.WorkflowDefinition,
	instance *workflows.WorkflowInstance,
) []relational.Labels {
	var systemID string
	if instance.SystemSecurityPlanID != nil {
		systemID = instance.SystemSecurityPlanID.String()
	} else {
		systemID = "unknown"
	}

	return []relational.Labels{
		{Name: "stream.type", Value: "workflow_instance"},
		{Name: "workflow.definition.id", Value: definition.ID.String()},
		{Name: "workflow.definition.name", Value: definition.Name},
		{Name: "workflow.definition.version", Value: definition.Version},
		{Name: "workflow.instance.id", Value: instance.ID.String()},
		{Name: "workflow.instance.name", Value: instance.Name},
		{Name: "workflow.instance.system_security_plan_id", Value: systemID},
	}
}
