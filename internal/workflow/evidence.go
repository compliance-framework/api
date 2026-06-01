package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// EvidenceIntegration handles evidence stream creation and management for workflow executions
// Design:
// - 1 evidence stream per workflow execution (accumulates step completion evidence)
// - 1 evidence stream per workflow instance (accumulates execution completion evidence)
// - Streams use label-seeded UUIDs for deterministic identification
type EvidenceIntegration struct {
	db                     *gorm.DB
	logger                 *zap.SugaredLogger
	workflowExecutionSvc   *workflows.WorkflowExecutionService
	stepExecutionSvc       *workflows.StepExecutionService
	workflowInstanceSvc    *workflows.WorkflowInstanceService
	workflowDefinitionSvc  *workflows.WorkflowDefinitionService
	stepDefinitionSvc      *workflows.WorkflowStepDefinitionService
	defaultGracePeriodDays int
}

// NewEvidenceIntegration creates a new evidence integration service
func NewEvidenceIntegration(
	db *gorm.DB,
	logger *zap.SugaredLogger,
	defaultGracePeriodDays ...int,
) *EvidenceIntegration {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

	gracePeriodDays := config.DefaultWorkflowConfig().GracePeriodDays
	if len(defaultGracePeriodDays) > 0 {
		gracePeriodDays = defaultGracePeriodDays[0]
	}

	return &EvidenceIntegration{
		db:                     db,
		logger:                 logger,
		workflowExecutionSvc:   workflows.NewWorkflowExecutionService(db),
		stepExecutionSvc:       workflows.NewStepExecutionService(db, nil),
		workflowInstanceSvc:    workflows.NewWorkflowInstanceService(db),
		workflowDefinitionSvc:  workflows.NewWorkflowDefinitionService(db),
		stepDefinitionSvc:      workflows.NewWorkflowStepDefinitionService(db),
		defaultGracePeriodDays: gracePeriodDays,
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

	e.logger.Infow("Instance evidence stream created",
		"stream_uuid", streamUUID,
		"stream_id", stream.ID,
		"workflow_instance_id", workflowInstanceID,
	)

	return stream, nil
}

// AddWorkflowExecutionEvidence adds a workflow execution evidence record.
func (e *EvidenceIntegration) AddWorkflowExecutionEvidence(ctx context.Context, workflowExecutionID *uuid.UUID, status string) error {
	// Get workflow execution
	execution, err := e.workflowExecutionSvc.GetByID(workflowExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get workflow execution: %w", err)
	}

	if status != "started" && status != "completed" {
		return fmt.Errorf("unsupported workflow execution evidence status %q; expected started or completed", status)
	}

	// Started evidence may be emitted right before or right after the transition.
	if status == "started" && execution.Status != "pending" && execution.Status != "in_progress" {
		return fmt.Errorf("workflow execution is not in pending or in_progress status, status: %s", execution.Status)
	}
	if status == "completed" && execution.Status != "in_progress" && execution.Status != "completed" {
		return fmt.Errorf("workflow execution is not in in_progress or completed status, status: %s", execution.Status)
	}
	if execution.StartedAt == nil {
		return fmt.Errorf("workflow execution %s evidence requires started_at", status)
	}

	// Get workflow definition through the instance
	instance, err := e.workflowInstanceSvc.GetByID(execution.WorkflowInstanceID)
	if err != nil {
		return fmt.Errorf("failed to get workflow instance: %w", err)
	}

	definition, err := e.workflowDefinitionSvc.GetByID(instance.WorkflowDefinitionID)
	if err != nil {
		return fmt.Errorf("failed to get workflow definition: %w", err)
	}
	var title string
	var description string
	var stream *relational.Evidence
	endTimestamp := execution.StartedAt
	switch status {
	case "started":
		stream, err = e.GetOrCreateExecutionStream(ctx, execution.ID)
		if err != nil {
			return fmt.Errorf("failed to get execution stream: %w", err)
		}
		title = fmt.Sprintf("Workflow Execution Started: %s", definition.Name)
		description = fmt.Sprintf("Workflow execution '%s' started at %s",
			execution.ID.String(),
			execution.StartedAt.Format(time.RFC3339),
		)
	case "completed":
		if execution.CompletedAt == nil {
			return fmt.Errorf("workflow execution completed evidence requires completed_at")
		}
		stream, err = e.GetOrCreateInstanceStream(ctx, execution.WorkflowInstanceID)
		if err != nil {
			return fmt.Errorf("failed to get instance stream: %w", err)
		}
		title = fmt.Sprintf("Workflow Execution Completed: %s", definition.Name)
		description = fmt.Sprintf("Workflow execution '%s' completed at %s",
			execution.ID.String(),
			execution.CompletedAt.Format(time.RFC3339),
		)
		endTimestamp = execution.CompletedAt
	default:
		return fmt.Errorf("unsupported workflow execution evidence status %q; expected started or completed", status)
	}
	// Create evidence record
	evidence := &relational.Evidence{
		UUID:        stream.UUID,
		Title:       title,
		Description: description,
		Start:       *execution.StartedAt,
		End:         *endTimestamp,
		Labels: []relational.Labels{
			{Name: "workflow.execution.id", Value: execution.ID.String()},
			{Name: "workflow.definition.id", Value: definition.ID.String()},
			{Name: "workflow.definition.name", Value: definition.Name},
			{Name: "workflow.instance.id", Value: execution.WorkflowInstanceID.String()},
			{Name: "evidence.type", Value: "workflow_execution_" + status},
		},
	}

	if status == "completed" {
		evidence.Status = datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		})
		evidence.Labels = append(evidence.Labels, e.buildWorkflowCoverageLabels(*definition.ID)...)
		evidence.Expires = e.calculateCompletionEvidenceExpires(execution.CompletedAt, instance, definition)
	}
	if err := e.db.Create(evidence).Error; err != nil {
		return fmt.Errorf("failed to create workflow execution evidence: %w", err)
	}

	e.logger.Infow("Workflow execution started evidence created", "workflow_execution_id", execution.ID, "status", execution.Status)
	return nil
}

// AddStepStartedEvidence adds a step started evidence record to the execution stream
func (e *EvidenceIntegration) AddStepStartedEvidence(ctx context.Context, stepExecutionID *uuid.UUID) error {
	// Get step execution
	stepExecution, err := e.stepExecutionSvc.GetByID(stepExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get step execution: %w", err)
	}

	// Started evidence may be emitted right before or right after transitioning to in_progress.
	if stepExecution.Status != "pending" && stepExecution.Status != "in_progress" {
		return fmt.Errorf("step execution is not in pending status, status: %s", stepExecution.Status)
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

	// Build step started evidence description
	description := fmt.Sprintf("Step '%s' started (transitioned from pending to in_progress)",
		stepDef.Name,
	)

	if stepExecution.StartedAt != nil {
		description += fmt.Sprintf("\nStarted: %s", stepExecution.StartedAt.Format(time.RFC3339))
	}

	evidence := &relational.Evidence{
		UUID:        stream.UUID, // Same stream UUID
		Title:       fmt.Sprintf("Step Started: %s", stepDef.Name),
		Description: description,
		Start:       time.Now(), // Use current time as evidence creation time
		End:         time.Now(),
	}

	// Generate unique ID for this evidence record
	id := uuid.New()
	evidence.ID = &id

	if err := e.db.Create(evidence).Error; err != nil {
		return fmt.Errorf("failed to create step started evidence: %w", err)
	}

	// Add labels
	labels := []relational.Labels{
		{Name: "step.execution.id", Value: stepExecution.ID.String()},
		{Name: "step.definition.id", Value: stepDef.ID.String()},
		{Name: "step.name", Value: stepDef.Name},
		{Name: "step.status", Value: stepExecution.Status},
		{Name: "evidence.type", Value: "step_started"},
	}

	if err := e.db.Model(evidence).Association("Labels").Append(labels); err != nil {
		return fmt.Errorf("failed to add labels: %w", err)
	}

	e.logger.Infow("Step started evidence added to execution stream",
		"stream_uuid", stream.UUID,
		"evidence_id", evidence.ID,
		"step_execution_id", stepExecutionID,
		"step_status", stepExecution.Status,
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
	if execution.StartedAt == nil {
		return fmt.Errorf("workflow execution completion evidence requires started_at")
	}
	if execution.CompletedAt == nil {
		return fmt.Errorf("workflow execution completion evidence requires completed_at")
	}

	// Get or create instance stream
	stream, err := e.GetOrCreateInstanceStream(ctx, execution.WorkflowInstanceID)
	if err != nil {
		return fmt.Errorf("failed to get instance stream: %w", err)
	}

	instance, err := e.workflowInstanceSvc.GetByID(execution.WorkflowInstanceID)
	if err != nil {
		return fmt.Errorf("failed to get workflow instance: %w", err)
	}

	definition, err := e.workflowDefinitionSvc.GetByID(instance.WorkflowDefinitionID)
	if err != nil {
		return fmt.Errorf("failed to get workflow definition: %w", err)
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
		Status:      datatypes.NewJSONType[oscalTypes_1_1_3.ObjectiveStatus](oscalTypes_1_1_3.ObjectiveStatus{State: relational.EvidenceStatusSatisfied}),
		Expires:     e.calculateCompletionEvidenceExpires(execution.CompletedAt, instance, definition),
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
	labels = append(labels, e.buildWorkflowCoverageLabels(*definition.ID)...)

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

// AddExecutionFailureEvidence adds workflow execution failure evidence to both execution and instance streams.
func (e *EvidenceIntegration) AddExecutionFailureEvidence(ctx context.Context, workflowExecutionID *uuid.UUID) error {
	execution, err := e.workflowExecutionSvc.GetByID(workflowExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get workflow execution: %w", err)
	}
	if execution.Status != workflows.WorkflowStatusFailed.String() {
		return fmt.Errorf("workflow execution is not failed, status: %s", execution.Status)
	}

	stepExecutions, err := e.stepExecutionSvc.GetByWorkflowExecutionID(workflowExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get step executions: %w", err)
	}

	completedCount := 0
	failedCount := 0
	overdueCount := 0
	unresolvedAssignees := make(map[string]struct{})
	for _, step := range stepExecutions {
		switch step.Status {
		case workflows.StepStatusCompleted.String():
			completedCount++
		case workflows.StepStatusOverdue.String():
			overdueCount++
		case workflows.StepStatusFailed.String():
			failedCount++
		}

		if step.Status != workflows.StepStatusCompleted.String() {
			key := step.AssignedToType + ":" + step.AssignedToID
			if step.AssignedToID != "" {
				unresolvedAssignees[key] = struct{}{}
			}
		}
	}

	assignees := make([]string, 0, len(unresolvedAssignees))
	for key := range unresolvedAssignees {
		assignees = append(assignees, key)
	}
	sort.Strings(assignees)

	const failureDescriptionTemplate = `Workflow Execution Failed
Execution ID: %s
Started: %s
Failed: %s
Completed Steps: %d
Failed Steps: %d
Overdue Steps: %d
Unresolved Assignees: %s`

	description := fmt.Sprintf(
		failureDescriptionTemplate,
		execution.ID,
		formatOptionalTime(execution.StartedAt),
		formatOptionalTime(execution.FailedAt),
		completedCount,
		failedCount,
		overdueCount,
		strings.Join(assignees, ","),
	)

	if err := e.addFailureEvidenceToStream(ctx, execution, description, completedCount, failedCount, overdueCount, assignees, true); err != nil {
		return err
	}
	if err := e.addFailureEvidenceToStream(ctx, execution, description, completedCount, failedCount, overdueCount, assignees, false); err != nil {
		return err
	}

	e.logger.Infow("Execution failure evidence added",
		"workflow_execution_id", workflowExecutionID,
		"failed_steps", failedCount,
		"overdue_steps", overdueCount,
	)
	return nil
}

func (e *EvidenceIntegration) addFailureEvidenceToStream(
	ctx context.Context,
	execution *workflows.WorkflowExecution,
	description string,
	completedCount int,
	failedCount int,
	overdueCount int,
	unresolvedAssignees []string,
	executionStream bool,
) error {
	var stream *relational.Evidence
	var err error
	var coverageLabels []relational.Labels
	if executionStream {
		stream, err = e.GetOrCreateExecutionStream(ctx, execution.ID)
	} else {
		instance, instanceErr := e.workflowInstanceSvc.GetByID(execution.WorkflowInstanceID)
		if instanceErr != nil {
			return fmt.Errorf("failed to get workflow instance: %w", instanceErr)
		}
		if instance.WorkflowDefinitionID == nil {
			return fmt.Errorf("workflow instance %s has no workflow definition id", execution.WorkflowInstanceID)
		}
		coverageLabels = e.buildWorkflowCoverageLabels(*instance.WorkflowDefinitionID)

		stream, err = e.GetOrCreateInstanceStream(ctx, execution.WorkflowInstanceID)
	}
	if err != nil {
		return err
	}

	evidence := &relational.Evidence{
		UUID:        stream.UUID,
		Title:       "Workflow Execution Failed",
		Description: description,
		Start:       nowOrValue(execution.StartedAt),
		End:         nowOrValue(execution.FailedAt),
		Status:      datatypes.NewJSONType[oscalTypes_1_1_3.ObjectiveStatus](oscalTypes_1_1_3.ObjectiveStatus{State: relational.EvidenceStatusNotSatisfied}),
	}
	id := uuid.New()
	evidence.ID = &id
	if err := e.db.Create(evidence).Error; err != nil {
		return err
	}

	labels := []relational.Labels{
		{Name: "workflow.execution.id", Value: execution.ID.String()},
		{Name: "workflow.execution.status", Value: execution.Status},
		{Name: "evidence.type", Value: "execution_failure"},
		{Name: "workflow.failed_steps", Value: fmt.Sprintf("%d", failedCount)},
		{Name: "workflow.overdue_steps", Value: fmt.Sprintf("%d", overdueCount)},
		{Name: "workflow.completed_steps", Value: fmt.Sprintf("%d", completedCount)},
		{Name: "workflow.unresolved_assignees", Value: strings.Join(unresolvedAssignees, ",")},
	}
	if !executionStream {
		labels = append(labels, coverageLabels...)
	}

	return e.db.Model(evidence).Association("Labels").Append(labels)
}

func formatOptionalTime(ts *time.Time) string {
	if ts == nil {
		return "unknown"
	}
	return ts.Format(time.RFC3339)
}

func nowOrValue(ts *time.Time) time.Time {
	if ts == nil {
		return time.Now()
	}
	return *ts
}

func (e *EvidenceIntegration) buildWorkflowCoverageLabels(definitionID uuid.UUID) []relational.Labels {
	return []relational.Labels{
		{Name: workflows.WorkflowEvidencePolicyLabel, Value: workflows.WorkflowPolicyValue(definitionID)},
		{Name: workflows.WorkflowEvidencePluginLabel, Value: workflows.WorkflowEvidencePluginValue},
	}
}

func (e *EvidenceIntegration) calculateCompletionEvidenceExpires(completedAt *time.Time, instance *workflows.WorkflowInstance, definition *workflows.WorkflowDefinition) *time.Time {
	if completedAt == nil {
		return nil
	}
	effectiveInstance := instance
	if definition != nil && instance != nil {
		instanceCopy := *instance
		instanceCopy.WorkflowDefinition = definition
		effectiveInstance = &instanceCopy
	}

	cadence := ""
	if effectiveInstance != nil {
		cadence = effectiveInstance.Cadence
	}
	if cadence == "" && definition != nil {
		cadence = definition.SuggestedCadence
	}

	graceDays := ResolveGraceDays(effectiveInstance, e.defaultGracePeriodDays)
	expires := nextCadenceExpiryBase(*completedAt, cadence).AddDate(0, 0, graceDays)
	return &expires
}

func nextCadenceExpiryBase(completedAt time.Time, cadence string) time.Time {
	cadenceType := workflows.CadenceType(cadence)
	if cadenceType.IsCron() {
		parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		schedule, err := parser.Parse(cadenceType.CronExpression())
		if err != nil {
			return completedAt.AddDate(0, 1, 0)
		}
		return schedule.Next(completedAt)
	}

	switch cadenceType {
	case workflows.CadenceDaily:
		return completedAt.AddDate(0, 0, 1)
	case workflows.CadenceWeekly:
		return completedAt.AddDate(0, 0, 7)
	case workflows.CadenceQuarterly:
		return completedAt.AddDate(0, 3, 0)
	case workflows.CadenceAnnually:
		return completedAt.AddDate(1, 0, 0)
	case workflows.CadenceMonthly:
		return completedAt.AddDate(0, 1, 0)
	default:
		return completedAt.AddDate(0, 1, 0)
	}
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
