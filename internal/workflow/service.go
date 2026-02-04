package workflow

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// RiverClient interface for job enqueueing (enables testing)
type RiverClient interface {
	InsertMany(ctx context.Context, params []river.InsertManyParams) ([]*rivertype.JobInsertResult, error)
}

// WorkflowService provides workflow execution capabilities via River job queue
type WorkflowService struct {
	executor    *DAGExecutor
	riverClient RiverClient
}

// NewWorkflowService creates a new workflow service
func NewWorkflowService(executor *DAGExecutor, riverClient RiverClient) (*WorkflowService, error) {
	if riverClient == nil {
		return nil, fmt.Errorf("river client is required for workflow service")
	}
	return &WorkflowService{
		executor:    executor,
		riverClient: riverClient,
	}, nil
}

// NewWorkflowServiceWithRiver creates a workflow service with a River client
func NewWorkflowServiceWithRiver(executor *DAGExecutor, riverClient *river.Client[pgx.Tx]) (*WorkflowService, error) {
	return NewWorkflowService(executor, riverClient)
}

// EnqueueWorkflowExecution enqueues a workflow execution job
func (s *WorkflowService) EnqueueWorkflowExecution(ctx context.Context, workflowExecutionID *uuid.UUID, triggeredBy, triggeredByID string) error {
	args := &ExecuteWorkflowArgs{
		WorkflowExecutionID: *workflowExecutionID,
		TriggeredBy:         triggeredBy,
		TriggeredByID:       triggeredByID,
	}

	// Insert the job
	_, err := s.riverClient.InsertMany(ctx, []river.InsertManyParams{
		{Args: args, InsertOpts: JobInsertOptionsForWorkflow()},
	})
	if err != nil {
		return fmt.Errorf("failed to enqueue workflow execution job: %w", err)
	}

	return nil
}

// GetExecutor returns the underlying DAG executor (for testing)
func (s *WorkflowService) GetExecutor() *DAGExecutor {
	return s.executor
}
