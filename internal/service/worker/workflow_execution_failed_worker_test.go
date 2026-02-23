package worker

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func makeFailedJob(args WorkflowExecutionFailedArgs) *river.Job[WorkflowExecutionFailedArgs] {
	return &river.Job[WorkflowExecutionFailedArgs]{Args: args}
}

func TestWorkflowExecutionFailedWorker_InvalidExecutionID_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	w := NewWorkflowExecutionFailedWorker(nil, mockEmail, mockRepo, "http://localhost:8000", mockLog)

	err := w.Work(ctx, makeFailedJob(WorkflowExecutionFailedArgs{WorkflowExecutionID: "not-a-uuid"}))
	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}

func TestWorkflowExecutionFailedWorker_NilDB_ReturnsError(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	w := NewWorkflowExecutionFailedWorker(nil, mockEmail, mockRepo, "http://localhost:8000", mockLog)

	err := w.Work(ctx, makeFailedJob(WorkflowExecutionFailedArgs{WorkflowExecutionID: uuid.New().String()}))
	assert.Error(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}
