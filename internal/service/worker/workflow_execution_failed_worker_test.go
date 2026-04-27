package worker

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func makeFailedJob(args WorkflowExecutionFailedArgs) *river.Job[WorkflowExecutionFailedArgs] {
	return &river.Job[WorkflowExecutionFailedArgs]{Args: args}
}

func TestWorkflowExecutionFailedWorker_InvalidExecutionID_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	w := NewWorkflowExecutionFailedWorker(nil, mockRepo, "http://localhost:8000", newTestNotificationRuntimeProvider(mockEmail, nil), mockLog)

	err := w.Work(ctx, makeFailedJob(WorkflowExecutionFailedArgs{WorkflowExecutionID: "not-a-uuid"}))
	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}

func TestWorkflowExecutionFailedWorker_NilDB_ReturnsError(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	w := NewWorkflowExecutionFailedWorker(nil, mockRepo, "http://localhost:8000", newTestNotificationRuntimeProvider(mockEmail, nil), mockLog)

	err := w.Work(ctx, makeFailedJob(WorkflowExecutionFailedArgs{WorkflowExecutionID: uuid.New().String()}))
	assert.Error(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}

func TestWorkflowExecutionFailedWorker_SlackSubscribedUser_SendsAllAssociatedChannels(t *testing.T) {
	ctx := context.Background()
	db := newWorkflowNotificationJobsTestDB(t)
	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()
	createdByID := uuid.New()
	executionID := seedWorkflowExecutionFailedFixture(t, db, createdByID)

	user := NotificationUser{
		ID:          createdByID.String(),
		Email:       "owner@example.com",
		FirstName:   "Workflow",
		LastName:    "Owner",
		SlackUserID: "UWFEXEC1",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.SubscriptionGateTaskAvailable, Channels: []string{"slack"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, createdByID.String()).Return(user, nil)
	mockEmail.On("UseTemplate", "workflow-execution-failed", mock.Anything).Return("<html>failed</html>", "failed text", nil).Once()
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com").Once()
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == "owner@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "wf-exec-email-1"}, nil).Once()
	mockSlack.On("IsEnabled").Return(true).Once()
	mockSlack.On("SendMessage", ctx, "UWFEXEC1", mock.MatchedBy(func(msg *slacktypes.Message) bool {
		return msg != nil && msg.Text != ""
	})).Return(&slacktypes.SendResult{Success: true, DeliveryID: "wf-exec-slack-1"}, nil).Once()

	w := NewWorkflowExecutionFailedWorker(db, mockRepo, "http://localhost:8000", newTestNotificationRuntimeProvider(mockEmail, mockSlack), mockLog)

	err := w.Work(ctx, makeFailedJob(WorkflowExecutionFailedArgs{WorkflowExecutionID: executionID.String()}))
	assert.NoError(t, err)
	mockEmail.AssertExpectations(t)
	mockSlack.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func TestWorkflowExecutionFailedWorker_EmailAndSlackUser_SendsBoth(t *testing.T) {
	ctx := context.Background()
	db := newWorkflowNotificationJobsTestDB(t)
	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()
	createdByID := uuid.New()
	executionID := seedWorkflowExecutionFailedFixture(t, db, createdByID)

	user := NotificationUser{
		ID:          createdByID.String(),
		Email:       "owner@example.com",
		FirstName:   "Workflow",
		LastName:    "Owner",
		SlackUserID: "UWFEXEC2",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.SubscriptionGateTaskAvailable, Channels: []string{"email", "slack"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, createdByID.String()).Return(user, nil)
	mockEmail.On("UseTemplate", "workflow-execution-failed", mock.Anything).Return("<html>failed</html>", "failed text", nil).Once()
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com").Once()
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == "owner@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "wf-exec-email-1"}, nil).Once()
	mockSlack.On("IsEnabled").Return(true).Once()
	mockSlack.On("SendMessage", ctx, "UWFEXEC2", mock.MatchedBy(func(msg *slacktypes.Message) bool {
		return msg != nil && msg.Text != ""
	})).Return(&slacktypes.SendResult{Success: true, DeliveryID: "wf-exec-slack-2"}, nil).Once()

	w := NewWorkflowExecutionFailedWorker(db, mockRepo, "http://localhost:8000", newTestNotificationRuntimeProvider(mockEmail, mockSlack), mockLog)

	err := w.Work(ctx, makeFailedJob(WorkflowExecutionFailedArgs{WorkflowExecutionID: executionID.String()}))
	assert.NoError(t, err)
	mockEmail.AssertExpectations(t)
	mockSlack.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func seedWorkflowExecutionFailedFixture(t *testing.T, db *gorm.DB, createdByID uuid.UUID) uuid.UUID {
	t.Helper()

	sspID := uuid.New()
	require.NoError(t, db.Model(&relational.SystemSecurityPlan{}).Create(map[string]interface{}{
		"id": sspID,
	}).Error)

	definition := workflows.WorkflowDefinition{Name: "Quarterly Review"}
	require.NoError(t, db.Create(&definition).Error)

	instance := workflows.WorkflowInstance{
		Name:                 "Q2 2026",
		WorkflowDefinitionID: definition.ID,
		SystemSecurityPlanID: &sspID,
		CreatedByID:          &createdByID,
	}
	require.NoError(t, db.Create(&instance).Error)

	failedAt := time.Now().Add(-1 * time.Hour)
	execution := workflows.WorkflowExecution{
		Status:             workflows.WorkflowStatusFailed.String(),
		TriggeredBy:        "manual",
		WorkflowInstanceID: instance.ID,
		FailedAt:           &failedAt,
		FailureReason:      "step execution failed",
	}
	require.NoError(t, db.Create(&execution).Error)

	failedStepDefinition := workflows.WorkflowStepDefinition{
		Name:                 "Collect Evidence",
		ResponsibleRole:      "owner",
		WorkflowDefinitionID: definition.ID,
	}
	completedStepDefinition := workflows.WorkflowStepDefinition{
		Name:                 "Review Evidence",
		ResponsibleRole:      "owner",
		WorkflowDefinitionID: definition.ID,
	}
	require.NoError(t, db.Create(&failedStepDefinition).Error)
	require.NoError(t, db.Create(&completedStepDefinition).Error)

	require.NoError(t, db.Create(&workflows.StepExecution{
		Status:                   workflows.StepStatusFailed.String(),
		AssignedToType:           workflows.AssignmentTypeUser.String(),
		AssignedToID:             createdByID.String(),
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: failedStepDefinition.ID,
	}).Error)
	require.NoError(t, db.Create(&workflows.StepExecution{
		Status:                   workflows.StepStatusCompleted.String(),
		AssignedToType:           workflows.AssignmentTypeUser.String(),
		AssignedToID:             createdByID.String(),
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: completedStepDefinition.ID,
	}).Error)

	return *execution.ID
}
