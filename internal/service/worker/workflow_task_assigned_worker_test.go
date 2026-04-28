package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) FindUserByID(ctx context.Context, userID string) (NotificationUser, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(NotificationUser), args.Error(1)
}

func makeTaskAssignedJob(args WorkflowTaskAssignedArgs) *river.Job[WorkflowTaskAssignedArgs] {
	return &river.Job[WorkflowTaskAssignedArgs]{Args: args}
}

func TestWorkflowTaskAssignedWorker_SubscribedUser_SendsEmail(t *testing.T) {
	ctx := context.Background()
	dueDate := time.Now().Add(48 * time.Hour)

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	user := NotificationUser{
		ID:        "user-1",
		Email:     "alice@example.com",
		FirstName: "Alice",
		LastName:  "Smith",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.SubscriptionGateTaskAvailable, Channels: []string{"email"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, "user-1").Return(user, nil)
	mockEmail.On("UseTemplate", "workflow-task-assigned", mock.Anything).Return("<html>Task</html>", "Task text", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return msg.To[0] == "alice@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "msg-1"}, nil)

	w := NewWorkflowTaskAssignedWorker(
		mockRepo,
		"http://localhost:8000",
		newTestNotificationRuntimeProvider(mockEmail, nil),
		mockLog,
	)

	args := WorkflowTaskAssignedArgs{
		UserID:                "user-1",
		StepExecutionID:       "step-1",
		StepTitle:             "Review Policy",
		WorkflowTitle:         "Annual Audit",
		WorkflowInstanceTitle: "Audit 2026",
		StepURL:               "https://app.example.com/steps/step-1",
		DueDate:               &dueDate,
	}

	err := w.Work(ctx, makeTaskAssignedJob(args))
	assert.NoError(t, err)
	mockEmail.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func TestWorkflowTaskAssignedWorker_UnsubscribedUser_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	user := NotificationUser{
		ID:        "user-2",
		Email:     "bob@example.com",
		FirstName: "Bob",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.SubscriptionGateTaskAvailable, Channels: []string{}},
		},
	}
	mockRepo.On("FindUserByID", ctx, "user-2").Return(user, nil)

	w := NewWorkflowTaskAssignedWorker(
		mockRepo,
		"http://localhost:8000",
		newTestNotificationRuntimeProvider(mockEmail, nil),
		mockLog,
	)

	args := WorkflowTaskAssignedArgs{
		UserID:          "user-2",
		StepExecutionID: "step-2",
		StepTitle:       "Review Policy",
		WorkflowTitle:   "Annual Audit",
	}

	err := w.Work(ctx, makeTaskAssignedJob(args))
	assert.NoError(t, err)
	// Send must NOT be called
	mockEmail.AssertNotCalled(t, "Send")
}

func TestWorkflowTaskAssignedWorker_UserNotFound_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	mockRepo.On("FindUserByID", ctx, "missing-user").Return(NotificationUser{}, errors.New("not found"))

	w := NewWorkflowTaskAssignedWorker(
		mockRepo,
		"http://localhost:8000",
		newTestNotificationRuntimeProvider(mockEmail, nil),
		mockLog,
	)

	args := WorkflowTaskAssignedArgs{
		UserID:          "missing-user",
		StepExecutionID: "step-3",
	}

	err := w.Work(ctx, makeTaskAssignedJob(args))
	// Should return nil (non-fatal skip)
	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}

func TestWorkflowTaskAssignedWorker_TemplateError_ReturnsError(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	user := NotificationUser{
		ID:        "user-3",
		Email:     "carol@example.com",
		FirstName: "Carol",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.SubscriptionGateTaskAvailable, Channels: []string{"email"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, "user-3").Return(user, nil)
	mockEmail.On("UseTemplate", "workflow-task-assigned", mock.Anything).Return("", "", errors.New("template broken"))
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")

	w := NewWorkflowTaskAssignedWorker(
		mockRepo,
		"http://localhost:8000",
		newTestNotificationRuntimeProvider(mockEmail, nil),
		mockLog,
	)

	args := WorkflowTaskAssignedArgs{
		UserID:          "user-3",
		StepExecutionID: "step-4",
		StepTitle:       "Review",
		WorkflowTitle:   "Audit",
	}

	err := w.Work(ctx, makeTaskAssignedJob(args))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow-task-assigned template")
}

func TestWorkflowTaskAssignedWorker_MultiChannel_EmailChannelJob_SendsOnlyEmail(t *testing.T) {
	ctx := context.Background()
	dueDate := time.Now().Add(48 * time.Hour)

	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	user := NotificationUser{
		ID:          "user-4",
		Email:       "dora@example.com",
		FirstName:   "Dora",
		SlackUserID: "U12345",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.SubscriptionGateTaskAvailable, Channels: []string{"slack", "email"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, "user-4").Return(user, nil)
	mockEmail.On("UseTemplate", "workflow-task-assigned", mock.Anything).Return("<html>Task</html>", "Task text", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return msg.To[0] == "dora@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "msg-4"}, nil).Once()

	w := NewWorkflowTaskAssignedWorker(
		mockRepo,
		"http://localhost:8000",
		newTestNotificationRuntimeProvider(mockEmail, mockSlack),
		mockLog,
	)

	args := WorkflowTaskAssignedArgs{
		Channel:               notification.DeliveryChannelEmail,
		UserID:                "user-4",
		StepExecutionID:       "step-4",
		StepTitle:             "Review Policy",
		WorkflowTitle:         "Annual Audit",
		WorkflowInstanceTitle: "Audit 2026",
		StepURL:               "https://app.example.com/steps/step-4",
		DueDate:               &dueDate,
	}

	err := w.Work(ctx, makeTaskAssignedJob(args))
	assert.NoError(t, err)
	mockEmail.AssertExpectations(t)
	mockSlack.AssertNotCalled(t, "IsEnabled")
	mockSlack.AssertNotCalled(t, "SendMessage", mock.Anything, mock.Anything, mock.Anything)
	mockRepo.AssertExpectations(t)
}

func TestWorkflowTaskAssignedWorker_MultiChannel_SlackChannelJob_SendsOnlySlack(t *testing.T) {
	ctx := context.Background()
	dueDate := time.Now().Add(48 * time.Hour)

	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	user := NotificationUser{
		ID:          "user-5",
		Email:       "ella@example.com",
		FirstName:   "Ella",
		SlackUserID: "USLACK5",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.SubscriptionGateTaskAvailable, Channels: []string{"slack", "email"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, "user-5").Return(user, nil)
	mockSlack.On("IsEnabled").Return(true).Once()
	mockSlack.On("SendMessage", ctx, "USLACK5", mock.MatchedBy(func(msg *slacktypes.Message) bool {
		return msg != nil && msg.Text != ""
	})).Return(&slacktypes.SendResult{Success: true, DeliveryID: "slack-msg-5"}, nil).Once()

	w := NewWorkflowTaskAssignedWorker(
		mockRepo,
		"http://localhost:8000",
		newTestNotificationRuntimeProvider(mockEmail, mockSlack),
		mockLog,
	)

	args := WorkflowTaskAssignedArgs{
		Channel:               notification.DeliveryChannelSlack,
		UserID:                "user-5",
		StepExecutionID:       "step-5",
		StepTitle:             "Review Policy",
		WorkflowTitle:         "Annual Audit",
		WorkflowInstanceTitle: "Audit 2026",
		StepURL:               "https://app.example.com/steps/step-5",
		DueDate:               &dueDate,
	}

	err := w.Work(ctx, makeTaskAssignedJob(args))
	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "UseTemplate", mock.Anything, mock.Anything)
	mockEmail.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
	mockSlack.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func TestWorkflowTaskAssignedWorker_EmailAssignee_SendsDirectEmailWithoutUserLookup(t *testing.T) {
	ctx := context.Background()
	dueDate := time.Now().Add(48 * time.Hour)

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	mockEmail.On("UseTemplate", "workflow-task-assigned", mock.Anything).Return("<html>Task</html>", "Task text", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == "external@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "msg-external"}, nil).Once()

	w := NewWorkflowTaskAssignedWorker(
		mockRepo,
		"http://localhost:8000",
		newTestNotificationRuntimeProvider(mockEmail, nil),
		mockLog,
	)

	args := WorkflowTaskAssignedArgs{
		AssignedToType:        workflows.AssignmentTypeEmail.String(),
		UserID:                "external@example.com",
		StepExecutionID:       "step-external",
		StepTitle:             "Submit Policy",
		WorkflowTitle:         "Annual Audit",
		WorkflowInstanceTitle: "Audit 2026",
		StepURL:               "https://app.example.com/steps/step-external",
		DueDate:               &dueDate,
	}

	err := w.Work(ctx, makeTaskAssignedJob(args))
	assert.NoError(t, err)
	mockEmail.AssertExpectations(t)
	mockRepo.AssertNotCalled(t, "FindUserByID", mock.Anything, mock.Anything)
}

func TestWorkflowTaskAssignedWorker_WithNotificationEnqueuer_EnqueuesSubscribedChannels(t *testing.T) {
	ctx := context.Background()
	client := &stubRiverClient{}
	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()
	db := newWorkflowNotificationJobsTestDB(t)

	user := NotificationUser{
		ID:          "user-7",
		Email:       "grace@example.com",
		FirstName:   "Grace",
		SlackUserID: "USLACK7",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.SubscriptionGateTaskAvailable, Channels: []string{"slack", "email"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, "user-7").Return(user, nil)
	mockEmail.On("UseTemplate", "workflow-task-assigned", mock.Anything).Return("<html>Task</html>", "Task text", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")

	w := NewWorkflowTaskAssignedWorker(
		mockRepo,
		"http://localhost:8000",
		newWorkerNotificationRuntimeProvider(mockEmail, nil, func() notification.WorkerEnqueuer {
			return newWorkerNotificationEnqueuer(client, "email", 5)
		}),
		mockLog,
	)
	w.db = db

	sspID := uuid.New()
	require.NoError(t, db.Model(&relational.SystemSecurityPlan{}).Create(map[string]interface{}{
		"id": sspID,
	}).Error)

	definition := workflows.WorkflowDefinition{Name: "Annual Audit"}
	require.NoError(t, db.Create(&definition).Error)

	instance := workflows.WorkflowInstance{
		Name:                 "Audit 2026",
		WorkflowDefinitionID: definition.ID,
		SystemSecurityPlanID: &sspID,
	}
	require.NoError(t, db.Create(&instance).Error)

	execution := workflows.WorkflowExecution{
		Status:             workflows.WorkflowStatusPending.String(),
		TriggeredBy:        workflows.TriggerManual.String(),
		WorkflowInstanceID: instance.ID,
	}
	require.NoError(t, db.Create(&execution).Error)

	stepDefinition := workflows.WorkflowStepDefinition{
		Name:                 "Review Policy",
		ResponsibleRole:      "owner",
		WorkflowDefinitionID: definition.ID,
	}
	require.NoError(t, db.Create(&stepDefinition).Error)

	dueDate := time.Now().Add(48 * time.Hour)
	stepExecution := workflows.StepExecution{
		Status:                   workflows.StepStatusPending.String(),
		AssignedToType:           workflows.AssignmentTypeUser.String(),
		AssignedToID:             "user-7",
		DueDate:                  &dueDate,
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDefinition.ID,
	}
	require.NoError(t, db.Create(&stepExecution).Error)

	args := WorkflowTaskAssignedArgs{
		AssignedToType:  workflows.AssignmentTypeUser.String(),
		UserID:          "user-7",
		StepExecutionID: stepExecution.ID.String(),
	}

	err := w.Work(ctx, makeTaskAssignedJob(args))
	require.NoError(t, err)
	require.Len(t, client.params, 2)

	var (
		emailJobs int
		slackJobs int
	)
	for _, param := range client.params {
		require.NotNil(t, param.InsertOpts)

		switch jobArgs := param.Args.(type) {
		case *SendEmailArgs:
			emailJobs++
			assert.Equal(t, []string{"grace@example.com"}, jobArgs.To)
			assert.Equal(t, JobTypeWorkflowTaskAssigned, jobArgs.NotificationKind)
			assert.Equal(t, "user-7", jobArgs.RecipientUserID)
			assert.Equal(t, "email", param.InsertOpts.Queue)
		case SendSlackDMArgs:
			slackJobs++
			assert.Equal(t, "USLACK7", jobArgs.Channel)
			assert.Equal(t, slackprovider.TargetTypeDirectMessage, jobArgs.TargetType)
			assert.Contains(t, jobArgs.Text, "Review Policy")
			assert.Contains(t, jobArgs.Text, "Annual Audit")
			assert.Equal(t, JobTypeWorkflowTaskAssigned, jobArgs.NotificationKind)
			assert.Equal(t, "user-7", jobArgs.RecipientUserID)
			assert.Equal(t, JobTypeWorkflowTaskAssigned, jobArgs.SourceJobKind)
			assert.Equal(t, "workflow_task_assigned:"+stepExecution.ID.String(), jobArgs.CorrelationID)
			assert.Equal(t, "slack", param.InsertOpts.Queue)
		default:
			t.Fatalf("unexpected job args type %T", param.Args)
		}
	}

	assert.Equal(t, 1, emailJobs)
	assert.Equal(t, 1, slackJobs)
	mockEmail.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}
