package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type countingNotificationUserRepository struct {
	users       map[string]NotificationUser
	lookupCount int
}

func (r *countingNotificationUserRepository) FindUserByID(_ context.Context, userID string) (NotificationUser, error) {
	r.lookupCount++

	user, ok := r.users[userID]
	if !ok {
		return NotificationUser{}, fmt.Errorf("user %s not found", userID)
	}

	return user, nil
}

func TestWorkflowTaskAssignedInsertParams_EnqueuesSingleWrapperJob(t *testing.T) {
	params := workflowTaskAssignedInsertParams(WorkflowTaskAssignedArgs{
		AssignedToType:  workflows.AssignmentTypeUser.String(),
		UserID:          "user-1",
		StepExecutionID: "step-1",
	})

	require.Len(t, params, 1)

	args, ok := params[0].Args.(WorkflowTaskAssignedArgs)
	require.True(t, ok)
	assert.Empty(t, args.Channel)
	require.NotNil(t, params[0].InsertOpts)
	assert.True(t, params[0].InsertOpts.UniqueOpts.ByArgs)
}

func TestWorkflowTaskAssignedInsertParams_EmailAssigneeOnlyEnqueuesEmail(t *testing.T) {
	params := workflowTaskAssignedInsertParams(WorkflowTaskAssignedArgs{
		AssignedToType:  workflows.AssignmentTypeEmail.String(),
		UserID:          "external@example.com",
		StepExecutionID: "step-2",
	})

	require.Len(t, params, 1)

	args, ok := params[0].Args.(WorkflowTaskAssignedArgs)
	require.True(t, ok)
	assert.Empty(t, args.Channel)
}

func TestWorkflowTaskAssignedArgs_JSONOmitsHydratedFieldsWhenEmpty(t *testing.T) {
	args := WorkflowTaskAssignedArgs{
		AssignedToType:  workflows.AssignmentTypeUser.String(),
		UserID:          "user-1",
		StepExecutionID: "step-1",
	}

	payload, err := json.Marshal(args)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"assigned_to_type":"user",
		"user_id":"user-1",
		"step_execution_id":"step-1"
	}`, string(payload))
}

func TestDueSoonCheckerWorker_EnqueuesOneJobPerChannel(t *testing.T) {
	db := newWorkflowNotificationJobsTestDB(t)
	client := &stubRiverClient{}
	worker := NewDueSoonCheckerWorker(
		db,
		"http://localhost:8000",
		newWorkerNotificationRuntimeProvider(nil, nil, func() notification.WorkerEnqueuer {
			return newWorkerNotificationEnqueuer(client, "email", 5)
		}),
		zap.NewNop().Sugar(),
	)

	userID := uuid.New()
	createWorkflowNotificationUser(t, db, userID, "alice@example.com", "UALICE")
	require.NoError(t, db.Create(&relational.UserNotificationSubscription{
		UserID:           userID.String(),
		NotificationType: notification.NotificationTypeTaskAvailable,
		Channels: datatypes.JSONSlice[string]{
			notification.DeliveryChannelEmail,
			notification.DeliveryChannelSlack,
		},
	}).Error)

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
	}
	require.NoError(t, db.Create(&instance).Error)

	execution := workflows.WorkflowExecution{
		Status:             workflows.WorkflowStatusPending.String(),
		TriggeredBy:        workflows.TriggerManual.String(),
		WorkflowInstanceID: instance.ID,
	}
	require.NoError(t, db.Create(&execution).Error)

	stepDefinition := workflows.WorkflowStepDefinition{
		Name:                 "Submit Evidence",
		ResponsibleRole:      "owner",
		WorkflowDefinitionID: definition.ID,
	}
	require.NoError(t, db.Create(&stepDefinition).Error)

	dueDate := time.Now().Add(3 * 24 * time.Hour)
	stepExecution := workflows.StepExecution{
		Status:                   workflows.StepStatusPending.String(),
		AssignedToType:           workflows.AssignmentTypeUser.String(),
		AssignedToID:             userID.String(),
		DueDate:                  &dueDate,
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDefinition.ID,
	}
	require.NoError(t, db.Create(&stepExecution).Error)

	err := worker.Work(context.Background(), &river.Job[DueSoonCheckerArgs]{Args: DueSoonCheckerArgs{}})
	require.NoError(t, err)
	require.Len(t, client.params, 2)

	var (
		emailJobs int
		slackJobs int
	)
	for _, param := range client.params {
		require.NotNil(t, param.InsertOpts)

		switch args := param.Args.(type) {
		case *SendEmailArgs:
			emailJobs++
			assert.Equal(t, []string{"alice@example.com"}, args.To)
			assert.Equal(t, JobTypeWorkflowTaskDueSoon, args.NotificationKind)
			assert.Equal(t, userID.String(), args.RecipientUserID)
			assert.Equal(t, "email", param.InsertOpts.Queue)
		case SendSlackDMArgs:
			slackJobs++
			assert.Equal(t, "UALICE", args.Channel)
			assert.Equal(t, slackprovider.TargetTypeDirectMessage, args.TargetType)
			assert.Equal(t, JobTypeWorkflowTaskDueSoon, args.NotificationKind)
			assert.Equal(t, userID.String(), args.RecipientUserID)
			assert.Equal(t, "slack", param.InsertOpts.Queue)
		default:
			t.Fatalf("unexpected job args type %T", param.Args)
		}
	}

	assert.Equal(t, 1, emailJobs)
	assert.Equal(t, 1, slackJobs)
}

func TestDueSoonCheckerWorker_CachesFetchedUsersAcrossDispatches(t *testing.T) {
	db := newWorkflowNotificationJobsTestDB(t)
	client := &stubRiverClient{}

	userID := uuid.New().String()
	repo := &countingNotificationUserRepository{
		users: map[string]NotificationUser{
			userID: {
				ID:        userID,
				Email:     "alice@example.com",
				FirstName: "Alice",
				LastName:  "User",
				NotificationSubscriptions: []NotificationSubscription{
					{
						NotificationType: notification.NotificationTypeTaskAvailable,
						Channels:         []string{notification.DeliveryChannelEmail},
					},
				},
			},
		},
	}

	worker := &DueSoonCheckerWorker{
		db: db,
		notificationRuntimeProvider: newWorkerNotificationRuntimeProvider(nil, nil, func() notification.WorkerEnqueuer {
			return newWorkerNotificationEnqueuer(client, "email", 5)
		}),
		userRepo:   repo,
		webBaseURL: "http://localhost:8000",
		logger:     zap.NewNop().Sugar(),
	}

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
	}
	require.NoError(t, db.Create(&instance).Error)

	execution := workflows.WorkflowExecution{
		Status:             workflows.WorkflowStatusPending.String(),
		TriggeredBy:        workflows.TriggerManual.String(),
		WorkflowInstanceID: instance.ID,
	}
	require.NoError(t, db.Create(&execution).Error)

	dueDate := time.Now().Add(3 * 24 * time.Hour)
	for i := range 2 {
		stepDefinition := workflows.WorkflowStepDefinition{
			Name:                 fmt.Sprintf("Submit Evidence %d", i+1),
			ResponsibleRole:      "owner",
			WorkflowDefinitionID: definition.ID,
		}
		require.NoError(t, db.Create(&stepDefinition).Error)

		stepExecution := workflows.StepExecution{
			Status:                   workflows.StepStatusPending.String(),
			AssignedToType:           workflows.AssignmentTypeUser.String(),
			AssignedToID:             userID,
			DueDate:                  &dueDate,
			WorkflowExecutionID:      execution.ID,
			WorkflowStepDefinitionID: stepDefinition.ID,
		}
		require.NoError(t, db.Create(&stepExecution).Error)
	}

	err := worker.Work(context.Background(), &river.Job[DueSoonCheckerArgs]{Args: DueSoonCheckerArgs{}})
	require.NoError(t, err)
	assert.Equal(t, 1, repo.lookupCount)
	require.Len(t, client.params, 2)
}

func TestWorkflowTaskDigestCheckerWorker_EnqueuesOneJobPerSubscribedUser(t *testing.T) {
	db := newWorkflowNotificationJobsTestDB(t)
	client := &stubRiverClient{}
	worker := NewWorkflowTaskDigestCheckerWorker(db, client, zap.NewNop().Sugar())

	userOneID := uuid.New()
	userTwoID := uuid.New()
	missingUserID := uuid.New()

	createWorkflowNotificationUser(t, db, userOneID, "alice@example.com")
	createWorkflowNotificationUser(t, db, userTwoID, "bob@example.com")

	require.NoError(t, db.Create(&relational.UserNotificationSubscription{
		UserID:           userOneID.String(),
		NotificationType: notification.NotificationTypeTaskDailyDigest,
		Channels: datatypes.JSONSlice[string]{
			notification.DeliveryChannelEmail,
			notification.DeliveryChannelSlack,
		},
	}).Error)
	require.NoError(t, db.Create(&relational.UserNotificationSubscription{
		UserID:           userTwoID.String(),
		NotificationType: notification.NotificationTypeTaskDailyDigest,
		Channels:         datatypes.JSONSlice[string]{notification.DeliveryChannelEmail},
	}).Error)
	require.NoError(t, db.Create(&relational.UserNotificationSubscription{
		UserID:           missingUserID.String(),
		NotificationType: notification.NotificationTypeTaskDailyDigest,
		Channels:         datatypes.JSONSlice[string]{notification.DeliveryChannelSlack},
	}).Error)

	err := worker.Work(context.Background(), &river.Job[WorkflowTaskDigestCheckerArgs]{Args: WorkflowTaskDigestCheckerArgs{}})
	require.NoError(t, err)
	require.Len(t, client.params, 2)

	got := make(map[string]string)
	for _, param := range client.params {
		args, ok := param.Args.(WorkflowTaskDigestArgs)
		require.True(t, ok)
		got[args.UserID] = args.Channel
	}

	assert.Equal(t, "", got[userOneID.String()])
	assert.Equal(t, "", got[userTwoID.String()])
	_, exists := got[missingUserID.String()]
	assert.False(t, exists)
}

func newWorkflowNotificationJobsTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&relational.User{},
		&relational.SlackUserLink{},
		&relational.UserNotificationSubscription{},
		&relational.SystemSecurityPlan{},
		&workflows.WorkflowDefinition{},
		&workflows.WorkflowInstance{},
		&workflows.WorkflowExecution{},
		&workflows.WorkflowStepDefinition{},
		&workflows.StepExecution{},
	))

	return db
}

func createWorkflowNotificationUser(t *testing.T, db *gorm.DB, id uuid.UUID, email string, slackUserID ...string) {
	t.Helper()

	require.NoError(t, db.Model(&relational.User{}).Create(map[string]interface{}{
		"id":          id,
		"email":       email,
		"first_name":  "Test",
		"last_name":   "User",
		"auth_method": "password",
	}).Error)

	if len(slackUserID) > 0 && slackUserID[0] != "" {
		require.NoError(t, db.Create(&relational.SlackUserLink{
			UserID:      id.String(),
			SlackUserID: slackUserID[0],
			SlackTeamID: "T-TEST",
		}).Error)
	}
}
