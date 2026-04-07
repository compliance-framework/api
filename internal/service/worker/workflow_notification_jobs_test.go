package worker

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
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

func TestWorkflowTaskAssignedInsertParams_UserAssigneeSplitsByChannel(t *testing.T) {
	params := workflowTaskAssignedInsertParams(WorkflowTaskAssignedArgs{
		AssignedToType:  workflows.AssignmentTypeUser.String(),
		UserID:          "user-1",
		StepExecutionID: "step-1",
	})

	require.Len(t, params, 2)

	var channels []string
	for _, param := range params {
		args, ok := param.Args.(WorkflowTaskAssignedArgs)
		require.True(t, ok)
		channels = append(channels, args.Channel)
		require.NotNil(t, param.InsertOpts)
		assert.True(t, param.InsertOpts.UniqueOpts.ByArgs)
	}

	assert.ElementsMatch(t, []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack}, channels)
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
	assert.Equal(t, notification.DeliveryChannelEmail, args.Channel)
}

func TestDueSoonCheckerWorker_EnqueuesOneJobPerChannel(t *testing.T) {
	db := newWorkflowNotificationJobsTestDB(t)
	client := &stubRiverClient{}
	worker := NewDueSoonCheckerWorker(db, client, zap.NewNop().Sugar())

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
		AssignedToID:             "user-1",
		DueDate:                  &dueDate,
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDefinition.ID,
	}
	require.NoError(t, db.Create(&stepExecution).Error)

	err := worker.Work(context.Background(), &river.Job[DueSoonCheckerArgs]{Args: DueSoonCheckerArgs{}})
	require.NoError(t, err)
	require.Len(t, client.params, 2)

	var channels []string
	for _, param := range client.params {
		args, ok := param.Args.(WorkflowTaskDueSoonArgs)
		require.True(t, ok)
		assert.Equal(t, stepExecution.ID.String(), args.StepExecutionID)
		channels = append(channels, args.Channel)
		require.NotNil(t, param.InsertOpts)
		assert.True(t, param.InsertOpts.UniqueOpts.ByArgs)
	}

	assert.ElementsMatch(t, []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack}, channels)
}

func TestWorkflowTaskDigestCheckerWorker_EnqueuesOneJobPerSubscribedChannel(t *testing.T) {
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
	require.Len(t, client.params, 3)

	got := make(map[string][]string)
	for _, param := range client.params {
		args, ok := param.Args.(WorkflowTaskDigestArgs)
		require.True(t, ok)
		got[args.UserID] = append(got[args.UserID], args.Channel)
	}

	assert.ElementsMatch(t, []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack}, got[userOneID.String()])
	assert.ElementsMatch(t, []string{notification.DeliveryChannelEmail}, got[userTwoID.String()])
	_, exists := got[missingUserID.String()]
	assert.False(t, exists)
}

func newWorkflowNotificationJobsTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&relational.User{},
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

func createWorkflowNotificationUser(t *testing.T, db *gorm.DB, id uuid.UUID, email string) {
	t.Helper()

	require.NoError(t, db.Model(&relational.User{}).Create(map[string]interface{}{
		"id":          id,
		"email":       email,
		"first_name":  "Test",
		"last_name":   "User",
		"auth_method": "password",
	}).Error)
}
