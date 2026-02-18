package workflow

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupEvidenceTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(
		&workflows.WorkflowDefinition{},
		&workflows.WorkflowStepDefinition{},
		&workflows.StepDependency{},
		&workflows.StepTrigger{},
		&workflows.WorkflowInstance{},
		&workflows.RoleAssignment{},
		&workflows.WorkflowExecution{},
		&workflows.StepExecution{},
		&workflows.StepEvidence{},
		&workflows.StepReassignmentHistory{},
		&workflows.ControlRelationship{},
		&relational.Evidence{},
		&relational.Labels{},
	)
	require.NoError(t, err)

	return db
}

func createTestWorkflowContext(t *testing.T, db *gorm.DB) (*workflows.WorkflowDefinition, *workflows.WorkflowInstance, *workflows.WorkflowExecution, uuid.UUID) {
	// Create workflow definition
	definition := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(definition).Error)

	// Create workflow instance
	sspID := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: definition.ID,
		Name:                 "Test Instance",
		SystemSecurityPlanID: &sspID,
	}
	require.NoError(t, db.Create(instance).Error)

	// Create workflow execution
	now := time.Now()
	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "pending",
		TriggeredBy:        "manual",
		StartedAt:          &now,
	}
	require.NoError(t, db.Create(execution).Error)

	return definition, instance, execution, sspID
}

// TestWorkflowExecutionEvidenceCreatedOnStart tests that workflow execution evidence is created when workflow starts
func TestWorkflowExecutionEvidenceCreatedOnStart(t *testing.T) {
	db := setupEvidenceTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
	}()

	// Create test workflow context
	definition, instance, execution, _ := createTestWorkflowContext(t, db)

	// Create evidence integration
	logger := zap.NewNop().Sugar()
	integration := NewEvidenceIntegration(db, logger)

	// Test that evidence stream is created when workflow execution starts
	ctx := context.Background()
	stream, err := integration.GetOrCreateExecutionStream(ctx, execution.ID)
	require.NoError(t, err)
	assert.NotNil(t, stream)
	assert.NotNil(t, stream.ID)

	// Verify the evidence stream has the correct properties
	assert.Equal(t, fmt.Sprintf("Workflow Execution: %s", definition.Name), stream.Title)
	assert.Contains(t, stream.Description, "Evidence stream for execution")
	assert.Contains(t, stream.Description, definition.Name)
	assert.Contains(t, stream.Description, definition.Version)

	// Verify labels were created
	var labels []relational.Labels
	err = db.Model(stream).Association("Labels").Find(&labels)
	require.NoError(t, err)
	assert.Greater(t, len(labels), 0)

	// Check for key labels
	labelMap := make(map[string]string)
	for _, label := range labels {
		labelMap[label.Name] = label.Value
	}
	assert.Equal(t, "workflow_execution", labelMap["stream.type"])
	assert.Equal(t, definition.ID.String(), labelMap["workflow.definition.id"])
	assert.Equal(t, definition.Name, labelMap["workflow.definition.name"])
	assert.Equal(t, instance.ID.String(), labelMap["workflow.instance.id"])
	assert.Equal(t, execution.ID.String(), labelMap["workflow.execution.id"])

	// Test that subsequent calls return the same stream (idempotent)
	stream2, err := integration.GetOrCreateExecutionStream(ctx, execution.ID)
	require.NoError(t, err)
	assert.Equal(t, stream.UUID, stream2.UUID)
	assert.Equal(t, stream.ID, stream2.ID)
}

func TestNewEvidenceIntegration(t *testing.T) {
	db := setupEvidenceTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		err := sqlDB.Close()
		require.NoError(t, err)
	}()

	logger := zap.NewNop().Sugar()
	integration := NewEvidenceIntegration(db, logger)

	assert.NotNil(t, integration)
	assert.NotNil(t, integration.db)
	assert.NotNil(t, integration.logger)
	assert.NotNil(t, integration.workflowExecutionSvc)
	assert.NotNil(t, integration.stepExecutionSvc)
	assert.NotNil(t, integration.workflowInstanceSvc)
	assert.NotNil(t, integration.workflowDefinitionSvc)
	assert.NotNil(t, integration.stepDefinitionSvc)
}

func TestGetOrCreateExecutionStream(t *testing.T) {
	db := setupEvidenceTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
	}()

	logger := zap.NewNop().Sugar()
	integration := NewEvidenceIntegration(db, logger)
	ctx := context.Background()

	definition, instance, execution, sspID := createTestWorkflowContext(t, db)

	t.Run("CreateNewStream", func(t *testing.T) {
		stream, err := integration.GetOrCreateExecutionStream(ctx, execution.ID)
		require.NoError(t, err)
		assert.NotNil(t, stream)
		assert.NotNil(t, stream.ID)
		assert.NotEqual(t, uuid.Nil, stream.UUID)
		assert.Contains(t, stream.Title, "Workflow Execution")
		assert.Contains(t, stream.Description, definition.Name)
		assert.Contains(t, stream.Description, sspID.String())

		// Verify labels were created
		var labels []relational.Labels
		err = db.Model(stream).Association("Labels").Find(&labels)
		require.NoError(t, err)
		assert.Greater(t, len(labels), 0)

		// Check for expected labels
		labelMap := make(map[string]string)
		for _, label := range labels {
			labelMap[label.Name] = label.Value
		}
		assert.Equal(t, "workflow_execution", labelMap["stream.type"])
		assert.Equal(t, definition.ID.String(), labelMap["workflow.definition.id"])
		assert.Equal(t, definition.Name, labelMap["workflow.definition.name"])
		assert.Equal(t, instance.ID.String(), labelMap["workflow.instance.id"])
		assert.Equal(t, execution.ID.String(), labelMap["workflow.execution.id"])
	})

	t.Run("ReuseExistingStream", func(t *testing.T) {
		// Get stream first time
		stream1, err := integration.GetOrCreateExecutionStream(ctx, execution.ID)
		require.NoError(t, err)

		// Get stream second time - should return same stream
		stream2, err := integration.GetOrCreateExecutionStream(ctx, execution.ID)
		require.NoError(t, err)

		assert.Equal(t, stream1.UUID, stream2.UUID)
		assert.Equal(t, stream1.ID.String(), stream2.ID.String())
	})

	t.Run("DeterministicUUID", func(t *testing.T) {
		// Create another execution for the same instance
		startTime := time.Now()
		execution2 := &workflows.WorkflowExecution{
			WorkflowInstanceID: instance.ID,
			Status:             "running",
			TriggeredBy:        "manual",
			StartedAt:          &startTime,
		}
		require.NoError(t, db.Create(execution2).Error)

		stream1, err := integration.GetOrCreateExecutionStream(ctx, execution.ID)
		require.NoError(t, err)

		stream2, err := integration.GetOrCreateExecutionStream(ctx, execution2.ID)
		require.NoError(t, err)

		// Different executions should have different stream UUIDs
		assert.NotEqual(t, stream1.UUID, stream2.UUID)
	})
}

func TestGetOrCreateInstanceStream(t *testing.T) {
	db := setupEvidenceTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
	}()

	logger := zap.NewNop().Sugar()
	integration := NewEvidenceIntegration(db, logger)
	ctx := context.Background()

	definition, instance, _, _ := createTestWorkflowContext(t, db)

	t.Run("CreateNewStream", func(t *testing.T) {
		stream, err := integration.GetOrCreateInstanceStream(ctx, instance.ID)
		require.NoError(t, err)
		assert.NotNil(t, stream)
		assert.NotNil(t, stream.ID)
		assert.NotEqual(t, uuid.Nil, stream.UUID)
		assert.Contains(t, stream.Title, "Workflow Instance")
		assert.Contains(t, stream.Description, instance.Name)
		assert.Contains(t, stream.Description, definition.Name)

	})

	t.Run("ReuseExistingStream", func(t *testing.T) {
		// Get stream first time
		stream1, err := integration.GetOrCreateInstanceStream(ctx, instance.ID)
		require.NoError(t, err)

		// Get stream second time - should return same stream
		stream2, err := integration.GetOrCreateInstanceStream(ctx, instance.ID)
		require.NoError(t, err)

		assert.Equal(t, stream1.UUID, stream2.UUID)
		// They should not contain the same ID - they're different evidence entries
		assert.NotEqual(t, stream1.ID.String(), stream2.ID.String())
	})

	t.Run("DeterministicUUID", func(t *testing.T) {
		// Create another instance for the same definition
		sspID2 := uuid.New()
		instance2 := &workflows.WorkflowInstance{
			WorkflowDefinitionID: definition.ID,
			Name:                 "Test Instance 2",
			SystemSecurityPlanID: &sspID2,
		}
		require.NoError(t, db.Create(instance2).Error)

		stream1, err := integration.GetOrCreateInstanceStream(ctx, instance.ID)
		require.NoError(t, err)

		stream2, err := integration.GetOrCreateInstanceStream(ctx, instance2.ID)
		require.NoError(t, err)

		// Different instances should have different stream UUIDs
		assert.NotEqual(t, stream1.UUID, stream2.UUID)
	})
}

func TestAddStepCompletionEvidence(t *testing.T) {
	db := setupEvidenceTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		err := sqlDB.Close()
		require.NoError(t, err)
	}()

	logger := zap.NewNop().Sugar()
	integration := NewEvidenceIntegration(db, logger)
	ctx := context.Background()

	definition, _, execution, _ := createTestWorkflowContext(t, db)

	// Create step definition
	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: definition.ID,
		Name:                 "Test Step",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef).Error)

	// Create step execution
	startTime := time.Now()
	completedTime := time.Now().Add(5 * time.Minute)
	stepExecution := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "completed",
		StartedAt:                &startTime,
		CompletedAt:              &completedTime,
	}
	require.NoError(t, db.Create(stepExecution).Error)

	t.Run("AddStepEvidence", func(t *testing.T) {
		err := integration.AddStepCompletionEvidence(ctx, stepExecution.ID)
		require.NoError(t, err)

		// Verify execution stream was created
		stream, err := integration.GetOrCreateExecutionStream(ctx, execution.ID)
		require.NoError(t, err)

		// Verify evidence record was created with same stream UUID
		var evidenceRecords []relational.Evidence
		err = db.Where("uuid = ?", stream.UUID).Find(&evidenceRecords).Error
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(evidenceRecords), 2) // Stream + step evidence

		// Find the step evidence record
		var stepEvidence *relational.Evidence
		for _, record := range evidenceRecords {
			if record.Title == "Step Completion: Test Step" {
				stepEvidence = &record
				break
			}
		}
		require.NotNil(t, stepEvidence, "Step evidence not found")
		assert.Contains(t, stepEvidence.Description, "Test Step")
		assert.Contains(t, stepEvidence.Description, "completed")
		assert.Equal(t, startTime.Unix(), stepEvidence.Start.Unix())
		assert.Equal(t, completedTime.Unix(), stepEvidence.End.Unix())

		// Verify labels
		var labels []relational.Labels
		err = db.Model(stepEvidence).Association("Labels").Find(&labels)
		require.NoError(t, err)
		assert.Greater(t, len(labels), 0)

		labelMap := make(map[string]string)
		for _, label := range labels {
			labelMap[label.Name] = label.Value
		}
		assert.Equal(t, "step_completion", labelMap["evidence.type"])
		assert.Equal(t, stepExecution.ID.String(), labelMap["step.execution.id"])
		assert.Equal(t, stepDef.ID.String(), labelMap["step.definition.id"])
		assert.Equal(t, "Test Step", labelMap["step.name"])
	})

	t.Run("MultipleStepsInSameStream", func(t *testing.T) {
		// Create another step execution
		stepDef2 := &workflows.WorkflowStepDefinition{
			WorkflowDefinitionID: definition.ID,
			Name:                 "Test Step 2",
			ResponsibleRole:      "engineer",
		}
		require.NoError(t, db.Create(stepDef2).Error)

		startTime2 := time.Now()
		completedTime2 := time.Now().Add(3 * time.Minute)
		stepExecution2 := &workflows.StepExecution{
			WorkflowExecutionID:      execution.ID,
			WorkflowStepDefinitionID: stepDef2.ID,
			Status:                   "completed",
			StartedAt:                &startTime2,
			CompletedAt:              &completedTime2,
		}
		require.NoError(t, db.Create(stepExecution2).Error)

		err := integration.AddStepCompletionEvidence(ctx, stepExecution2.ID)
		require.NoError(t, err)

		// Verify both evidence records share the same stream UUID
		stream, err := integration.GetOrCreateExecutionStream(ctx, execution.ID)
		require.NoError(t, err)

		var evidenceRecords []relational.Evidence
		err = db.Where("uuid = ?", stream.UUID).Find(&evidenceRecords).Error
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(evidenceRecords), 3) // Stream + 2 step evidences
	})
}

func TestAddExecutionCompletionEvidence(t *testing.T) {
	db := setupEvidenceTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		err := sqlDB.Close()
		require.NoError(t, err)
	}()

	logger := zap.NewNop().Sugar()
	integration := NewEvidenceIntegration(db, logger)
	ctx := context.Background()

	definition, instance, execution, _ := createTestWorkflowContext(t, db)

	// Mark execution as completed
	completedTime := time.Now()
	execution.Status = "completed"
	execution.CompletedAt = &completedTime
	require.NoError(t, db.Save(execution).Error)

	// Create some step executions for metrics
	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: definition.ID,
		Name:                 "Test Step",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef).Error)

	startTime := time.Now()
	stepExecution := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "completed",
		StartedAt:                &startTime,
		CompletedAt:              &completedTime,
	}
	require.NoError(t, db.Create(stepExecution).Error)

	t.Run("AddExecutionEvidence", func(t *testing.T) {
		err := integration.AddExecutionCompletionEvidence(ctx, execution.ID)
		require.NoError(t, err)

		// Verify instance stream was created
		stream, err := integration.GetOrCreateInstanceStream(ctx, instance.ID)
		require.NoError(t, err)

		// Verify evidence record was created with same stream UUID
		var evidenceRecords []relational.Evidence
		err = db.Where("uuid = ?", stream.UUID).Find(&evidenceRecords).Error
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(evidenceRecords), 1) // Only execution evidence (no instance stream)

		// Find the execution evidence record
		var execEvidence *relational.Evidence
		for _, record := range evidenceRecords {
			if record.Title == "Workflow Execution Completed" {
				execEvidence = &record
				break
			}
		}
		require.NotNil(t, execEvidence, "Execution evidence not found")
		assert.Contains(t, execEvidence.Description, "Workflow Execution Completed")
		assert.Contains(t, execEvidence.Description, execution.ID.String())
		assert.Contains(t, execEvidence.Description, "Total Steps: 1")

		// Verify labels
		var labels []relational.Labels
		err = db.Model(execEvidence).Association("Labels").Find(&labels)
		require.NoError(t, err)
		assert.Greater(t, len(labels), 0)

		labelMap := make(map[string]string)
		for _, label := range labels {
			labelMap[label.Name] = label.Value
		}
		assert.Equal(t, "execution_completion", labelMap["evidence.type"])
		assert.Equal(t, execution.ID.String(), labelMap["workflow.execution.id"])
		assert.Equal(t, "completed", labelMap["workflow.execution.status"])
		// Completion evidence should not have failure reason
		_, exists := labelMap["workflow.failure_reason"]
		assert.False(t, exists, "completion evidence should not have failure reason")
	})

	t.Run("RejectNonCompletedExecution", func(t *testing.T) {
		// Create a running execution
		startTime := time.Now()
		runningExecution := &workflows.WorkflowExecution{
			WorkflowInstanceID: instance.ID,
			Status:             "running",
			TriggeredBy:        "manual",
			StartedAt:          &startTime,
		}
		require.NoError(t, db.Create(runningExecution).Error)

		err := integration.AddExecutionCompletionEvidence(ctx, runningExecution.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not completed")
	})

	t.Run("MultipleExecutionsInSameStream", func(t *testing.T) {
		// Create another execution for the same instance
		startTime2 := time.Now()
		completedTime2 := time.Now().Add(10 * time.Minute)
		execution2 := &workflows.WorkflowExecution{
			WorkflowInstanceID: instance.ID,
			Status:             "completed",
			TriggeredBy:        "manual",
			StartedAt:          &startTime2,
			CompletedAt:        &completedTime2,
		}
		require.NoError(t, db.Create(execution2).Error)

		err := integration.AddExecutionCompletionEvidence(ctx, execution2.ID)
		require.NoError(t, err)

		// Verify both evidence records share the same stream UUID
		stream, err := integration.GetOrCreateInstanceStream(ctx, instance.ID)
		require.NoError(t, err)

		var evidenceRecords []relational.Evidence
		err = db.Where("uuid = ?", stream.UUID).Find(&evidenceRecords).Error
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(evidenceRecords), 2) // Only 2 execution evidences (no instance stream)
	})
}

func TestGenerateStreamUUIDs(t *testing.T) {
	db := setupEvidenceTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
	}()

	logger := zap.NewNop().Sugar()
	integration := NewEvidenceIntegration(db, logger)

	definition, instance, execution, _ := createTestWorkflowContext(t, db)

	t.Run("ExecutionStreamUUIDIsDeterministic", func(t *testing.T) {
		uuid1 := integration.generateExecutionStreamUUID(definition, instance, execution)
		uuid2 := integration.generateExecutionStreamUUID(definition, instance, execution)

		assert.Equal(t, uuid1, uuid2, "Same inputs should produce same UUID")
		assert.NotEqual(t, uuid.Nil, uuid1, "UUID should not be nil")
	})

	t.Run("InstanceStreamUUIDIsDeterministic", func(t *testing.T) {
		uuid1 := integration.generateInstanceStreamUUID(definition, instance)
		uuid2 := integration.generateInstanceStreamUUID(definition, instance)

		assert.Equal(t, uuid1, uuid2, "Same inputs should produce same UUID")
		assert.NotEqual(t, uuid.Nil, uuid1, "UUID should not be nil")
	})

	t.Run("DifferentContextsProduceDifferentUUIDs", func(t *testing.T) {
		// Create another execution
		startTime := time.Now()
		execution2 := &workflows.WorkflowExecution{
			WorkflowInstanceID: instance.ID,
			Status:             "running",
			TriggeredBy:        "manual",
			StartedAt:          &startTime,
		}
		require.NoError(t, db.Create(execution2).Error)

		uuid1 := integration.generateExecutionStreamUUID(definition, instance, execution)
		uuid2 := integration.generateExecutionStreamUUID(definition, instance, execution2)

		assert.NotEqual(t, uuid1, uuid2, "Different executions should produce different UUIDs")
	})
}

func TestBuildStreamLabels(t *testing.T) {
	db := setupEvidenceTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		err := sqlDB.Close()
		require.NoError(t, err)
	}()

	logger := zap.NewNop().Sugar()
	integration := NewEvidenceIntegration(db, logger)

	definition, instance, execution, sspID := createTestWorkflowContext(t, db)

	t.Run("ExecutionStreamLabels", func(t *testing.T) {
		labels := integration.buildExecutionStreamLabels(definition, instance, execution)

		assert.Greater(t, len(labels), 0)

		labelMap := make(map[string]string)
		for _, label := range labels {
			labelMap[label.Name] = label.Value
		}

		assert.Equal(t, "workflow_execution", labelMap["stream.type"])
		assert.Equal(t, definition.ID.String(), labelMap["workflow.definition.id"])
		assert.Equal(t, definition.Name, labelMap["workflow.definition.name"])
		assert.Equal(t, definition.Version, labelMap["workflow.definition.version"])
		assert.Equal(t, instance.ID.String(), labelMap["workflow.instance.id"])
		assert.Equal(t, instance.Name, labelMap["workflow.instance.name"])
		assert.Equal(t, sspID.String(), labelMap["workflow.instance.system_security_plan_id"])
		assert.Equal(t, execution.ID.String(), labelMap["workflow.execution.id"])
		assert.Equal(t, execution.TriggeredBy, labelMap["workflow.triggered_by"])
	})

	t.Run("InstanceStreamLabels", func(t *testing.T) {
		labels := integration.buildInstanceStreamLabels(definition, instance)

		assert.Greater(t, len(labels), 0)

		labelMap := make(map[string]string)
		for _, label := range labels {
			labelMap[label.Name] = label.Value
		}

		assert.Equal(t, "workflow_instance", labelMap["stream.type"])
		assert.Equal(t, definition.ID.String(), labelMap["workflow.definition.id"])
		assert.Equal(t, definition.Name, labelMap["workflow.definition.name"])
		assert.Equal(t, definition.Version, labelMap["workflow.definition.version"])
		assert.Equal(t, instance.ID.String(), labelMap["workflow.instance.id"])
		assert.Equal(t, instance.Name, labelMap["workflow.instance.name"])
		assert.Equal(t, sspID.String(), labelMap["workflow.instance.system_security_plan_id"])
	})
}

func TestAddWorkflowExecutionStartedEvidence(t *testing.T) {
	db := setupEvidenceTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
	}()

	logger := zap.NewNop().Sugar()
	evidenceIntegration := NewEvidenceIntegration(db, logger)

	t.Run("AddWorkflowExecutionStartedEvidence", func(t *testing.T) {
		// Create workflow context
		definition, instance, execution, _ := createTestWorkflowContext(t, db)

		// Verify the execution starts in pending status
		assert.Equal(t, "pending", execution.Status)

		// Test that the evidence method works directly with the pending execution
		err := evidenceIntegration.AddWorkflowExecutionEvidence(context.Background(), execution.ID, "started")
		require.NoError(t, err)

		// Find the workflow execution started evidence
		var evidence relational.Evidence
		err = db.Where("title LIKE ?", "Workflow Execution Started: %").First(&evidence).Error
		require.NoError(t, err)

		// Verify evidence properties
		assert.Equal(t, fmt.Sprintf("Workflow Execution Started: %s", definition.Name), evidence.Title)
		assert.Contains(t, evidence.Description, execution.ID.String())
		assert.Contains(t, evidence.Description, "started at")

		// Verify labels
		var labels []relational.Labels
		err = db.Model(&evidence).Association("Labels").Find(&labels)
		require.NoError(t, err)
		require.Greater(t, len(labels), 0)

		labelMap := make(map[string]string)
		for _, label := range labels {
			labelMap[label.Name] = label.Value
		}

		assert.Equal(t, execution.ID.String(), labelMap["workflow.execution.id"])
		assert.Equal(t, definition.ID.String(), labelMap["workflow.definition.id"])
		assert.Equal(t, definition.Name, labelMap["workflow.definition.name"])
		assert.Equal(t, instance.ID.String(), labelMap["workflow.instance.id"])
		assert.Equal(t, "workflow_execution_started", labelMap["evidence.type"])
	})

	t.Run("RejectInvalidExecutionStatusForStarted", func(t *testing.T) {
		// Create workflow context
		_, _, execution, _ := createTestWorkflowContext(t, db)

		// Update execution to failed status
		err := db.Model(execution).Update("status", "failed").Error
		require.NoError(t, err)

		// Try to add started evidence for a failed execution (should fail)
		err = evidenceIntegration.AddWorkflowExecutionEvidence(context.Background(), execution.ID, "started")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not in pending status")
	})
}

func TestAddStepStartedEvidence(t *testing.T) {
	db := setupEvidenceTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
	}()

	logger := zap.NewNop().Sugar()
	evidenceIntegration := NewEvidenceIntegration(db, logger)

	// Set the evidence integration as its own evidence creator to enable step started evidence
	evidenceIntegration.stepExecutionSvc.SetEvidenceCreator(evidenceIntegration)

	t.Run("AddStepStartedEvidence", func(t *testing.T) {
		// Create workflow context
		definition, _, execution, _ := createTestWorkflowContext(t, db)

		stepDef := &workflows.WorkflowStepDefinition{
			WorkflowDefinitionID: definition.ID,
			Name:                 "Test Step",
			Description:          "A test step",
		}
		require.NoError(t, db.Create(stepDef).Error)

		stepExecution := &workflows.StepExecution{
			WorkflowExecutionID:      execution.ID,
			WorkflowStepDefinitionID: stepDef.ID,
			Status:                   "pending",
			StartedAt:                &time.Time{},
		}
		require.NoError(t, db.Create(stepExecution).Error)

		// Now use the UpdateStatus method to trigger evidence creation
		err := evidenceIntegration.stepExecutionSvc.UpdateStatus(context.Background(), stepExecution.ID, "in_progress")
		require.NoError(t, err)

		// Find the step started evidence
		var evidence relational.Evidence
		err = db.Where("title LIKE ?", "Step Started: %").First(&evidence).Error
		require.NoError(t, err)

		// Verify labels
		var labels []relational.Labels
		err = db.Model(&evidence).Association("Labels").Find(&labels)
		require.NoError(t, err)
		require.Greater(t, len(labels), 0)

		labelMap := make(map[string]string)
		for _, label := range labels {
			labelMap[label.Name] = label.Value
		}
		assert.Equal(t, "step_started", labelMap["evidence.type"])
		assert.Equal(t, stepExecution.ID.String(), labelMap["step.execution.id"])
		assert.Equal(t, stepDef.ID.String(), labelMap["step.definition.id"])
		assert.Equal(t, stepDef.Name, labelMap["step.name"])
		assert.Equal(t, "in_progress", labelMap["step.status"])
	})

	t.Run("RejectNonInProgressStep", func(t *testing.T) {
		// Create workflow context
		definition, _, execution, _ := createTestWorkflowContext(t, db)

		stepDef := &workflows.WorkflowStepDefinition{
			WorkflowDefinitionID: definition.ID,
			Name:                 "Test Step",
			Description:          "A test step",
		}
		require.NoError(t, db.Create(stepDef).Error)

		// Create step with canceled status (should not allow step started evidence)
		stepExecution := &workflows.StepExecution{
			WorkflowExecutionID:      execution.ID,
			WorkflowStepDefinitionID: stepDef.ID,
			Status:                   "canceled",
		}
		require.NoError(t, db.Create(stepExecution).Error)

		// Try to add step started evidence - should fail
		err := evidenceIntegration.AddStepStartedEvidence(context.Background(), stepExecution.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not in pending status")
	})
}
