//go:build integration

package workflows

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func setupStepExecutionTestHandler(t *testing.T) (*StepExecutionHandler, *gorm.DB) {
	db := setupTestDB(t)
	logger := zap.NewNop().Sugar()

	// Create evidence integration first
	evidenceIntegration := workflow.NewEvidenceIntegration(db, logger)

	// Create services needed for step transition
	stepExecService := workflows.NewStepExecutionService(db, evidenceIntegration)
	stepDefService := workflows.NewWorkflowStepDefinitionService(db)
	workflowExecService := workflows.NewWorkflowExecutionService(db)
	workflowInstanceService := workflows.NewWorkflowInstanceService(db)
	workflowDefinitionService := workflows.NewWorkflowDefinitionService(db)
	roleAssignmentService := workflows.NewRoleAssignmentService(db)

	// Create assignment service
	assignmentService := workflow.NewAssignmentService(roleAssignmentService, stepExecService, db, zap.NewNop().Sugar(), nil)
	privateKey, _, err := config.GenerateKeyPair(2048)
	require.NoError(t, err)
	evidenceService := evidencesvc.NewEvidenceService(db, logger, &config.Config{JWTPrivateKey: privateKey}, nil)

	// Create executor for step transition coordination
	stdLogger := log.Default()
	executor := workflow.NewDAGExecutor(
		stepExecService,
		workflowExecService,
		stepDefService,
		assignmentService,
		stdLogger,
		nil,
	)

	// Create step transition service
	transitionService := workflow.NewStepTransitionService(
		stepExecService,
		stepDefService,
		workflowExecService,
		roleAssignmentService,
		workflowInstanceService,
		workflowDefinitionService,
		executor,
		db,
		evidenceService,
		evidenceIntegration,
	)

	handler := NewStepExecutionHandler(logger, db, transitionService, assignmentService)
	return handler, db
}

func TestStepExecutionHandler_List(t *testing.T) {
	handler, db := setupStepExecutionTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	sysId := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemSecurityPlanID: &sysId,
	}
	require.NoError(t, db.Create(instance).Error)

	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef).Error)

	stepExec := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "in_progress",
	}
	require.NoError(t, db.Create(stepExec).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions?workflow_execution_id="+execution.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response StepExecutionListResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Data, 1)
	})

	t.Run("MissingWorkflowExecutionID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestStepExecutionHandler_Get(t *testing.T) {
	handler, db := setupStepExecutionTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)
	sysId := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemSecurityPlanID: &sysId,
	}
	require.NoError(t, db.Create(instance).Error)

	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef).Error)

	stepExec := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "in_progress",
	}
	require.NoError(t, db.Create(stepExec).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/"+stepExec.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepExec.ID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response StepExecutionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, stepExec.ID.String(), response.Data.ID.String())
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/"+nonExistentID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestStepExecutionHandler_TransitionStep(t *testing.T) {
	handler, db := setupStepExecutionTestHandler(t)
	e := echo.New()
	e.Validator = middleware.NewValidator()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	sysId := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemSecurityPlanID: &sysId,
	}
	require.NoError(t, db.Create(instance).Error)

	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
		EvidenceRequired:     []workflows.EvidenceRequirement{},
	}
	require.NoError(t, db.Create(stepDef).Error)

	testUser := &relational.User{
		Email:     "test-user@example.com",
		FirstName: "Test",
		LastName:  "User",
	}
	require.NoError(t, db.Create(testUser).Error)

	// Create role assignment for the user
	roleAssignment := &workflows.RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "engineer",
		AssignedToType:     "user",
		AssignedToID:       testUser.ID.String(),
		IsActive:           true,
	}
	require.NoError(t, db.Create(roleAssignment).Error)

	stepExec := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "pending",
	}
	require.NoError(t, db.Create(stepExec).Error)

	t.Run("Success", func(t *testing.T) {
		claims := &authn.UserClaims{GivenName: "Test", FamilyName: "User"}
		claims.Subject = "test-user@example.com"

		// First transition from pending to in_progress
		reqBody := TransitionStepRequest{
			Status:   "in_progress",
			UserID:   "spoofed-user",
			UserType: "group",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/step-executions/"+stepExec.ID.String()+"/transition", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepExec.ID.String())
		c.Set("user", claims)

		err = handler.TransitionStep(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Then transition from in_progress to completed
		reqBody = TransitionStepRequest{
			Status:   "completed",
			UserID:   "spoofed-user",
			UserType: "group",
			Evidence: []workflow.EvidenceSubmission{
				{
					EvidenceType: "document",
					Name:         "attestation.pdf",
					Description:  "Signed attestation",
					FilePath:     "/tmp/attestation.pdf",
					FileHash:     "abc123",
					FileContent:  "ZmFrZS1wZGY=",
					MediaType:    "application/pdf",
					Metadata:     "{\"kind\":\"attestation\"}",
				},
			},
		}

		body, err = json.Marshal(reqBody)
		require.NoError(t, err)

		req = httptest.NewRequest(http.MethodPut, "/workflows/step-executions/"+stepExec.ID.String()+"/transition", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepExec.ID.String())
		c.Set("user", claims)

		err = handler.TransitionStep(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response StepExecutionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		require.NotNil(t, response)
		require.NotNil(t, response.Data)
		assert.Equal(t, "completed", response.Data.Status)

		var evidences []relational.Evidence
		require.NoError(t, db.Preload("Labels").Preload("BackMatter").Preload("BackMatter.Resources").Find(&evidences).Error)

		var completedEvidence *relational.Evidence
		for i := range evidences {
			if strings.Contains(evidences[i].Title, "completed successfully") {
				completedEvidence = &evidences[i]
				break
			}
		}
		require.NotNil(t, completedEvidence)
		require.NotNil(t, completedEvidence.Signature)
		require.NotNil(t, completedEvidence.BackMatter)
		require.Len(t, completedEvidence.BackMatter.Resources, 1)

		foundSubmittedBy := false
		for _, label := range completedEvidence.Labels {
			if label.Name == "evidence.submitted_by" && label.Value == claims.Subject {
				foundSubmittedBy = true
				break
			}
		}
		require.True(t, foundSubmittedBy)
	})

	t.Run("OverdueToInProgressReturnsBadRequest", func(t *testing.T) {
		claims := &authn.UserClaims{GivenName: "Test", FamilyName: "User"}
		claims.Subject = "test-user@example.com"

		overdueStepDef := &workflows.WorkflowStepDefinition{
			WorkflowDefinitionID: workflowDef.ID,
			Name:                 "Overdue Step",
			ResponsibleRole:      "engineer",
			EvidenceRequired:     []workflows.EvidenceRequirement{},
		}
		require.NoError(t, db.Create(overdueStepDef).Error)

		overdueStep := &workflows.StepExecution{
			WorkflowExecutionID:      execution.ID,
			WorkflowStepDefinitionID: overdueStepDef.ID,
			Status:                   workflows.StepStatusOverdue.String(),
		}
		require.NoError(t, db.Create(overdueStep).Error)

		reqBody := TransitionStepRequest{
			Status:   "in_progress",
			UserID:   "spoofed-user",
			UserType: "group",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/step-executions/"+overdueStep.ID.String()+"/transition", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(overdueStep.ID.String())
		c.Set("user", claims)

		err = handler.TransitionStep(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestStepExecutionHandler_GetEvidenceRequirements(t *testing.T) {
	handler, db := setupStepExecutionTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)
	sysId := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemSecurityPlanID: &sysId,
	}
	require.NoError(t, db.Create(instance).Error)

	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
		EvidenceRequired: []workflows.EvidenceRequirement{
			{
				Type:     "Documentation",
				Required: true,
			},
		},
	}
	require.NoError(t, db.Create(stepDef).Error)

	stepExec := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "pending",
	}
	require.NoError(t, db.Create(stepExec).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/"+stepExec.ID.String()+"/evidence-requirements", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepExec.ID.String())

		err := handler.GetEvidenceRequirements(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response map[string]interface{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response["data"])
	})
}

func TestStepExecutionHandler_Fail(t *testing.T) {
	handler, db := setupStepExecutionTestHandler(t)
	e := echo.New()
	e.Validator = middleware.NewValidator()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	sysId := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemSecurityPlanID: &sysId,
	}
	require.NoError(t, db.Create(instance).Error)

	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef).Error)

	stepExec := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "in_progress",
	}
	require.NoError(t, db.Create(stepExec).Error)

	t.Run("Success", func(t *testing.T) {
		reqBody := FailStepRequest{
			Reason: "Test failed due to validation error",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/step-executions/"+stepExec.ID.String()+"/fail", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepExec.ID.String())

		err = handler.Fail(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response StepExecutionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "failed", response.Data.Status)
	})
}

func TestStepExecutionHandler_ListMy(t *testing.T) {
	handler, db := setupStepExecutionTestHandler(t)
	e := echo.New()

	// Create test users
	testUser1 := &relational.User{
		Email:     "testuser1@example.com",
		FirstName: "Test",
		LastName:  "User1",
	}
	require.NoError(t, db.Create(testUser1).Error)

	testUser2 := &relational.User{
		Email:     "testuser2@example.com",
		FirstName: "Test",
		LastName:  "User2",
	}
	require.NoError(t, db.Create(testUser2).Error)

	// Create workflow definition
	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	// Create another workflow definition for filtering tests
	workflowDef2 := &workflows.WorkflowDefinition{
		Name:    "Test Workflow 2",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef2).Error)

	sysId := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemSecurityPlanID: &sysId,
	}
	require.NoError(t, db.Create(instance).Error)

	instance2 := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef2.ID,
		Name:                 "Test Instance 2",
		SystemSecurityPlanID: &sysId,
	}
	require.NoError(t, db.Create(instance2).Error)

	// Create executions with different due dates
	now := time.Now()
	dueDatePast := now.Add(-24 * time.Hour)
	dueDateFuture := now.Add(24 * time.Hour)

	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
		DueDate:            &dueDateFuture,
	}
	require.NoError(t, db.Create(execution).Error)

	execution2 := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance2.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
		DueDate:            &dueDatePast,
	}
	require.NoError(t, db.Create(execution2).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef).Error)

	stepDef2 := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef2.ID,
		Name:                 "Step 2",
		ResponsibleRole:      "reviewer",
	}
	require.NoError(t, db.Create(stepDef2).Error)
	stepDef3 := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 3",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef3).Error)
	stepDef4 := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 4",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef4).Error)

	// Create step executions assigned to test user 1 (by user ID)
	assignedAt := time.Now()
	stepExec1 := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "pending",
		AssignedToType:           "user",
		AssignedToID:             testUser1.ID.String(),
		AssignedAt:               &assignedAt,
	}
	require.NoError(t, db.Create(stepExec1).Error)

	stepExec2 := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef3.ID,
		Status:                   "in_progress",
		AssignedToType:           "user",
		AssignedToID:             testUser1.ID.String(),
		AssignedAt:               &assignedAt,
	}
	require.NoError(t, db.Create(stepExec2).Error)

	// Create step execution assigned to test user 1 by email
	stepExec3 := &workflows.StepExecution{
		WorkflowExecutionID:      execution2.ID,
		WorkflowStepDefinitionID: stepDef2.ID,
		Status:                   "blocked",
		AssignedToType:           "email",
		AssignedToID:             testUser1.Email,
		AssignedAt:               &assignedAt,
	}
	require.NoError(t, db.Create(stepExec3).Error)

	// Create step execution assigned to different user
	stepExec4 := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef4.ID,
		Status:                   "pending",
		AssignedToType:           "user",
		AssignedToID:             testUser2.ID.String(),
		AssignedAt:               &assignedAt,
	}
	require.NoError(t, db.Create(stepExec4).Error)

	// Helper to create context with JWT claims
	createContextWithClaims := func(req *http.Request, rec *httptest.ResponseRecorder, email string) echo.Context {
		c := e.NewContext(req, rec)
		c.Set("user", &authn.UserClaims{
			GivenName:  "Test",
			FamilyName: "User",
		})
		// Set the Subject (email) in claims
		claims := c.Get("user").(*authn.UserClaims)
		claims.Subject = email
		return c
	}

	t.Run("Success_BasicQuery", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my", nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response MyAssignmentsResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, int64(3), response.Total)
		assert.Len(t, response.Data, 3)
		assert.Equal(t, 20, response.Limit)
		assert.Equal(t, 0, response.Offset)
		assert.False(t, response.HasMore)
	})

	t.Run("Success_FilterByStatus", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my?status=pending", nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response MyAssignmentsResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, int64(1), response.Total)
		assert.Len(t, response.Data, 1)
		assert.Equal(t, "pending", response.Data[0].Status)
	})

	t.Run("Success_FilterByWorkflowDefinition", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my?workflow_definition_id="+workflowDef.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response MyAssignmentsResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, int64(2), response.Total)
		assert.Len(t, response.Data, 2)
	})

	t.Run("Success_FilterByDueBefore", func(t *testing.T) {
		dueBefore := now.Format(time.RFC3339)
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my?due_before="+dueBefore, nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response MyAssignmentsResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, int64(1), response.Total)
	})

	t.Run("Success_FilterByDueAfter", func(t *testing.T) {
		dueAfter := now.Format(time.RFC3339)
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my?due_after="+dueAfter, nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response MyAssignmentsResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, int64(2), response.Total)
	})

	t.Run("Success_Pagination", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my?limit=2&offset=0", nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response MyAssignmentsResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, int64(3), response.Total)
		assert.Len(t, response.Data, 2)
		assert.Equal(t, 2, response.Limit)
		assert.Equal(t, 0, response.Offset)
		assert.True(t, response.HasMore)
	})

	t.Run("Success_PaginationOffset", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my?limit=2&offset=2", nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response MyAssignmentsResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, int64(3), response.Total)
		assert.Len(t, response.Data, 1)
		assert.False(t, response.HasMore)
	})

	t.Run("Success_LimitCappedAt100", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my?limit=200", nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response MyAssignmentsResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, 100, response.Limit)
	})

	t.Run("Success_DifferentUser", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my", nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser2.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response MyAssignmentsResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, int64(1), response.Total)
		assert.Len(t, response.Data, 1)
	})

	t.Run("Error_MissingClaims", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("Error_UserNotFound", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my", nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, "nonexistent@example.com")

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("Error_InvalidDueBefore", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my?due_before=invalid", nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("Error_InvalidDueAfter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my?due_after=invalid", nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("Error_InvalidWorkflowDefinitionID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my?workflow_definition_id=invalid", nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("Error_InvalidLimit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my?limit=invalid", nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("Error_InvalidOffset", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my?offset=invalid", nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("Error_NegativeOffset", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my?offset=-1", nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("Error_ZeroLimit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/my?limit=0", nil)
		rec := httptest.NewRecorder()
		c := createContextWithClaims(req, rec, testUser1.Email)

		err := handler.ListMy(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestStepExecutionHandler_Reassign(t *testing.T) {
	handler, db := setupStepExecutionTestHandler(t)
	e := echo.New()
	e.Validator = middleware.NewValidator()

	actor := &relational.User{
		Email:      "actor@example.com",
		FirstName:  "Actor",
		LastName:   "User",
		AuthMethod: "local",
		IsActive:   true,
	}
	require.NoError(t, db.Create(actor).Error)

	newAssignee := &relational.User{
		Email:      "new-assignee@example.com",
		FirstName:  "New",
		LastName:   "Owner",
		AuthMethod: "local",
		IsActive:   true,
	}
	require.NoError(t, db.Create(newAssignee).Error)

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Reassign Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	sysID := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Reassign Instance",
		SystemSecurityPlanID: &sysID,
	}
	require.NoError(t, db.Create(instance).Error)

	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step to Reassign",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef).Error)

	stepExec := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "pending",
		AssignedToType:           "group",
		AssignedToID:             "old-group",
	}
	require.NoError(t, db.Create(stepExec).Error)

	createActorContext := func(req *http.Request, rec *httptest.ResponseRecorder) echo.Context {
		c := e.NewContext(req, rec)
		c.Set("user", &authn.UserClaims{
			GivenName:  actor.FirstName,
			FamilyName: actor.LastName,
		})
		claims := c.Get("user").(*authn.UserClaims)
		claims.Subject = actor.Email
		c.SetParamNames("id")
		c.SetParamValues(stepExec.ID.String())
		return c
	}

	t.Run("Success", func(t *testing.T) {
		reqBody := ReassignStepRequest{
			AssignedToType: "user",
			AssignedToID:   newAssignee.ID.String(),
			Reason:         "load balancing",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/step-executions/"+stepExec.ID.String()+"/reassign", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := createActorContext(req, rec)

		err = handler.Reassign(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response StepExecutionResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
		require.NotNil(t, response.Data)
		assert.Equal(t, "user", response.Data.AssignedToType)
		assert.Equal(t, newAssignee.ID.String(), response.Data.AssignedToID)

		var history []workflows.StepReassignmentHistory
		require.NoError(t, db.Where("step_execution_id = ?", stepExec.ID).Find(&history).Error)
		require.Len(t, history, 1)
		assert.Equal(t, "old-group", history[0].PreviousAssignedToID)
		assert.Equal(t, newAssignee.ID.String(), history[0].NewAssignedToID)
		assert.Equal(t, actor.Email, history[0].ReassignedByEmail)
	})

	t.Run("Error_InvalidStatusForReassignment", func(t *testing.T) {
		require.NoError(t, db.Model(&workflows.StepExecution{}).Where("id = ?", stepExec.ID).Update("status", "completed").Error)

		reqBody := ReassignStepRequest{
			AssignedToType: "group",
			AssignedToID:   "new-group",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/step-executions/"+stepExec.ID.String()+"/reassign", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := createActorContext(req, rec)

		err = handler.Reassign(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		require.NoError(t, db.Model(&workflows.StepExecution{}).Where("id = ?", stepExec.ID).Update("status", "pending").Error)
	})

	t.Run("Error_InvalidAssigneePayload", func(t *testing.T) {
		reqBody := map[string]string{
			"assigned-to-type": "unknown",
			"assigned-to-id":   "x",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/step-executions/"+stepExec.ID.String()+"/reassign", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := createActorContext(req, rec)

		err = handler.Reassign(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("Error_NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		reqBody := ReassignStepRequest{
			AssignedToType: "group",
			AssignedToID:   "new-group",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/step-executions/"+nonExistentID.String()+"/reassign", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user", &authn.UserClaims{
			GivenName:  actor.FirstName,
			FamilyName: actor.LastName,
		})
		claims := c.Get("user").(*authn.UserClaims)
		claims.Subject = actor.Email
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err = handler.Reassign(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}
