package templates

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTemplateService_Use(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err, "Failed to create template service")

	data := TemplateData{
		"FirstName": "John",
		"ResetURL":  "http://localhost:8000/auth/password-reset?token=abc123",
	}

	html, text, err := service.Use("forgot-password", data)
	require.NoError(t, err, "Failed to use template")
	require.NotEmpty(t, html, "HTML content should not be empty")
	require.NotEmpty(t, text, "Text content should not be empty")
	require.Contains(t, html, "Hello John")
	require.Contains(t, text, "Hello John")
	require.Contains(t, html, data["ResetURL"].(string))
	require.Contains(t, text, data["ResetURL"].(string))
}

func TestTemplateService_UseHTMLAndUseText(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err, "Failed to create template service")

	data := TemplateData{
		"FirstName": "Alice",
		"ResetURL":  "http://localhost/reset?token=xyz",
	}

	htmlContent, err := service.UseHTML("forgot-password", data)
	require.NoError(t, err, "UseHTML should render known template")
	require.Contains(t, htmlContent, "Alice")
	require.Contains(t, htmlContent, data["ResetURL"].(string))

	textContent, err := service.UseText("forgot-password", data)
	require.NoError(t, err, "UseText should render known template")
	require.Contains(t, textContent, "Alice")
	require.Contains(t, textContent, data["ResetURL"].(string))
}

func TestTemplateService_MissingTemplates(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err, "Failed to create template service")

	_, err = service.UseHTML("missing-template", TemplateData{})
	require.Error(t, err, "UseHTML should error for missing template")

	_, err = service.UseText("missing-template", TemplateData{})
	require.Error(t, err, "UseText should error for missing template")
}

func TestTemplateService_WorkflowTaskAssigned(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err)

	dueDate := "2026-03-01 09:00:00 +0000 UTC"
	data := TemplateData{
		"UserName":              "Alice Smith",
		"StepTitle":             "Review Policy",
		"WorkflowTitle":         "Annual Audit",
		"WorkflowInstanceTitle": "Audit 2026",
		"StepURL":               "https://app.example.com/steps/abc",
		"DueDate":               dueDate,
	}

	html, text, err := service.Use("workflow-task-assigned", data)
	require.NoError(t, err)
	require.NotEmpty(t, html)
	require.NotEmpty(t, text)
	require.Contains(t, html, "Alice Smith")
	require.Contains(t, html, "Review Policy")
	require.Contains(t, html, "Annual Audit")
	require.Contains(t, html, "https://app.example.com/steps/abc")
	require.Contains(t, text, "Alice Smith")
	require.Contains(t, text, "Review Policy")
	require.Contains(t, text, "https://app.example.com/steps/abc")
}

func TestTemplateService_WorkflowTaskAssigned_NoDueDate(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err)

	data := TemplateData{
		"UserName":              "Bob",
		"StepTitle":             "Submit Evidence",
		"WorkflowTitle":         "SOC2 Audit",
		"WorkflowInstanceTitle": "SOC2 2026",
		"StepURL":               "https://app.example.com/steps/xyz",
		"DueDate":               nil,
	}

	html, text, err := service.Use("workflow-task-assigned", data)
	require.NoError(t, err)
	require.NotEmpty(t, html)
	require.NotEmpty(t, text)
	require.Contains(t, html, "Bob")
	require.NotContains(t, html, "Due Date")
}

func TestTemplateService_WorkflowTaskDueSoon(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err)

	data := TemplateData{
		"UserName":              "Alice Smith",
		"StepTitle":             "Submit Evidence",
		"WorkflowTitle":         "SOC2 Audit",
		"WorkflowInstanceTitle": "SOC2 2026",
		"StepURL":               "https://app.example.com/steps/abc",
		"DueDate":               "2026-03-01",
	}

	html, text, err := service.Use("workflow-task-due-soon", data)
	require.NoError(t, err)
	require.NotEmpty(t, html)
	require.NotEmpty(t, text)
	require.Contains(t, html, "Alice Smith")
	require.Contains(t, html, "Submit Evidence")
	require.Contains(t, html, "SOC2 Audit")
	require.Contains(t, html, "https://app.example.com/steps/abc")
	require.Contains(t, html, "2026-03-01")
	require.Contains(t, text, "Alice Smith")
	require.Contains(t, text, "Submit Evidence")
	require.Contains(t, text, "https://app.example.com/steps/abc")
	require.Contains(t, text, "TOMORROW")
}

func TestTemplateService_WorkflowExecutionFailed_WithData(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err)

	data := TemplateData{
		"RecipientName":        "Alice Smith",
		"WorkflowTitle":        "SOC2 Audit",
		"WorkflowInstanceName": "SOC2 2026",
		"ExecutionID":          "exec-abc-123",
		"FailureReason":        "2 of 5 steps failed",
		"FailedAt":             "Wed, 19 Feb 2026 08:00:00 UTC",
		"FailedSteps":          2,
		"CompletedSteps":       3,
		"TotalSteps":           5,
		"WorkflowURL":          "https://app.example.com/workflows/abc",
	}

	html, text, err := service.Use("workflow-execution-failed", data)
	require.NoError(t, err)
	require.NotEmpty(t, html)
	require.NotEmpty(t, text)
	require.Contains(t, html, "Alice Smith")
	require.Contains(t, html, "SOC2 Audit")
	require.Contains(t, html, "SOC2 2026")
	require.Contains(t, html, "2 of 5 steps failed")
	require.Contains(t, html, "exec-abc-123")
	require.Contains(t, text, "Alice Smith")
	require.Contains(t, text, "SOC2 Audit")
	require.Contains(t, text, "2 of 5 steps failed")
	require.Contains(t, text, "FAILED")
}

func TestTemplateService_WorkflowExecutionFailed_NoURL(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err)

	data := TemplateData{
		"RecipientName":        "Bob",
		"WorkflowTitle":        "Annual Audit",
		"WorkflowInstanceName": "Audit 2026",
		"ExecutionID":          "exec-xyz-456",
		"FailureReason":        "1 of 3 steps failed",
		"FailedAt":             "Wed, 19 Feb 2026 09:00:00 UTC",
		"FailedSteps":          1,
		"CompletedSteps":       2,
		"TotalSteps":           3,
		"WorkflowURL":          "",
	}

	html, text, err := service.Use("workflow-execution-failed", data)
	require.NoError(t, err)
	require.NotEmpty(t, html)
	require.NotEmpty(t, text)
	require.Contains(t, html, "Bob")
	require.NotContains(t, html, "View Workflow Instance")
}

func TestTemplateService_WorkflowTaskDigest_WithTasks(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err)

	pendingDue := "2026-03-15"
	overdueDue := "2026-02-01"
	data := TemplateData{
		"UserName":    "Alice Smith",
		"PeriodLabel": "Daily digest — Wednesday, 19 February 2026",
		"PendingTasks": []map[string]interface{}{
			{
				"StepTitle":             "Submit Evidence",
				"WorkflowTitle":         "SOC2 Audit",
				"WorkflowInstanceTitle": "SOC2 2026",
				"DueDate":               &pendingDue,
				"StepURL":               "https://app.example.com/steps/abc",
			},
		},
		"OverdueTasks": []map[string]interface{}{
			{
				"StepTitle":             "Review Policy",
				"WorkflowTitle":         "Annual Audit",
				"WorkflowInstanceTitle": "Audit 2026",
				"DueDate":               &overdueDue,
				"StepURL":               "https://app.example.com/steps/xyz",
			},
		},
	}

	html, text, err := service.Use("workflow-task-digest", data)
	require.NoError(t, err)
	require.NotEmpty(t, html)
	require.NotEmpty(t, text)
	require.Contains(t, html, "Alice Smith")
	require.Contains(t, html, "Submit Evidence")
	require.Contains(t, html, "Review Policy")
	require.Contains(t, html, "SOC2 Audit")
	require.Contains(t, text, "Alice Smith")
	require.Contains(t, text, "Submit Evidence")
	require.Contains(t, text, "PENDING")
	require.Contains(t, text, "OVERDUE")
}

func TestTemplateService_WorkflowTaskDigest_EmptyTasks(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err)

	data := TemplateData{
		"UserName":     "Bob",
		"PeriodLabel":  "Daily digest — Wednesday, 19 February 2026",
		"PendingTasks": []map[string]interface{}{},
		"OverdueTasks": []map[string]interface{}{},
	}

	html, text, err := service.Use("workflow-task-digest", data)
	require.NoError(t, err)
	require.NotEmpty(t, html)
	require.NotEmpty(t, text)
	require.Contains(t, html, "Bob")
}

func TestTemplateService_RiskTemplates(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err)

	data := TemplateData{
		"OwnerName":      "Alice Smith",
		"RiskTitle":      "Weak MFA Controls",
		"SSPName":        "GoodRead SSP",
		"RiskStatus":     "risk-accepted",
		"ReviewDeadline": "01/mar/2026",
		"LastSeenAt":     "15/feb/2026",
		"RiskURL":        "https://app.example.com/risks/123",
	}

	for _, name := range []string{
		"risk-review-due-reminder",
		"risk-review-overdue-escalation",
		"risk-stale-open-reminder",
	} {
		html, text, err := service.Use(name, data)
		require.NoError(t, err)
		require.NotEmpty(t, html)
		require.NotEmpty(t, text)
		require.Contains(t, html, "Alice Smith")
		require.Contains(t, text, "Weak MFA Controls")
		require.Contains(t, text, "https://app.example.com/risks/123")
	}
}

func TestTemplateService_ListTemplates(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err, "Failed to create template service")

	templates := service.ListTemplates()
	require.NotEmpty(t, templates, "Should have at least one template")

	found := false
	for _, tmpl := range templates {
		if tmpl == "forgot-password" {
			found = true
			break
		}
	}
	require.True(t, found, "Should contain 'forgot-password' template")
}
