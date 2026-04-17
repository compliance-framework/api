package worker

import (
	"context"
	"fmt"

	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
)

func renderWorkflowTaskAssignedEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	assignedModel, err := workflowTaskAssignedNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return emailprovider.TemplateContent{
		TemplateName: "workflow-task-assigned",
		TemplateData: map[string]any{
			"UserName":              assignedModel.UserName,
			"StepTitle":             assignedModel.StepTitle,
			"WorkflowTitle":         assignedModel.WorkflowTitle,
			"WorkflowInstanceTitle": assignedModel.WorkflowInstanceTitle,
			"StepURL":               assignedModel.StepURL,
			"MyTasksURL":            assignedModel.MyTasksURL,
			"DueDate":               assignedModel.DueDate,
		},
		Subject:  fmt.Sprintf("Task ready for you: %s — %s", assignedModel.StepTitle, assignedModel.WorkflowTitle),
		TextBody: fmt.Sprintf("%s is assigned to you and due %s. Open: %s", assignedModel.StepTitle, assignedModel.DueDate, assignedModel.StepURL),
	}, nil
}

func renderWorkflowTaskDueSoonEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	dueSoonModel, err := workflowTaskDueSoonNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return emailprovider.TemplateContent{
		TemplateName: "workflow-task-due-soon",
		TemplateData: map[string]any{
			"UserName":              dueSoonModel.UserName,
			"StepTitle":             dueSoonModel.StepTitle,
			"WorkflowTitle":         dueSoonModel.WorkflowTitle,
			"WorkflowInstanceTitle": dueSoonModel.WorkflowInstanceTitle,
			"StepURL":               dueSoonModel.StepURL,
			"MyTasksURL":            dueSoonModel.MyTasksURL,
			"DueDate":               dueSoonModel.DueDate,
		},
		Subject:  fmt.Sprintf("Reminder: %s is due soon — %s", dueSoonModel.StepTitle, dueSoonModel.WorkflowTitle),
		TextBody: fmt.Sprintf("%s is due on %s. Open: %s", dueSoonModel.StepTitle, dueSoonModel.DueDate, dueSoonModel.StepURL),
	}, nil
}

func renderWorkflowTaskDigestEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	digestModel, err := workflowTaskDigestNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return emailprovider.TemplateContent{
		TemplateName: "workflow-task-digest",
		TemplateData: digestModel.templateData(),
		Subject:      fmt.Sprintf("Your workflow task summary — %s", formatDate(digestModel.GeneratedAt)),
		TextBody:     "Your workflow task digest is ready.",
	}, nil
}
