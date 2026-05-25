package notificationtroubleshooting

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/worker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeArgsRedactsProviderPayloads(t *testing.T) {
	emailArgs := map[string]any{
		"to":          []any{"admin@example.com"},
		"subject":     "hello",
		"html_body":   "<p>secret body</p>",
		"text_body":   "secret body",
		"attachments": []any{"secret.pdf"},
		"headers":     map[string]any{"Authorization": "Bearer token"},
	}
	sanitizedEmail := sanitizeArgs(worker.JobTypeSendEmail, emailArgs)
	assert.Equal(t, []any{"admin@example.com"}, sanitizedEmail["to"])
	assert.Equal(t, "hello", sanitizedEmail["subject"])
	assert.NotContains(t, sanitizedEmail, "htmlBody")
	assert.NotContains(t, sanitizedEmail, "textBody")
	assert.NotContains(t, sanitizedEmail, "attachments")
	assert.NotContains(t, sanitizedEmail, "headers")

	slackArgs := map[string]any{
		"channel":     "ccf-alerts",
		"target_type": "channel",
		"text":        "secret text",
		"blocks":      []any{"secret block"},
	}
	sanitizedSlack := sanitizeArgs(worker.JobTypeSendSlackChannel, slackArgs)
	assert.Equal(t, "ccf-alerts", sanitizedSlack["channel"])
	assert.Equal(t, "channel", sanitizedSlack["targetType"])
	assert.NotContains(t, sanitizedSlack, "text")
	assert.NotContains(t, sanitizedSlack, "blocks")
}

func TestIsStaleJobUsesProviderAndSourceThresholds(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)

	assert.True(t, isStaleJob(worker.JobTypeSendSlackChannel, "available", now.Add(-11*time.Minute), now))
	assert.False(t, isStaleJob(worker.JobTypeSendSlackChannel, "available", now.Add(-9*time.Minute), now))
	assert.True(t, isStaleJob(worker.JobTypeRiskReviewDeadlineReminderScanner, "available", now.Add(-31*time.Minute), now))
	assert.False(t, isStaleJob(worker.JobTypeRiskReviewDeadlineReminderScanner, "available", now.Add(-29*time.Minute), now))
	assert.False(t, isStaleJob(worker.JobTypeSendSlackChannel, "scheduled", now.Add(time.Minute), now))
	assert.False(t, isStaleJob(worker.JobTypeSendSlackChannel, "completed", now.Add(-24*time.Hour), now))
}

func TestValidateJobsQueryNormalizesRepeatableAndCommaSeparatedFilters(t *testing.T) {
	query := JobsQuery{
		Queues:   []string{"email,slack", "digest"},
		Provider: "SLACK",
		States:   []string{"available,retryable"},
		Limit:    300,
	}

	require.NoError(t, validateJobsQuery(&query))
	assert.Equal(t, []string{"digest", "email", "slack"}, query.Queues)
	assert.Equal(t, "slack", query.Provider)
	assert.Equal(t, []string{"available", "retryable"}, query.States)
	assert.Equal(t, 200, normalizeLimit(query.Limit))
}

func TestValidateJobsQueryRejectsUnsupportedFilters(t *testing.T) {
	require.Error(t, validateJobsQuery(&JobsQuery{Queues: []string{"default"}}))
	require.Error(t, validateJobsQuery(&JobsQuery{Provider: "pagerduty"}))
	require.Error(t, validateJobsQuery(&JobsQuery{States: []string{"lost"}}))
}

func TestNextRunParsesDescriptorSchedules(t *testing.T) {
	now := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)

	next, err := nextRun("@daily", now)
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 5, 23, 0, 0, 0, 0, time.UTC), next)
}

func TestSupportsSystemDestinationOnlyAllowsConfiguredSystemTypes(t *testing.T) {
	assert.True(t, supportsSystemDestination(notification.SystemNotificationNameEvidenceDigest))
	assert.True(t, supportsSystemDestination(notification.SystemNotificationNameWorkflowExecutionFailed))
	assert.True(t, supportsSystemDestination(" WORKFLOW_EXECUTION_FAILED "))

	assert.False(t, supportsSystemDestination(notification.SubscriptionGateTaskAvailable))
	assert.False(t, supportsSystemDestination(notification.SubscriptionGateTaskDailyDigest))
	assert.False(t, supportsSystemDestination(notification.SubscriptionGateRiskNotifications))
	assert.False(t, supportsSystemDestination("poam_deadline_reminder"))
	assert.False(t, supportsSystemDestination("poam_notifications"))
}

func TestSubscriptionDiagnosticsForFamilyUsesDistinctWorkflowLabels(t *testing.T) {
	diagnostics := subscriptionDiagnosticsForFamily("workflow")

	require.Len(t, diagnostics, 2)
	assert.Equal(t, notification.SubscriptionGateTaskAvailable, diagnostics[0].Gate)
	assert.Equal(t, notification.SubscriptionGateTaskAvailable, diagnostics[0].CodeSuffix)
	assert.Equal(t, "Task Available subscribers", diagnostics[0].Label)
	assert.Equal(t, notification.SubscriptionGateTaskDailyDigest, diagnostics[1].Gate)
	assert.Equal(t, notification.SubscriptionGateTaskDailyDigest, diagnostics[1].CodeSuffix)
	assert.Equal(t, "Task Daily Digest subscribers", diagnostics[1].Label)
}

func TestSubscriptionDiagnosticsForFamilyUsesPoamSpecificCode(t *testing.T) {
	diagnostics := subscriptionDiagnosticsForFamily("poam")

	require.Len(t, diagnostics, 1)
	assert.Equal(t, notification.SubscriptionGateRiskNotifications, diagnostics[0].Gate)
	assert.Equal(t, "poam_notifications", diagnostics[0].CodeSuffix)
	assert.Equal(t, "POAM subscribers", diagnostics[0].Label)
}

func TestProviderJobSourcePredicateConstrainsLatestSourceJob(t *testing.T) {
	createdAt := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)

	predicate, args := providerJobSourcePredicate(
		[]string{worker.JobTypeWorkflowTaskDueSoon},
		riverJobRecord{ID: 241582, CreatedAt: createdAt},
	)

	assert.Contains(t, predicate, "source_job_kind")
	assert.Contains(t, predicate, "source_job_id")
	assert.Contains(t, predicate, "source_job_id', ''), NULLIF(metadata ->> 'source_job_id'")
	assert.Contains(t, predicate, "created_at >= ?")
	require.Len(t, args, 3)
	assert.Equal(t, []string{worker.JobTypeWorkflowTaskDueSoon}, args[0])
	assert.Equal(t, "241582", args[1])
	assert.Equal(t, createdAt, args[2])
}

func TestProviderJobSourcePredicateKeepsLegacyWindowForSyntheticSource(t *testing.T) {
	createdAt := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)

	predicate, args := providerJobSourcePredicate(
		[]string{worker.JobTypeWorkflowTaskDueSoon},
		riverJobRecord{CreatedAt: createdAt},
	)

	assert.Contains(t, predicate, "source_job_kind")
	assert.NotContains(t, predicate, "source_job_id")
	assert.Contains(t, predicate, "created_at >= ?")
	require.Len(t, args, 2)
	assert.Equal(t, []string{worker.JobTypeWorkflowTaskDueSoon}, args[0])
	assert.Equal(t, createdAt, args[1])
}
