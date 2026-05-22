package notificationtroubleshooting

import (
	"testing"
	"time"

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
