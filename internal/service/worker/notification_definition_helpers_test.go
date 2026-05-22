package worker

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestBuildWorkflowTaskDigestNotificationRequest_CorrelationIncludesDigestDate(t *testing.T) {
	generatedAt := time.Date(2026, time.April, 20, 9, 30, 0, 0, time.UTC)

	request := buildWorkflowTaskDigestNotificationRequest(
		WorkflowTaskDigestArgs{
			UserID: "user-1",
		},
		digestNotificationData{
			GeneratedAt: generatedAt,
		},
	)

	assert.Equal(t, "workflow_task_digest:user-1:2026-04-20", request.Options.CorrelationID)
	assert.Equal(t, JobTypeWorkflowTaskDigest, request.Options.SourceJobKind)
}

func TestRequestWithSourceJobIDSetsDispatchMetadata(t *testing.T) {
	request := buildWorkflowTaskDigestNotificationRequest(
		WorkflowTaskDigestArgs{UserID: "user-1"},
		digestNotificationData{},
	)

	request = requestWithSourceJobID(request, 241582)

	assert.Equal(t, "241582", request.Options.SourceJobID)
}

func TestRiskReminderDispatchOptions_IncludesWindowKey(t *testing.T) {
	riskID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	ownerUserID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

	options := riskReminderDispatchOptions(
		JobTypeRiskReviewDueReminder,
		"",
		riskID,
		ownerUserID,
		"2026-04-20",
	)

	assert.Equal(
		t,
		"risk_review_due_reminder:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb:2026-04-20",
		options.CorrelationID,
	)
}

func TestBuildRiskOpenDigestNotificationRequest_CorrelationIncludesWindow(t *testing.T) {
	recipientUserID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

	request := buildRiskOpenDigestNotificationRequest(
		RiskOpenDigestArgs{
			RecipientUserID: recipientUserID,
			WindowStart:     "2026-04-13T00:00:00Z",
			WindowEnd:       "2026-04-20T00:00:00Z",
			WindowKind:      riskDigestWindowWeekly,
		},
		riskDigestNotificationData{},
	)

	assert.Equal(
		t,
		"risk_open_digest:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:2026-04-13T00:00:00Z:2026-04-20T00:00:00Z:weekly",
		request.Options.CorrelationID,
	)
}

func TestBuildPoamOpenDigestNotificationRequest_CorrelationIncludesWindow(t *testing.T) {
	recipientUserID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

	request := buildPoamOpenDigestNotificationRequest(
		PoamOpenDigestArgs{
			RecipientUserID: recipientUserID,
			WindowStart:     "2026-04-19T00:00:00Z",
			WindowEnd:       "2026-04-20T00:00:00Z",
			WindowKind:      poamDigestWindowDaily,
		},
		poamOpenDigestNotificationData{},
	)

	assert.Equal(
		t,
		"poam_open_digest:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:2026-04-19T00:00:00Z:2026-04-20T00:00:00Z:daily",
		request.Options.CorrelationID,
	)
}
