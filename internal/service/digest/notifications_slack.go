package digest

import (
	"context"
	"fmt"

	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	slackformatters "github.com/compliance-framework/api/internal/service/slack/formatters"
	"github.com/slack-go/slack"
)

func (m evidenceDigestNotificationModel) slackSummary() *slackformatters.DigestSummary {
	summary := m.summary()
	return &slackformatters.DigestSummary{
		TotalCount:        summary.TotalCount,
		SatisfiedCount:    summary.SatisfiedCount,
		NotSatisfiedCount: summary.NotSatisfiedCount,
		ExpiredCount:      summary.ExpiredCount,
		TopExpired:        toSlackDigestEvidence(summary.TopExpired),
		TopNotSatisfied:   toSlackDigestEvidence(summary.TopNotSatisfied),
		BaseURL:           m.WebBaseURL,
	}
}

func toSlackDigestEvidence(items []EvidenceItem) []slackformatters.DigestSummaryEvidence {
	if len(items) == 0 {
		return nil
	}

	out := make([]slackformatters.DigestSummaryEvidence, 0, len(items))
	for i := range items {
		out = append(out, slackformatters.DigestSummaryEvidence{
			ID:          items[i].ID,
			Title:       items[i].Title,
			Description: items[i].Description,
			ExpiresAt:   items[i].ExpiresAt,
		})
	}

	return out
}

func renderEvidenceDigestSlack(_ context.Context, model any) (slackprovider.Content, error) {
	digestModel, err := evidenceDigestModelFromAny(model)
	if err != nil {
		return slackprovider.Content{}, err
	}

	message, err := slackformatters.FormatDigestMessage(digestModel.slackSummary())
	if err != nil {
		return slackprovider.Content{}, fmt.Errorf("failed to format slack message for digest: %w", err)
	}

	return slackprovider.Content{
		Text:   message.Text,
		Blocks: append([]slack.Block(nil), message.Blocks...),
	}, nil
}
