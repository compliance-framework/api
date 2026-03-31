package formatters

import (
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/slack-go/slack"
)

func FormatDigestMessage(digestSummary *DigestSummary) (*types.Message, error) {
	if digestSummary == nil {
		return nil, fmt.Errorf("digest summary is required")
	}

	// Limit the number of evidence items shown in the Slack digest to keep the message concise
	// and prevent overwhelming users within Slack's UI.
	const maxEvidenceItems = 3

	blocks := []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject(slack.PlainTextType, "Evidence Digest", true, false)),
		slack.NewSectionBlock(
			slack.NewTextBlockObject(
				slack.MarkdownType,
				"Here is your evidence compliance summary. This digest highlights evidence that requires attention.",
				false,
				false,
			),
			nil,
			nil,
		),
		slack.NewDividerBlock(),
		slack.NewSectionBlock(nil, []*slack.TextBlockObject{
			slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*Total Evidence*\n%d", digestSummary.TotalCount), false, false),
			slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*Satisfied*\n%d", digestSummary.SatisfiedCount), false, false),
			slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*Not Satisfied*\n%d", digestSummary.NotSatisfiedCount), false, false),
			slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*Expired*\n%d", digestSummary.ExpiredCount), false, false),
		}, nil),
	}

	remaining := maxEvidenceItems
	shownTotal := 0

	availableNotSatisfied := len(digestSummary.TopNotSatisfied)
	if int(digestSummary.NotSatisfiedCount) < availableNotSatisfied {
		availableNotSatisfied = int(digestSummary.NotSatisfiedCount)
	}

	availableExpired := len(digestSummary.TopExpired)
	if int(digestSummary.ExpiredCount) < availableExpired {
		availableExpired = int(digestSummary.ExpiredCount)
	}

	notSatisfiedToShow := len(digestSummary.TopNotSatisfied)
	if notSatisfiedToShow > remaining {
		notSatisfiedToShow = remaining
	}
	if notSatisfiedToShow > 0 {
		blocks = append(blocks, slack.NewDividerBlock())
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, "*Not Satisfied Evidence*", false, false),
			nil,
			nil,
		))
		for i := 0; i < notSatisfiedToShow; i++ {
			blocks = append(blocks, slack.NewSectionBlock(
				slack.NewTextBlockObject(slack.MarkdownType, formatEvidenceLine(digestSummary.TopNotSatisfied[i], digestSummary.BaseURL, "Status: not-satisfied"), false, false),
				nil,
				nil,
			))
		}
		shownTotal += notSatisfiedToShow
		remaining -= notSatisfiedToShow
	}

	expiredToShow := len(digestSummary.TopExpired)
	if expiredToShow > remaining {
		expiredToShow = remaining
	}
	if expiredToShow > 0 {
		blocks = append(blocks, slack.NewDividerBlock())
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, "*Expired Evidence*", false, false),
			nil,
			nil,
		))
		for i := 0; i < expiredToShow; i++ {
			meta := "Expired: N/A"
			if digestSummary.TopExpired[i].ExpiresAt != "" {
				meta = "Expired: " + digestSummary.TopExpired[i].ExpiresAt
			}
			blocks = append(blocks, slack.NewSectionBlock(
				slack.NewTextBlockObject(slack.MarkdownType, formatEvidenceLine(digestSummary.TopExpired[i], digestSummary.BaseURL, meta), false, false),
				nil,
				nil,
			))
		}
		shownTotal += expiredToShow
	}

	hasMore := availableNotSatisfied > notSatisfiedToShow || availableExpired > expiredToShow
	if hasMore {
		remainingNotSatisfied := availableNotSatisfied - notSatisfiedToShow
		if remainingNotSatisfied < 0 {
			remainingNotSatisfied = 0
		}
		remainingExpired := availableExpired - expiredToShow
		if remainingExpired < 0 {
			remainingExpired = 0
		}

		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(
				slack.MarkdownType,
				buildMoreEvidenceText(shownTotal, remainingNotSatisfied, remainingExpired),
				false,
				false,
			),
			nil,
			nil,
		))
	}

	if digestSummary.NotSatisfiedCount == 0 && digestSummary.ExpiredCount == 0 {
		blocks = append(blocks, slack.NewDividerBlock())
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, ":white_check_mark: All evidence is satisfied.", false, false),
			nil,
			nil,
		))
	}

	if digestSummary.BaseURL != "" {
		viewAllURL := strings.TrimRight(digestSummary.BaseURL, "/") + "/evidence"
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("<%s|View all evidence>", viewAllURL), false, false),
			nil,
			nil,
		))
	}

	return &types.Message{
		Text:   buildFallbackText(digestSummary),
		Blocks: blocks,
	}, nil
}

func buildFallbackText(summary *DigestSummary) string {
	return fmt.Sprintf(
		"Evidence Digest: total=%d, satisfied=%d, not-satisfied=%d, expired=%d",
		summary.TotalCount,
		summary.SatisfiedCount,
		summary.NotSatisfiedCount,
		summary.ExpiredCount,
	)
}

func formatEvidenceLine(item DigestSummaryEvidence, baseURL string, meta string) string {
	title := strings.TrimSpace(item.Title)
	if title == "" {
		title = "Untitled evidence"
	}

	titleLine := "*" + title + "*"
	if baseURL != "" && item.ID != "" {
		titleLine = fmt.Sprintf("*<%s/evidence/%s|%s>*", strings.TrimRight(baseURL, "/"), item.ID, title)
	}
	maxDescriptionLength := 240
	truncatedDescriptionLength := 237
	description := strings.TrimSpace(item.Description)
	runes := []rune(description)
	if len(runes) > maxDescriptionLength {
		end := truncatedDescriptionLength
		if end > len(runes) {
			end = len(runes)
		}
		description = string(runes[:end]) + "..."
	}

	lines := []string{titleLine}
	if description != "" {
		lines = append(lines, description)
	}
	if meta != "" {
		lines = append(lines, "_"+meta+"_")
	}
	return strings.Join(lines, "\n")
}

func buildMoreEvidenceText(shown, remainingNotSatisfied, remainingExpired int) string {
	parts := make([]string, 0, 2)
	if remainingNotSatisfied > 0 {
		parts = append(parts, fmt.Sprintf("%d more not-satisfied %s", remainingNotSatisfied, pluralize(remainingNotSatisfied, "item", "items")))
	}
	if remainingExpired > 0 {
		parts = append(parts, fmt.Sprintf("%d more expired %s", remainingExpired, pluralize(remainingExpired, "item", "items")))
	}

	if len(parts) == 0 {
		return fmt.Sprintf("_Showing %d evidence items in Slack. There is more to see in the full evidence view._", shown)
	}

	return fmt.Sprintf(
		"_Showing %d evidence items. The full evidence view has %s._",
		shown,
		strings.Join(parts, " and "),
	)
}

func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}
