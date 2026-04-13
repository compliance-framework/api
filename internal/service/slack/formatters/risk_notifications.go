package formatters

import (
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/slack-go/slack"
)

type RiskDigestItem struct {
	Title          string
	SSPName        string
	Status         string
	Severity       string
	OwnerName      string
	ReviewDeadline string
	RiskURL        string
}

const riskDigestSlackSectionItemLimit = 5

func FormatRiskReviewDueReminderMessage(
	userName string,
	riskTitle string,
	sspName string,
	riskStatus string,
	reviewDeadline string,
	riskURL string,
) (*types.Message, error) {
	return formatRiskNotificationMessage(
		"Risk Review Due Soon",
		userName,
		"A risk review deadline is approaching.",
		riskTitle,
		sspName,
		riskStatus,
		reviewDeadline,
		"",
		riskURL,
	)
}

func FormatRiskReviewOverdueEscalationMessage(
	userName string,
	riskTitle string,
	sspName string,
	riskStatus string,
	reviewDeadline string,
	riskURL string,
) (*types.Message, error) {
	return formatRiskNotificationMessage(
		"Risk Review Overdue",
		userName,
		"A risk review is overdue and requires attention.",
		riskTitle,
		sspName,
		riskStatus,
		reviewDeadline,
		"",
		riskURL,
	)
}

func FormatRiskStaleOpenReminderMessage(
	userName string,
	riskTitle string,
	sspName string,
	riskStatus string,
	lastSeenAt string,
	riskURL string,
) (*types.Message, error) {
	return formatRiskNotificationMessage(
		"Stale Risk Reminder",
		userName,
		"A risk assigned to you appears stale and has not been updated recently.",
		riskTitle,
		sspName,
		riskStatus,
		"",
		lastSeenAt,
		riskURL,
	)
}

func FormatRiskOpenDigestMessage(
	recipientName string,
	periodLabel string,
	newItems []RiskDigestItem,
	overdueItems []RiskDigestItem,
	staleItems []RiskDigestItem,
	overdueReviewItems []RiskDigestItem,
	dueForReviewItems []RiskDigestItem,
	risksURL string,
) (*types.Message, error) {
	title := strings.TrimSpace(periodLabel)
	if title == "" {
		title = "Daily digest"
	}

	greeting := "Here is the latest summary of the risks that need your attention."
	if name := strings.TrimSpace(recipientName); name != "" {
		greeting = fmt.Sprintf("Hi %s, here is the latest summary of the risks that need your attention.", name)
	}

	blocks := []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject(slack.PlainTextType, "Risk Digest", true, false)),
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, greeting, false, false), nil, nil),
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*Period:* %s", title), false, false), nil, nil),
	}

	blocks = appendRiskDigestSection(blocks, "New Since Last Digest", newItems)
	blocks = appendRiskDigestSection(blocks, "Overdue For Action", overdueItems)
	blocks = appendRiskDigestSection(blocks, "Stale", staleItems)
	blocks = appendRiskDigestSection(blocks, "Overdue Review", overdueReviewItems)
	blocks = appendRiskDigestSection(blocks, "Due For Review", dueForReviewItems)

	if len(newItems) == 0 && len(overdueItems) == 0 && len(staleItems) == 0 && len(overdueReviewItems) == 0 && len(dueForReviewItems) == 0 {
		blocks = append(blocks, slack.NewDividerBlock())
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, ":white_check_mark: No risks currently require attention in this digest window.", false, false),
			nil,
			nil,
		))
	}

	risksURL = strings.TrimSpace(risksURL)
	if risksURL != "" {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("<%s|View all risks>", risksURL), false, false),
			nil,
			nil,
		))
	}

	return &types.Message{
		Text: fmt.Sprintf(
			"Risk digest: new=%d, overdue_action=%d, stale=%d, overdue_review=%d, due_review=%d",
			len(newItems),
			len(overdueItems),
			len(staleItems),
			len(overdueReviewItems),
			len(dueForReviewItems),
		),
		Blocks: blocks,
	}, nil
}

func formatRiskNotificationMessage(
	header string,
	userName string,
	message string,
	riskTitle string,
	sspName string,
	riskStatus string,
	reviewDeadline string,
	lastSeenAt string,
	riskURL string,
) (*types.Message, error) {
	title := strings.TrimSpace(riskTitle)
	if title == "" {
		title = "Untitled risk"
	}

	ssp := strings.TrimSpace(sspName)
	if ssp == "" {
		ssp = "N/A"
	}

	status := strings.TrimSpace(riskStatus)
	if status == "" {
		status = "N/A"
	}

	greeting := message
	if name := strings.TrimSpace(userName); name != "" {
		greeting = fmt.Sprintf("Hi %s, %s", name, lowerFirst(message))
	}

	details := fmt.Sprintf("*Risk:* %s\n*SSP:* %s\n*Status:* %s", title, ssp, status)
	if trimmed := strings.TrimSpace(reviewDeadline); trimmed != "" {
		details += fmt.Sprintf("\n*Review Deadline:* %s", trimmed)
	}
	if trimmed := strings.TrimSpace(lastSeenAt); trimmed != "" {
		details += fmt.Sprintf("\n*Last Seen:* %s", trimmed)
	}

	blocks := []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject(slack.PlainTextType, header, true, false)),
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, greeting, false, false), nil, nil),
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, details, false, false), nil, nil),
	}

	riskURL = strings.TrimSpace(riskURL)
	if riskURL != "" {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("<%s|Open Risk>", riskURL), false, false),
			nil,
			nil,
		))
	}

	return &types.Message{
		Text:   fmt.Sprintf("%s: %s", header, title),
		Blocks: blocks,
	}, nil
}

func appendRiskDigestSection(blocks []slack.Block, title string, items []RiskDigestItem) []slack.Block {
	if len(items) == 0 {
		return blocks
	}

	blocks = append(blocks, slack.NewDividerBlock())
	blocks = append(blocks, slack.NewSectionBlock(
		slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*%s (%d)*", title, len(items)), false, false),
		nil,
		nil,
	))

	limit := len(items)
	if limit > riskDigestSlackSectionItemLimit {
		limit = riskDigestSlackSectionItemLimit
	}

	for i := 0; i < limit; i++ {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, formatRiskDigestItem(items[i]), false, false),
			nil,
			nil,
		))
	}

	if len(items) > limit {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(
				slack.MarkdownType,
				fmt.Sprintf("_Showing %d of %d items in Slack. Open the full risk view for the rest._", limit, len(items)),
				false,
				false,
			),
			nil,
			nil,
		))
	}

	return blocks
}

func formatRiskDigestItem(item RiskDigestItem) string {
	title := strings.TrimSpace(item.Title)
	if title == "" {
		title = "Untitled risk"
	}

	titleLine := "*" + title + "*"
	if url := strings.TrimSpace(item.RiskURL); url != "" {
		titleLine = fmt.Sprintf("*<%s|%s>*", url, title)
	}

	lines := []string{titleLine}

	if value := strings.TrimSpace(item.SSPName); value != "" {
		lines = append(lines, "SSP: "+value)
	}
	if value := strings.TrimSpace(item.Status); value != "" {
		lines = append(lines, "Status: "+value)
	}
	if value := strings.TrimSpace(item.Severity); value != "" {
		lines = append(lines, "Severity: "+value)
	}
	if value := strings.TrimSpace(item.OwnerName); value != "" {
		lines = append(lines, "Owner: "+value)
	}
	if value := strings.TrimSpace(item.ReviewDeadline); value != "" {
		lines = append(lines, "Review deadline: "+value)
	}

	return strings.Join(lines, "\n")
}

func lowerFirst(value string) string {
	if value == "" {
		return value
	}

	runes := []rune(value)
	if len(runes) == 0 {
		return value
	}
	runes[0] = []rune(strings.ToLower(string(runes[0])))[0]
	return string(runes)
}
