package relational

import "time"

// SlackLinkAttempt stores one-time OAuth state for Slack profile linking.
type SlackLinkAttempt struct {
	UUIDModel

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	State  string `json:"state" gorm:"size:256;not null;uniqueIndex:idx_ccf_slack_link_attempts_expires_at_state,priority:1"`
	UserID string `json:"userId" gorm:"not null;index"`

	ExpiresAt time.Time `json:"expiresAt" gorm:"not null;uniqueIndex:idx_ccf_slack_link_attempts_expires_at_state,priority:2"`
}

func (SlackLinkAttempt) TableName() string {
	return "ccf_slack_link_attempts"
}
