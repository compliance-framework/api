package relational

import (
	"time"

	"gorm.io/gorm"
)

// SlackUserLink associates a CCF user with a Slack account.
type SlackUserLink struct {
	UUIDModel

	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `json:"deletedAt" gorm:"index"`

	UserID string `json:"userId" gorm:"not null;uniqueIndex:idx_ccf_slack_user_links_user,WHERE:deleted_at IS NULL"`

	SlackUserID string `json:"slackUserId" gorm:"not null;uniqueIndex:idx_ccf_slack_user_links_identity,WHERE:deleted_at IS NULL"`
	SlackTeamID string `json:"slackTeamId" gorm:"not null;uniqueIndex:idx_ccf_slack_user_links_identity,WHERE:deleted_at IS NULL"`

	SlackTeamDomain  string `json:"slackTeamDomain"`
	SlackTeamName    string `json:"slackTeamName"`
	SlackDisplayName string `json:"slackDisplayName"`
	SlackEmail       string `json:"slackEmail"`

	LastLinkedAt time.Time `json:"lastLinkedAt"`

	User User `json:"user,omitempty" gorm:"foreignKey:UserID;references:ID"`
}

func (SlackUserLink) TableName() string {
	return "ccf_slack_user_links"
}
