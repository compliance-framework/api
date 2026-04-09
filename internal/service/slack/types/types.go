package types

import "github.com/slack-go/slack"

type SendResult struct {
	Success      bool   `json:"success"`
	Message      string `json:"message,omitempty"`
	Channel      string `json:"channel,omitempty"`
	DeliveryID   string `json:"deliveryId,omitempty"`
	ResponseText string `json:"responseText,omitempty"`
	Error        string `json:"error,omitempty"`
}

type Message struct {
	Text   string
	Blocks []slack.Block
}
