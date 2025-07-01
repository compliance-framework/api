package sdk

import (
	"net/http"
)

type Config struct {
	BaseURL string
}

type Client struct {
	httpClient *http.Client

	config *Config

	Evidence *evidenceClient
}

func NewClient(client *http.Client, config *Config) *Client {
	return &Client{
		httpClient: client,
		config:     config,
		Evidence: &evidenceClient{
			httpClient: client,
			config:     config,
		},
	}
}
