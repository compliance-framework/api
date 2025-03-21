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

	Observations *observationsClient
	Findings     *findingsClient
}

func NewClient(client *http.Client, config *Config) *Client {
	return &Client{
		Observations: &observationsClient{
			httpClient: client,
			config:     config,
		},
		Findings: &findingsClient{
			httpClient: client,
			config:     config,
		},
	}
}
