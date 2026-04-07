package sdk

import (
	"context"
	"fmt"
	"net/http"

	"github.com/compliance-framework/api/sdk/types"
)

type heartbeatClient struct {
	client *Client
}

func (h *heartbeatClient) Create(ctx context.Context, heartbeat types.Heartbeat) error {
	response, err := h.client.doJSONRequest(ctx, http.MethodPost, "/api/agent/heartbeat", heartbeat)
	if err != nil {
		return err
	}
	closeResponseBody(response, h.client.config.Logger)

	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected api response status code: %d", response.StatusCode)
	}

	return nil
}
