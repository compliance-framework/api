package sdk

import (
	"context"
	"fmt"
	"net/http"

	"github.com/compliance-framework/api/sdk/types"
)

type evidenceClient struct {
	client *Client
}

func (r *evidenceClient) Create(ctx context.Context, evidence ...types.Evidence) error {
	for _, evid := range evidence {
		response, err := r.client.doJSONRequest(ctx, http.MethodPost, "/api/evidence", evid)
		if err != nil {
			return err
		}
		closeResponseBody(response, r.client.config.Logger)

		if response.StatusCode != http.StatusCreated {
			return fmt.Errorf("unexpected api response status code: %d", response.StatusCode)
		}
	}

	return nil
}
