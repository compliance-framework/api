package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/compliance-framework/api/sdk/types"
)

type evidenceClient struct {
	httpClient *http.Client
	config     *Config
}

func (r *evidenceClient) Create(ctx context.Context, evidence ...types.Evidence) error {
	for _, evid := range evidence {
		reqBody, _ := json.Marshal(evid)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/evidence", r.config.BaseURL), bytes.NewReader(reqBody))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := r.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer func() {
			err := response.Body.Close()
			if err != nil {
				if r.config.Logger != nil {
					r.config.Logger.Error("failed to close response body", "err", err)
				}
			}
		}()

		if response.StatusCode != http.StatusCreated {
			return fmt.Errorf("unexpected api response status code: %d", response.StatusCode)
		}
	}

	return nil
}
