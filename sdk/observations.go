package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/compliance-framework/configuration-service/sdk/types"
	"net/http"
)

type observationsClient struct {
	httpClient *http.Client
	config     *Config
}

func (r *observationsClient) Create(ctx context.Context, observations []types.Observation) error {
	reqBody, _ := json.Marshal(observations)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/observations/", r.config.BaseURL), bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected api response status code: %d", response.StatusCode)
	}

	return nil
}
