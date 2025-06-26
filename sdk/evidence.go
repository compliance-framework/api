package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"net/http"
)

type evidenceClient struct {
	httpClient *http.Client
	config     *Config
}

func (r *evidenceClient) Create(ctx context.Context, evidence handler.EvidenceCreateRequest) error {
	reqBody, _ := json.Marshal(evidence)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/agent/evidence", r.config.BaseURL), bytes.NewReader(reqBody))
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
