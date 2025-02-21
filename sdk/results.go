package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/compliance-framework/configuration-service/internal/domain"
	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"io"
	"net/http"
)

type resultClient struct {
	httpClient *http.Client
	config     *Config
}

func (r *resultClient) Create(streamId uuid.UUID, labels map[string]string, result *oscaltypes113.Result) (*oscaltypes113.Result, error) {
	reqBody, _ := json.Marshal(&domain.Result{
		StreamID: streamId,
		Labels:   labels,
		Result:   *result,
	})
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/assessment-results", r.config.BaseURL), bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected api response status code: %d", response.StatusCode)
	}

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(bodyBytes, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
