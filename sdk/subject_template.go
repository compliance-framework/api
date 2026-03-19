package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/compliance-framework/api/sdk/types"
)

type subjectTemplateClient struct {
	httpClient *http.Client
	config     *Config
}

type upsertSubjectTemplatesRequest struct {
	PluginID  string                  `json:"plugin-id"`
	Templates []types.SubjectTemplate `json:"templates"`
}

func (r *subjectTemplateClient) Upsert(ctx context.Context, pluginID string, subjectTemplates ...types.SubjectTemplate) error {
	if len(subjectTemplates) == 0 {
		subjectTemplates = []types.SubjectTemplate{}
	}

	reqData := &upsertSubjectTemplatesRequest{
		PluginID:  pluginID,
		Templates: subjectTemplates,
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/agent/subject-templates/batch", r.config.BaseURL), bytes.NewReader(reqBody))
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

	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected api response status code: %d", response.StatusCode)
	}

	return nil
}
