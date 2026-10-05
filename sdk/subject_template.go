package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/compliance-framework/api/sdk/types"
)

type subjectTemplateClient struct {
	client *Client
}

type upsertSubjectTemplatesRequest struct {
	PluginID  string                  `json:"plugin-id"`
	Templates []types.SubjectTemplate `json:"templates"`
}

type upsertSubjectTemplatesResponse struct {
	Data struct {
		// Warnings name accepted templates that produce no evidence subjects (non-component
		// templates).
		Warnings []string `json:"warnings"`
	} `json:"data"`
}

func (r *subjectTemplateClient) Upsert(ctx context.Context, pluginID string, subjectTemplates ...types.SubjectTemplate) error {
	if len(subjectTemplates) == 0 {
		subjectTemplates = []types.SubjectTemplate{}
	}

	reqData := &upsertSubjectTemplatesRequest{
		PluginID:  pluginID,
		Templates: subjectTemplates,
	}

	response, err := r.client.doJSONRequest(ctx, http.MethodPost, "/api/agent/subject-templates/batch", reqData)
	if err != nil {
		return err
	}
	defer closeResponseBody(response, r.client.config.Logger)

	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected api response status code: %d", response.StatusCode)
	}

	r.logWarnings(pluginID, response)
	return nil
}

// logWarnings logs the warnings the API returns for the upserted templates, so agents
// report them without handling the response themselves. Warnings are informational: a body
// that can't be read doesn't fail the upsert.
func (r *subjectTemplateClient) logWarnings(pluginID string, response *http.Response) {
	logger := r.client.config.Logger
	if logger == nil {
		return
	}

	var body upsertSubjectTemplatesResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return
	}
	for _, warning := range body.Data.Warnings {
		logger.Warnw("Subject template warning", "plugin_id", pluginID, "warning", warning)
	}
}
