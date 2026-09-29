package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// UpsertSubjectTemplatesResult is the outcome of a subject template batch upsert.
type UpsertSubjectTemplatesResult struct {
	// Warnings are non-fatal notices about accepted templates, e.g. templates whose
	// type is not "component" and therefore will not produce subjects.
	Warnings []string `json:"warnings,omitempty"`
}

type upsertSubjectTemplatesResponse struct {
	Data UpsertSubjectTemplatesResult `json:"data"`
}

func (r *subjectTemplateClient) Upsert(ctx context.Context, pluginID string, subjectTemplates ...types.SubjectTemplate) (*UpsertSubjectTemplatesResult, error) {
	if len(subjectTemplates) == 0 {
		subjectTemplates = []types.SubjectTemplate{}
	}

	reqData := &upsertSubjectTemplatesRequest{
		PluginID:  pluginID,
		Templates: subjectTemplates,
	}

	response, err := r.client.doJSONRequest(ctx, http.MethodPost, "/api/agent/subject-templates/batch", reqData)
	if err != nil {
		return nil, err
	}
	defer closeResponseBody(response, r.client.config.Logger)

	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected api response status code: %d", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read subject template upsert response: %w", err)
	}

	var decoded upsertSubjectTemplatesResponse
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &decoded); err != nil {
			return nil, fmt.Errorf("decode subject template upsert response: %w", err)
		}
	}

	return &decoded.Data, nil
}
