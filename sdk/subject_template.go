package sdk

import (
	"context"
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
	closeResponseBody(response, r.client.config.Logger)

	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected api response status code: %d", response.StatusCode)
	}

	return nil
}
