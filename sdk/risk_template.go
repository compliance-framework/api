package sdk

import (
	"context"
	"fmt"
	"net/http"

	"github.com/compliance-framework/api/sdk/types"
)

type riskTemplateClient struct {
	client *Client
}

type upsertRiskTemplatesRequest struct {
	PluginID      string               `json:"plugin-id"`
	PolicyPackage string               `json:"policy-package"`
	Templates     []types.RiskTemplate `json:"templates"`
}

func (r *riskTemplateClient) Upsert(ctx context.Context, pluginID string, policyPackage string, riskTemplates ...types.RiskTemplate) error {
	if len(riskTemplates) == 0 {
		riskTemplates = []types.RiskTemplate{}
	}

	reqData := &upsertRiskTemplatesRequest{
		PluginID:      pluginID,
		PolicyPackage: policyPackage,
		Templates:     riskTemplates,
	}
	response, err := r.client.doJSONRequest(ctx, http.MethodPost, "/api/agent/risk-templates/batch", reqData)
	if err != nil {
		return err
	}
	closeResponseBody(response, r.client.config.Logger)

	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected api response status code: %d", response.StatusCode)
	}

	return nil
}
