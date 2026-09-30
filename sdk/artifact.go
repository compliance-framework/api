package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"

	"github.com/compliance-framework/api/internal/artifact"
)

const (
	// ArtifactMediaTypePolicyBundle uploads a policy bundle as a tar or gzipped tar.
	ArtifactMediaTypePolicyBundle = artifact.MediaTypePolicyBundle
	// ArtifactMediaTypeJSON uploads any JSON value.
	ArtifactMediaTypeJSON = artifact.MediaTypeJSON
)

// ArtifactInfo describes a stored artifact. The API computes Digest from the content's
// canonical form.
type ArtifactInfo = artifact.Info

// ArtifactStatusError is an unexpected HTTP status from an artifact route. A 404 or 405 on
// Upload means the API predates artifact storage.
type ArtifactStatusError struct {
	StatusCode int
	Body       string
}

func (e *ArtifactStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("unexpected api response status code: %d", e.StatusCode)
	}
	return fmt.Sprintf("unexpected api response status code: %d: %s", e.StatusCode, e.Body)
}

func artifactStatusError(response *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
	return &ArtifactStatusError{StatusCode: response.StatusCode, Body: string(body)}
}

type artifactClient struct {
	client *Client
}

// Upload stores content as an artifact. The API converts it to canonical form, so the same
// content always returns the same digest however it was encoded. It needs agent
// authentication.
func (a *artifactClient) Upload(ctx context.Context, mediaType string, content []byte) (*ArtifactInfo, error) {
	headers := http.Header{}
	headers.Set("Content-Type", mediaType)

	response, err := a.client.doRequestWithHeaders(ctx, http.MethodPost, "/api/agent/artifacts", content, headers)
	if err != nil {
		return nil, err
	}
	defer closeResponseBody(response, a.client.config.Logger)

	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return nil, artifactStatusError(response)
	}

	var info ArtifactInfo
	if err := json.NewDecoder(response.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode artifact response: %w", err)
	}
	return &info, nil
}

// Get downloads the artifact with digest and returns its canonical content and media type,
// after checking the content matches the digest.
func (a *artifactClient) Get(ctx context.Context, digest string) ([]byte, string, error) {
	response, err := a.client.doRequest(ctx, http.MethodGet, "/api/artifacts/"+url.PathEscape(digest), nil)
	if err != nil {
		return nil, "", err
	}
	defer closeResponseBody(response, a.client.config.Logger)

	if response.StatusCode != http.StatusOK {
		return nil, "", artifactStatusError(response)
	}

	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, "", err
	}
	if got := artifact.Digest(content); got != digest {
		return nil, "", fmt.Errorf("artifact content digest %s does not match %s", got, digest)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil {
		return nil, "", fmt.Errorf("artifact media type: %w", err)
	}
	return content, mediaType, nil
}
