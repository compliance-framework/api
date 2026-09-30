package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/artifact"
	"github.com/compliance-framework/api/sdk/types"
	"github.com/google/uuid"
)

func artifactTestClient(t *testing.T, handler func(r *http.Request) *http.Response) *Client {
	t.Helper()
	return NewClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return handler(r), nil
	})}, &Config{BaseURL: "http://example.test"})
}

func response(status int, contentType, body string) *http.Response {
	header := make(http.Header)
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: header}
}

func TestArtifactUploadSendsMediaType(t *testing.T) {
	content := []byte("tar bytes")
	client := artifactTestClient(t, func(r *http.Request) *http.Response {
		if r.Method != http.MethodPost || r.URL.Path != "/api/agent/artifacts" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != ArtifactMediaTypePolicyBundle {
			t.Fatalf("Content-Type = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != string(content) {
			t.Fatalf("body = %q", body)
		}
		return response(http.StatusCreated, "application/json", `{"digest":"sha256:abc","mediaType":"`+ArtifactMediaTypePolicyBundle+`","sizeBytes":2048}`)
	})

	info, err := client.Artifact.Upload(context.Background(), ArtifactMediaTypePolicyBundle, content)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if info.Digest != "sha256:abc" || info.SizeBytes != 2048 {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestArtifactUploadReportsStatus(t *testing.T) {
	client := artifactTestClient(t, func(*http.Request) *http.Response {
		return response(http.StatusNotFound, "", "")
	})
	_, err := client.Artifact.Upload(context.Background(), ArtifactMediaTypeJSON, []byte(`{}`))
	var statusErr *ArtifactStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusNotFound {
		t.Fatalf("expected *ArtifactStatusError with 404, got %T %v", err, err)
	}
}

func TestArtifactGetVerifiesDigest(t *testing.T) {
	content := []byte(`{"a":1}`)
	digest := artifact.Digest(content)

	client := artifactTestClient(t, func(r *http.Request) *http.Response {
		if r.Method != http.MethodGet || r.URL.Path != "/api/artifacts/"+digest {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		return response(http.StatusOK, "application/json; charset=utf-8", string(content))
	})
	got, mediaType, err := client.Artifact.Get(context.Background(), digest)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != string(content) || mediaType != ArtifactMediaTypeJSON {
		t.Fatalf("got %q %q", got, mediaType)
	}

	tampered := artifactTestClient(t, func(*http.Request) *http.Response {
		return response(http.StatusOK, "application/json", `{"a":2}`)
	})
	if _, _, err := tampered.Artifact.Get(context.Background(), digest); err == nil {
		t.Fatal("expected a digest mismatch error")
	}
}

func TestEvidenceCreateSendsPolicyArtifacts(t *testing.T) {
	var body map[string]any
	client := artifactTestClient(t, func(r *http.Request) *http.Response {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		return response(http.StatusCreated, "", "")
	})

	err := client.Evidence.Create(context.Background(), types.Evidence{
		UUID:  uuid.New(),
		Title: "e",
		Start: time.Now(),
		End:   time.Now(),
		PolicyArtifacts: &types.PolicyArtifacts{
			BundleDigest: "sha256:b",
			InputDigest:  "sha256:i",
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	refs, _ := body["policy-artifacts"].(map[string]any)
	if refs["bundle-digest"] != "sha256:b" || refs["input-digest"] != "sha256:i" {
		t.Fatalf("policy-artifacts = %v", body["policy-artifacts"])
	}
	if _, ok := refs["policy-data-digest"]; ok {
		t.Fatal("an empty policy-data-digest must be omitted")
	}
}
