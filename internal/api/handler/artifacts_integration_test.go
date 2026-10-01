//go:build integration

package handler

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/artifact"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/pkg/policyeval"
	"github.com/compliance-framework/api/sdk"
	"github.com/compliance-framework/api/sdk/types"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

const artifactTestBundle = "../../artifact/testdata/bundle"

func TestArtifactApi(t *testing.T) {
	suite.Run(t, new(ArtifactApiIntegrationSuite))
}

type ArtifactApiIntegrationSuite struct {
	tests.IntegrationTestSuite

	server     *api.Server
	agentToken string
	agentID    string
	userToken  string
}

func (suite *ArtifactApiIntegrationSuite) SetupTest() {
	suite.Require().NoError(suite.Migrator.Refresh())
	// Public agent endpoints on: artifact routes must still refuse anonymous callers.
	suite.Config.StrictDisablePublicAgentEndpoints = false

	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	RegisterHandlers(suite.server, logger.Sugar(), suite.DB, suite.Config, &APIServices{})

	agent, err := suite.CreateAgent("artifact-agent")
	suite.Require().NoError(err)
	key, _, err := suite.CreateAgentKey(agent, "artifact-key")
	suite.Require().NoError(err)
	token, err := suite.GetAgentToken(agent, key)
	suite.Require().NoError(err)
	suite.agentToken = *token
	suite.agentID = agent.ID.String()

	userToken, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	suite.userToken = *userToken
}

func (suite *ArtifactApiIntegrationSuite) do(method, path, token, contentType string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set(echo.HeaderContentType, contentType)
	}
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
	}
	rec := httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)
	return rec
}

func (suite *ArtifactApiIntegrationSuite) upload(token, mediaType string, content []byte) *httptest.ResponseRecorder {
	return suite.do(http.MethodPost, "/api/agent/artifacts", token, mediaType, content)
}

// uploadDigest uploads as the agent and returns the digest the API assigned.
func (suite *ArtifactApiIntegrationSuite) uploadDigest(mediaType string, content []byte) string {
	rec := suite.upload(suite.agentToken, mediaType, content)
	suite.Require().Contains([]int{http.StatusCreated, http.StatusOK}, rec.Code, rec.Body.String())
	var info artifact.Info
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &info))
	return info.Digest
}

// tarBundle archives a bundle directory as an agent might, optionally gzipped.
func (suite *ArtifactApiIntegrationSuite) tarBundle(dir string, gzipped bool) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	suite.Require().NoError(filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: filepath.ToSlash(rel), Mode: 0o600, Size: int64(len(content)), ModTime: info.ModTime()}); err != nil {
			return err
		}
		_, err = tw.Write(content)
		return err
	}))
	suite.Require().NoError(tw.Close())
	if !gzipped {
		return buf.Bytes()
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, err := zw.Write(buf.Bytes())
	suite.Require().NoError(err)
	suite.Require().NoError(zw.Close())
	return gz.Bytes()
}

func (suite *ArtifactApiIntegrationSuite) artifactCount() int64 {
	var count int64
	suite.Require().NoError(suite.DB.Model(&relational.Artifact{}).Count(&count).Error)
	return count
}

func (suite *ArtifactApiIntegrationSuite) TestUploadCanonicalises() {
	first := suite.upload(suite.agentToken, artifact.MediaTypeJSON, []byte(`{ "b": 1, "a": 2 }`))
	suite.Require().Equal(http.StatusCreated, first.Code, first.Body.String())
	var info artifact.Info
	suite.Require().NoError(json.Unmarshal(first.Body.Bytes(), &info))
	canonical := []byte(`{"a":2,"b":1}`)
	suite.Equal(artifact.Info{Digest: artifact.Digest(canonical), MediaType: artifact.MediaTypeJSON, SizeBytes: int64(len(canonical))}, info)

	second := suite.upload(suite.agentToken, artifact.MediaTypeJSON, []byte(`{"b":1,"a":2}`))
	suite.Require().Equal(http.StatusOK, second.Code, "the same value encoded differently is already stored")

	var rows []relational.Artifact
	suite.Require().NoError(suite.DB.Find(&rows).Error)
	suite.Require().Len(rows, 1)
	suite.Equal(canonical, rows[0].Content)
	suite.Require().NotNil(rows[0].CreatedByAgentID)
	suite.Equal(suite.agentID, rows[0].CreatedByAgentID.String())
}

func (suite *ArtifactApiIntegrationSuite) TestBundleArchiveShapesShareADigest() {
	plain := suite.uploadDigest(artifact.MediaTypePolicyBundle, suite.tarBundle(artifactTestBundle, false))
	gzipped := suite.uploadDigest(artifact.MediaTypePolicyBundle, suite.tarBundle(artifactTestBundle, true))
	suite.Equal(plain, gzipped)
	suite.EqualValues(1, suite.artifactCount())
}

func (suite *ArtifactApiIntegrationSuite) TestUploadTakesAgentIngestAuth() {
	// Public agent endpoints allowed (SetupTest): agents without credentials may upload.
	suite.Equal(http.StatusCreated, suite.upload("", artifact.MediaTypeJSON, []byte(`{"anonymous":true}`)).Code, "anonymous")
	suite.Equal(http.StatusUnauthorized, suite.upload(suite.userToken, artifact.MediaTypeJSON, []byte(`{}`)).Code, "user token")

	// Public agent endpoints disabled: only agent tokens.
	suite.Config.StrictDisablePublicAgentEndpoints = true
	defer func() { suite.Config.StrictDisablePublicAgentEndpoints = false }()
	logger, _ := zap.NewDevelopment()
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, api.NewMetricsHandler(context.Background(), logger.Sugar()))
	RegisterHandlers(suite.server, logger.Sugar(), suite.DB, suite.Config, &APIServices{})
	suite.Equal(http.StatusUnauthorized, suite.upload("", artifact.MediaTypeJSON, []byte(`{"strict":true}`)).Code, "anonymous, strict")
	suite.Equal(http.StatusCreated, suite.upload(suite.agentToken, artifact.MediaTypeJSON, []byte(`{"strict":true}`)).Code, "agent token, strict")

	var rows []relational.Artifact
	suite.Require().NoError(suite.DB.Order("created_at").Find(&rows).Error)
	suite.Require().Len(rows, 2)
	suite.Nil(rows[0].CreatedByAgentID, "an anonymous upload records no agent")
	suite.Require().NotNil(rows[1].CreatedByAgentID)
}

// TestAnonymousAgentFlow is an agent without credentials, as in local-dev: it uploads its
// artifacts and creates evidence referring to them, all without a token.
func (suite *ArtifactApiIntegrationSuite) TestAnonymousAgentFlow() {
	bundle := suite.upload("", artifact.MediaTypePolicyBundle, suite.tarBundle(artifactTestBundle, true))
	suite.Require().Equal(http.StatusCreated, bundle.Code, bundle.Body.String())
	input := suite.upload("", artifact.MediaTypeJSON, []byte(`{"open_ports":[22]}`))
	suite.Require().Equal(http.StatusCreated, input.Code, input.Body.String())

	var bundleInfo, inputInfo artifact.Info
	suite.Require().NoError(json.Unmarshal(bundle.Body.Bytes(), &bundleInfo))
	suite.Require().NoError(json.Unmarshal(input.Body.Bytes(), &inputInfo))

	rec := suite.createEvidence("", nil, &EvidencePolicyArtifacts{BundleDigest: bundleInfo.Digest, InputDigest: inputInfo.Digest})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())
	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	suite.Equal(inputInfo.Digest, propMap(evidence)[artifact.PropPolicyInputDigest])
}

func (suite *ArtifactApiIntegrationSuite) TestUploadRejectsInvalidContent() {
	for name, tc := range map[string]struct {
		mediaType string
		content   string
	}{
		"invalid JSON":       {artifact.MediaTypeJSON, `{"a":`},
		"unsupported type":   {"text/plain", `hello`},
		"bundle not a tar":   {artifact.MediaTypePolicyBundle, "not a tar"},
		"missing media type": {"", `{}`},
	} {
		rec := suite.upload(suite.agentToken, tc.mediaType, []byte(tc.content))
		suite.Equal(http.StatusBadRequest, rec.Code, "%s: %s", name, rec.Body.String())
	}
	suite.Zero(suite.artifactCount())
}

func (suite *ArtifactApiIntegrationSuite) TestUploadRejectsOversizedContent() {
	previous := suite.Config.Artifact
	suite.Config.Artifact = &config.ArtifactConfig{MaxBytes: 64}
	defer func() { suite.Config.Artifact = previous }()
	suite.SetupTest()

	body := []byte(`{"padding":"` + strings.Repeat("x", 128) + `"}`)
	suite.Equal(http.StatusRequestEntityTooLarge, suite.upload(suite.agentToken, artifact.MediaTypeJSON, body).Code)
}

func (suite *ArtifactApiIntegrationSuite) TestGetNeedsAnyToken() {
	digest := suite.uploadDigest(artifact.MediaTypeJSON, []byte(`{"a":1}`))
	path := "/api/artifacts/" + digest

	for name, token := range map[string]string{"user": suite.userToken, "agent": suite.agentToken} {
		rec := suite.do(http.MethodGet, path, token, "", nil)
		suite.Require().Equal(http.StatusOK, rec.Code, name)
		suite.Equal(`{"a":1}`, rec.Body.String(), name)
		suite.Equal(artifact.MediaTypeJSON, rec.Header().Get(echo.HeaderContentType), name)
		suite.Equal(`"`+digest+`"`, rec.Header().Get("ETag"), name)
	}

	suite.Equal(http.StatusUnauthorized, suite.do(http.MethodGet, path, "", "", nil).Code, "anonymous")
	suite.Equal(http.StatusNotFound, suite.do(http.MethodGet, "/api/artifacts/"+artifact.Digest([]byte("missing")), suite.userToken, "", nil).Code)
	suite.Equal(http.StatusBadRequest, suite.do(http.MethodGet, "/api/artifacts/not-a-digest", suite.userToken, "", nil).Code)
}

type storedArtifacts struct {
	bundle, input, data string
}

func (suite *ArtifactApiIntegrationSuite) storeEvaluation() storedArtifacts {
	return storedArtifacts{
		bundle: suite.uploadDigest(artifact.MediaTypePolicyBundle, suite.tarBundle(artifactTestBundle, true)),
		input:  suite.uploadDigest(artifact.MediaTypeJSON, []byte(`{"open_ports": [22, 8080]}`)),
		data:   suite.uploadDigest(artifact.MediaTypeJSON, []byte(`{"extra": true}`)),
	}
}

func (suite *ArtifactApiIntegrationSuite) createEvidence(token string, props map[string]string, refs *EvidencePolicyArtifacts) *httptest.ResponseRecorder {
	request := map[string]any{
		"uuid":   uuid.New(),
		"title":  "Only approved ports are open",
		"start":  time.Now().Add(-time.Hour),
		"end":    time.Now().Add(-time.Minute),
		"status": map[string]any{"state": "not-satisfied", "reason": "fail"},
	}
	var list []map[string]string
	for name, value := range props {
		list = append(list, map[string]string{"name": name, "value": value})
	}
	if list != nil {
		request["props"] = list
	}
	if refs != nil {
		request["policy-artifacts"] = refs
	}
	body, err := json.Marshal(request)
	suite.Require().NoError(err)
	return suite.do(http.MethodPost, "/api/evidence", token, echo.MIMEApplicationJSON, body)
}

func propMap(evidence relational.Evidence) map[string]string {
	out := map[string]string{}
	for _, prop := range evidence.Props {
		out[prop.Name] = prop.Value
	}
	return out
}

func (suite *ArtifactApiIntegrationSuite) verify(id string) evidencesvc.VerificationResult {
	rec := suite.do(http.MethodPost, "/api/evidence/"+id+"/verify", suite.userToken, "", nil)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var resp GenericDataResponse[evidencesvc.VerificationResult]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

func (suite *ArtifactApiIntegrationSuite) TestEvidenceRecordsSignedArtifactDigests() {
	stored := suite.storeEvaluation()

	rec := suite.createEvidence(suite.agentToken, map[string]string{"_violation_id": "unapproved-port"}, &EvidencePolicyArtifacts{
		BundleDigest: stored.bundle, InputDigest: stored.input, PolicyDataDigest: stored.data,
	})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	suite.Equal(map[string]string{
		"_violation_id":                 "unapproved-port",
		artifact.PropPolicyBundleDigest: stored.bundle,
		artifact.PropPolicyInputDigest:  stored.input,
		artifact.PropPolicyDataDigest:   stored.data,
	}, propMap(evidence))

	suite.Require().True(suite.verify(evidence.ID.String()).IsValid, "the digests must be part of the signed content")

	// Pointing the evidence at other input, even directly in the database, breaks verification.
	other := suite.uploadDigest(artifact.MediaTypeJSON, []byte(`{"open_ports": [22]}`))
	for i := range evidence.Props {
		if evidence.Props[i].Name == artifact.PropPolicyInputDigest {
			evidence.Props[i].Value = other
		}
	}
	suite.Require().NoError(suite.DB.Model(&evidence).Update("props", evidence.Props).Error)
	suite.False(suite.verify(evidence.ID.String()).IsValid)
}

func (suite *ArtifactApiIntegrationSuite) TestEvidenceWithoutPolicyDataOmitsItsDigest() {
	stored := suite.storeEvaluation()
	rec := suite.createEvidence(suite.agentToken, nil, &EvidencePolicyArtifacts{BundleDigest: stored.bundle, InputDigest: stored.input})
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	suite.NotContains(propMap(evidence), artifact.PropPolicyDataDigest)
	suite.Contains(propMap(evidence), artifact.PropPolicyBundleDigest)
}

func (suite *ArtifactApiIntegrationSuite) TestEvidenceRejectsBadArtifactReferences() {
	stored := suite.storeEvaluation()
	missing := artifact.Digest([]byte("never uploaded"))

	cases := map[string]struct {
		props map[string]string
		refs  *EvidencePolicyArtifacts
	}{
		"unknown digest":          {nil, &EvidencePolicyArtifacts{BundleDigest: stored.bundle, InputDigest: missing}},
		"malformed digest":        {nil, &EvidencePolicyArtifacts{BundleDigest: stored.bundle, InputDigest: "sha256:nope"}},
		"input is a bundle":       {nil, &EvidencePolicyArtifacts{BundleDigest: stored.bundle, InputDigest: stored.bundle}},
		"bundle is JSON":          {nil, &EvidencePolicyArtifacts{BundleDigest: stored.input, InputDigest: stored.input}},
		"bundle missing":          {nil, &EvidencePolicyArtifacts{InputDigest: stored.input}},
		"input missing":           {nil, &EvidencePolicyArtifacts{BundleDigest: stored.bundle}},
		"client-set digest prop":  {map[string]string{artifact.PropPolicyInputDigest: stored.input}, nil},
		"client-set prop and ref": {map[string]string{artifact.PropPolicyBundleDigest: stored.bundle}, &EvidencePolicyArtifacts{BundleDigest: stored.bundle, InputDigest: stored.input}},
	}
	for name, tc := range cases {
		rec := suite.createEvidence(suite.agentToken, tc.props, tc.refs)
		suite.Equal(http.StatusBadRequest, rec.Code, "%s: %s", name, rec.Body.String())
	}

	var count int64
	suite.Require().NoError(suite.DB.Model(&relational.Evidence{}).Count(&count).Error)
	suite.Zero(count)
}

// TestPlaybackFromEvidence follows the digests on stored evidence back to the artifacts,
// and replays the evaluation through the playback endpoint.
func (suite *ArtifactApiIntegrationSuite) TestPlaybackFromEvidence() {
	stored := suite.storeEvaluation()
	suite.Require().Equal(http.StatusCreated, suite.createEvidence(suite.agentToken, nil, &EvidencePolicyArtifacts{BundleDigest: stored.bundle, InputDigest: stored.input}).Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	props := propMap(evidence)

	bundleRec := suite.do(http.MethodGet, "/api/artifacts/"+props[artifact.PropPolicyBundleDigest], suite.userToken, "", nil)
	suite.Require().Equal(http.StatusOK, bundleRec.Code)
	inputRec := suite.do(http.MethodGet, "/api/artifacts/"+props[artifact.PropPolicyInputDigest], suite.userToken, "", nil)
	suite.Require().Equal(http.StatusOK, inputRec.Code)

	bundle, err := artifact.ReadBundleTar(bundleRec.Body.Bytes())
	suite.Require().NoError(err)
	modules := map[string]string{}
	for name, source := range bundle.Modules {
		if name != policyeval.PolicyModuleName {
			modules[name] = source
		}
	}
	body, err := json.Marshal(map[string]any{
		"policy":  bundle.Modules[policyeval.PolicyModuleName],
		"modules": modules,
		"input":   json.RawMessage(inputRec.Body.Bytes()),
		"data":    bundle.Data,
	})
	suite.Require().NoError(err)

	rec := suite.do(http.MethodPost, "/api/playback/evaluate", suite.userToken, echo.MIMEApplicationJSON, body)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var resp policyeval.EvaluateResponse
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	suite.Require().Len(resp.Results, 1)
	suite.Equal(policyeval.StatusNotSatisfied, resp.Results[0].Status)
	suite.Require().Len(resp.Results[0].Violations, 1)
	suite.Equal("unapproved-port", *resp.Results[0].Violations[0].ID)
}

// bearerTransport adds a fixed bearer token, standing in for the SDK's agent login.
type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(echo.HeaderAuthorization, "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

// TestSDKRoundTrip uses the SDK the agent uses, over HTTP, so the SDK's request shapes and
// the handlers are checked against each other.
func (suite *ArtifactApiIntegrationSuite) TestSDKRoundTrip() {
	server := httptest.NewServer(suite.server.E())
	defer server.Close()
	client := sdk.NewClient(&http.Client{Transport: bearerTransport{token: suite.agentToken}}, &sdk.Config{BaseURL: server.URL})
	ctx := context.Background()

	bundle, err := client.Artifact.Upload(ctx, sdk.ArtifactMediaTypePolicyBundle, suite.tarBundle(artifactTestBundle, false))
	suite.Require().NoError(err)
	input, err := client.Artifact.Upload(ctx, sdk.ArtifactMediaTypeJSON, []byte(`{"open_ports":[22,8080]}`))
	suite.Require().NoError(err)

	content, mediaType, err := client.Artifact.Get(ctx, input.Digest)
	suite.Require().NoError(err)
	suite.Equal(`{"open_ports":[22,8080]}`, string(content))
	suite.Equal(sdk.ArtifactMediaTypeJSON, mediaType)

	suite.Require().NoError(client.Evidence.Create(ctx, types.Evidence{
		UUID:  uuid.New(),
		Title: "Only approved ports are open",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: types.ObjectiveStatus{
			State:  "not-satisfied",
			Reason: "fail",
		},
		PolicyArtifacts: &types.PolicyArtifacts{BundleDigest: bundle.Digest, InputDigest: input.Digest},
	}))

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	props := propMap(evidence)
	suite.Equal(bundle.Digest, props[artifact.PropPolicyBundleDigest])
	suite.Equal(input.Digest, props[artifact.PropPolicyInputDigest])

	// An old API has no artifact route: the SDK reports it as a status error.
	_, err = sdk.NewClient(&http.Client{Transport: bearerTransport{token: suite.agentToken}}, &sdk.Config{BaseURL: server.URL + "/nowhere"}).
		Artifact.Upload(ctx, sdk.ArtifactMediaTypeJSON, []byte(`{}`))
	var statusErr *sdk.ArtifactStatusError
	suite.Require().ErrorAs(err, &statusErr)
	suite.Equal(http.StatusNotFound, statusErr.StatusCode)
}

// testBundleFiles reads the test bundle from disk, keyed by slash-separated path.
func (suite *ArtifactApiIntegrationSuite) testBundleFiles() map[string][]byte {
	files := map[string][]byte{}
	suite.Require().NoError(filepath.Walk(artifactTestBundle, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(artifactTestBundle, p)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(p)
		files[filepath.ToSlash(rel)] = content
		return err
	}))
	return files
}

func (suite *ArtifactApiIntegrationSuite) getWithHeaders(path, token string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	suite.server.E().ServeHTTP(rec, req)
	return rec
}

func (suite *ArtifactApiIntegrationSuite) TestListBundleFiles() {
	digest := suite.uploadDigest(artifact.MediaTypePolicyBundle, suite.tarBundle(artifactTestBundle, true))
	path := "/api/artifacts/" + digest + "/files"
	onDisk := suite.testBundleFiles()

	for name, token := range map[string]string{"user": suite.userToken, "agent": suite.agentToken} {
		rec := suite.do(http.MethodGet, path, token, "", nil)
		suite.Require().Equal(http.StatusOK, rec.Code, "%s: %s", name, rec.Body.String())
		suite.Equal(echo.MIMEApplicationJSON, rec.Header().Get(echo.HeaderContentType), name)

		var list ArtifactFileList
		suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &list))
		suite.Equal(digest, list.Digest)
		suite.Equal(agentconfig.BundleTreeDigest(onDisk), list.TreeDigest, "the tree digest agent config reports use")

		want := []ArtifactFileInfo{
			{Path: "config/data.json", Size: int64(len(onDisk["config/data.json"]))},
			{Path: "lib/helpers.rego", Size: int64(len(onDisk["lib/helpers.rego"])), Package: "ccf_libs.helpers"},
			{Path: "policy.rego", Size: int64(len(onDisk["policy.rego"])), Package: "compliance_framework.ports"},
		}
		for i := range want {
			sum := sha256.Sum256(onDisk[want[i].Path])
			want[i].SHA256 = hex.EncodeToString(sum[:])
		}
		suite.Equal(want, list.Files, name)
		suite.NotContains(rec.Body.String(), `"package":""`, "package is omitted for non-Rego files")
	}

	suite.Equal(http.StatusUnauthorized, suite.do(http.MethodGet, path, "", "", nil).Code, "anonymous")
}

func (suite *ArtifactApiIntegrationSuite) TestBundleFileRoutesCaching() {
	digest := suite.uploadDigest(artifact.MediaTypePolicyBundle, suite.tarBundle(artifactTestBundle, false))

	for _, path := range []string{"/api/artifacts/" + digest + "/files", "/api/artifacts/" + digest + "/files/policy.rego"} {
		first := suite.do(http.MethodGet, path, suite.userToken, "", nil)
		suite.Require().Equal(http.StatusOK, first.Code, first.Body.String())
		etag := first.Header().Get("ETag")
		suite.Require().NotEmpty(etag, path)
		suite.Equal(`"`+artifact.Digest(first.Body.Bytes())+`"`, etag, "the ETag is the digest of the body")
		suite.Equal("private, max-age=31536000, immutable", first.Header().Get("Cache-Control"))

		again := suite.do(http.MethodGet, path, suite.userToken, "", nil)
		suite.Equal(etag, again.Header().Get("ETag"), "stable across requests")

		notModified := suite.getWithHeaders(path, suite.userToken, map[string]string{"If-None-Match": `"other", ` + etag})
		suite.Equal(http.StatusNotModified, notModified.Code, path)
		suite.Empty(notModified.Body.String())
		suite.Equal(etag, notModified.Header().Get("ETag"))

		weak := suite.getWithHeaders(path, suite.userToken, map[string]string{"If-None-Match": "W/" + etag})
		suite.Equal(http.StatusNotModified, weak.Code, "weak comparison")

		changed := suite.getWithHeaders(path, suite.userToken, map[string]string{"If-None-Match": `"sha256:stale"`})
		suite.Equal(http.StatusOK, changed.Code)
	}

	// The listing and a file of the same artifact are different representations.
	list := suite.do(http.MethodGet, "/api/artifacts/"+digest+"/files", suite.userToken, "", nil)
	file := suite.do(http.MethodGet, "/api/artifacts/"+digest+"/files/policy.rego", suite.userToken, "", nil)
	suite.NotEqual(list.Header().Get("ETag"), file.Header().Get("ETag"))
}

func (suite *ArtifactApiIntegrationSuite) TestGetBundleFile() {
	digest := suite.uploadDigest(artifact.MediaTypePolicyBundle, suite.tarBundle(artifactTestBundle, true))
	onDisk := suite.testBundleFiles()

	for _, tc := range []struct {
		path, request, pkg string
	}{
		{"policy.rego", "policy.rego", "compliance_framework.ports"},
		{"lib/helpers.rego", "lib/helpers.rego", "ccf_libs.helpers"},
		{"lib/helpers.rego", "lib%2Fhelpers.rego", "ccf_libs.helpers"}, // escaped separator
		{"config/data.json", "config/data.json", ""},
	} {
		rec := suite.do(http.MethodGet, "/api/artifacts/"+digest+"/files/"+tc.request, suite.agentToken, "", nil)
		suite.Require().Equal(http.StatusOK, rec.Code, "%s: %s", tc.request, rec.Body.String())
		var file ArtifactFileSource
		suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &file))
		sum := sha256.Sum256(onDisk[tc.path])
		suite.Equal(ArtifactFileSource{
			Path:    tc.path,
			Package: tc.pkg,
			SHA256:  hex.EncodeToString(sum[:]),
			Source:  string(onDisk[tc.path]),
		}, file, tc.request)
	}

	base := "/api/artifacts/" + digest + "/files/"
	suite.Equal(http.StatusNotFound, suite.do(http.MethodGet, base+"missing.rego", suite.userToken, "", nil).Code, "unknown path")
	suite.Equal(http.StatusNotFound, suite.do(http.MethodGet, base+"lib", suite.userToken, "", nil).Code, "a directory is not a file")
	suite.Equal(http.StatusNotFound, suite.do(http.MethodGet, base+"./policy.rego", suite.userToken, "", nil).Code, "paths are matched exactly")
	suite.Equal(http.StatusUnauthorized, suite.do(http.MethodGet, base+"policy.rego", "", "", nil).Code, "anonymous")
}

func (suite *ArtifactApiIntegrationSuite) TestBundleFileRoutesRejectOtherArtifacts() {
	jsonDigest := suite.uploadDigest(artifact.MediaTypeJSON, []byte(`{"a":1}`))
	missing := artifact.Digest([]byte("never uploaded"))

	for _, suffix := range []string{"/files", "/files/policy.rego"} {
		rec := suite.do(http.MethodGet, "/api/artifacts/"+jsonDigest+suffix, suite.userToken, "", nil)
		suite.Equal(http.StatusUnsupportedMediaType, rec.Code, "%s: %s", suffix, rec.Body.String())
		suite.Equal(http.StatusNotFound, suite.do(http.MethodGet, "/api/artifacts/"+missing+suffix, suite.userToken, "", nil).Code, suffix)
		suite.Equal(http.StatusBadRequest, suite.do(http.MethodGet, "/api/artifacts/not-a-digest"+suffix, suite.userToken, "", nil).Code, suffix)
	}
}

func (suite *ArtifactApiIntegrationSuite) TestGetBundleFileLimits() {
	big := strings.Repeat("# padding\n", MaxArtifactFileSourceBytes/10+1)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range map[string]string{
		"policy.rego": "package compliance_framework.big\n\nimport rego.v1\n\ntitle := \"t\"\n" + big,
		"exact.rego":  "package compliance_framework.exact\n" + strings.Repeat("#", MaxArtifactFileSourceBytes-len("package compliance_framework.exact\n")),
		"binary.bin":  "\xff\xfe\x00binary",
	} {
		suite.Require().NoError(tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(content))}))
		_, err := tw.Write([]byte(content))
		suite.Require().NoError(err)
	}
	suite.Require().NoError(tw.Close())
	digest := suite.uploadDigest(artifact.MediaTypePolicyBundle, buf.Bytes())
	base := "/api/artifacts/" + digest + "/files/"

	rec := suite.do(http.MethodGet, base+"policy.rego", suite.userToken, "", nil)
	suite.Equal(http.StatusUnprocessableEntity, rec.Code, "over 1 MiB")
	suite.Contains(rec.Body.String(), "over the 1048576 byte limit")
	suite.Equal(http.StatusOK, suite.do(http.MethodGet, base+"exact.rego", suite.userToken, "", nil).Code, "exactly 1 MiB")
	suite.Equal(http.StatusUnprocessableEntity, suite.do(http.MethodGet, base+"binary.bin", suite.userToken, "", nil).Code, "not UTF-8")

	// The listing still covers every file.
	rec = suite.do(http.MethodGet, "/api/artifacts/"+digest+"/files", suite.userToken, "", nil)
	suite.Require().Equal(http.StatusOK, rec.Code)
	var list ArtifactFileList
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &list))
	suite.Len(list.Files, 3)
}
