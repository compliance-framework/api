//go:build integration

package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/artifact"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/pkg/policyeval"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

const playbackTestPackage = "compliance_framework.ports"

// createPlaybackEvidence creates evidence as an agent would after evaluating the test
// bundle: labelled with its policy package, with a recorded status and violation ids.
func (suite *ArtifactApiIntegrationSuite) createPlaybackEvidence(state string, violationIDs []string, refs *EvidencePolicyArtifacts) string {
	props := []map[string]string{}
	for _, id := range violationIDs {
		props = append(props, map[string]string{"name": "_violation_id", "value": id})
	}
	stream := uuid.New()
	request := map[string]any{
		"uuid":   stream,
		"title":  "Only approved ports are open",
		"start":  time.Now().Add(-time.Hour),
		"end":    time.Now().Add(-time.Minute),
		"labels": map[string]string{"_policy": playbackTestPackage},
		"props":  props,
		"status": map[string]any{"state": state, "reason": state},
	}
	if refs != nil {
		request["policy-artifacts"] = refs
	}
	body, err := json.Marshal(request)
	suite.Require().NoError(err)
	rec := suite.do(http.MethodPost, "/api/evidence", suite.agentToken, echo.MIMEApplicationJSON, body)
	suite.Require().Equal(http.StatusCreated, rec.Code, rec.Body.String())

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.Where("uuid = ?", stream).First(&evidence).Error)
	return evidence.ID.String()
}

func (suite *ArtifactApiIntegrationSuite) playback(id, token string) (int, EvidencePlaybackResponse) {
	rec := suite.do(http.MethodGet, "/api/evidence/"+id+"/playback", token, "", nil)
	var resp GenericDataResponse[EvidencePlaybackResponse]
	if rec.Code == http.StatusOK {
		suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp), rec.Body.String())
	}
	return rec.Code, resp.Data
}

func (suite *ArtifactApiIntegrationSuite) refs(stored storedArtifacts) *EvidencePolicyArtifacts {
	return &EvidencePolicyArtifacts{BundleDigest: stored.bundle, InputDigest: stored.input, PolicyDataDigest: stored.data}
}

func (suite *ArtifactApiIntegrationSuite) TestPlaybackMatchesRecordedEvidence() {
	stored := suite.storeEvaluation()
	id := suite.createPlaybackEvidence("not-satisfied", []string{"unapproved-port"}, suite.refs(stored))

	code, resp := suite.playback(id, suite.userToken)
	suite.Require().Equal(http.StatusOK, code)
	suite.Require().True(resp.Available, resp.Reason)
	suite.Equal(playbackTestPackage, resp.Package)
	suite.Require().NotNil(resp.EvaluatedAt)

	suite.Equal(stored.bundle, resp.Artifacts.Bundle.Digest)
	suite.Equal(stored.input, resp.Artifacts.Input.Digest)
	suite.Require().NotNil(resp.Artifacts.PolicyData)
	suite.Equal(stored.data, resp.Artifacts.PolicyData.Digest)

	paths := map[string]bool{}
	for _, file := range resp.PolicyFiles {
		paths[file.Path] = file.ContainsPackage
	}
	suite.Equal(map[string]bool{"policy.rego": true, "lib/helpers.rego": false}, paths)

	suite.Contains(resp.InputJSON, "8080")
	suite.False(resp.InputTruncated)
	suite.Require().NotNil(resp.PolicyDataJSON)
	suite.Contains(*resp.PolicyDataJSON, `"extra": true`)
	suite.Require().NotNil(resp.BundleDataJSON)
	suite.Contains(*resp.BundleDataJSON, "approved_ports")

	suite.Require().NotNil(resp.Replay)
	suite.Equal("not-satisfied", resp.Replay.Status)
	suite.Require().Len(resp.Replay.Violations, 1)
	suite.Equal("unapproved-port", *resp.Replay.Violations[0].ID)
	suite.Equal([]policyeval.RuleLocation{{File: "policy.rego", StartLine: 7, EndLine: 10}}, resp.Replay.Violations[0].Rules,
		"each violation points at the rule that produced it")
	suite.Contains(resp.Replay.RawJSON, "violation")

	suite.Equal(EvidencePlaybackRecorded{Status: "not-satisfied", ViolationIDs: []string{"unapproved-port"}}, resp.Recorded)
	suite.Equal(&EvidencePlaybackComparison{StatusMatches: true, MissingViolationIDs: []string{}, NewViolationIDs: []string{}}, resp.Comparison)
	suite.Empty(resp.Errors)
}

func (suite *ArtifactApiIntegrationSuite) TestPlaybackReportsAMismatch() {
	stored := suite.storeEvaluation()

	// Recorded as satisfied, but the replay finds a violation.
	id := suite.createPlaybackEvidence("satisfied", nil, suite.refs(stored))
	_, resp := suite.playback(id, suite.userToken)
	suite.Require().True(resp.Available, resp.Reason)
	suite.False(resp.Comparison.StatusMatches)
	suite.Equal([]string{"unapproved-port"}, resp.Comparison.NewViolationIDs)
	suite.Empty(resp.Comparison.MissingViolationIDs)

	// Recorded a violation the replay no longer finds.
	id = suite.createPlaybackEvidence("not-satisfied", []string{"unapproved-port", "retired-check"}, suite.refs(stored))
	_, resp = suite.playback(id, suite.userToken)
	suite.True(resp.Comparison.StatusMatches)
	suite.Equal([]string{"retired-check"}, resp.Comparison.MissingViolationIDs)
	suite.Empty(resp.Comparison.NewViolationIDs)
}

func (suite *ArtifactApiIntegrationSuite) TestPlaybackWithoutArtifactsIsUnavailable() {
	id := suite.createPlaybackEvidence("satisfied", nil, nil)
	code, resp := suite.playback(id, suite.userToken)
	suite.Require().Equal(http.StatusOK, code)
	suite.False(resp.Available)
	suite.Contains(resp.Reason, "recorded without policy artifacts")
	suite.Nil(resp.Replay)
	suite.Equal("satisfied", resp.Recorded.Status)
}

func (suite *ArtifactApiIntegrationSuite) TestPlaybackWithAMissingArtifactIsUnavailable() {
	stored := suite.storeEvaluation()
	id := suite.createPlaybackEvidence("not-satisfied", []string{"unapproved-port"}, suite.refs(stored))
	suite.Require().NoError(suite.DB.Where("digest = ?", stored.input).Delete(&relational.Artifact{}).Error)

	_, resp := suite.playback(id, suite.userToken)
	suite.False(resp.Available)
	suite.Contains(resp.Reason, "input artifact")
	suite.Contains(resp.Reason, "not stored")
}

func (suite *ArtifactApiIntegrationSuite) TestPlaybackTruncatesALargeInput() {
	previous := suite.Config.Artifact
	suite.Config.Artifact = &config.ArtifactConfig{MaxBytes: 4 << 20, MaxConcurrent: 8}
	defer func() { suite.Config.Artifact = previous }()
	suite.SetupTest()

	bundle := suite.uploadDigest(artifact.MediaTypePolicyBundle, suite.tarBundle(artifactTestBundle, true))
	large, err := json.Marshal(map[string]any{"open_ports": []int{22}, "padding": strings.Repeat("x", 2<<20)})
	suite.Require().NoError(err)
	input := suite.uploadDigest(artifact.MediaTypeJSON, large)

	id := suite.createPlaybackEvidence("satisfied", nil, &EvidencePolicyArtifacts{BundleDigest: bundle, InputDigest: input})
	_, resp := suite.playback(id, suite.userToken)
	suite.Require().True(resp.Available, resp.Reason)
	suite.True(resp.InputTruncated)
	suite.LessOrEqual(len(resp.InputJSON), maxPlaybackJSONBytes)
	suite.Require().NotNil(resp.Replay, "the replay uses the full input")
	suite.Equal("satisfied", resp.Replay.Status)
	suite.True(resp.Comparison.StatusMatches)
}

func (suite *ArtifactApiIntegrationSuite) TestPlaybackReportsEvaluationErrors() {
	dir := suite.T().TempDir()
	suite.Require().NoError(os.WriteFile(filepath.Join(dir, "escape.rego"), []byte(`package compliance_framework.ports

title := "escape"

leak := http.send({"method": "GET", "url": "http://example.com"})
`), 0o644))
	bundle := suite.uploadDigest(artifact.MediaTypePolicyBundle, suite.tarBundle(dir, false))
	input := suite.uploadDigest(artifact.MediaTypeJSON, []byte(`{}`))

	id := suite.createPlaybackEvidence("satisfied", nil, &EvidencePolicyArtifacts{BundleDigest: bundle, InputDigest: input})
	_, resp := suite.playback(id, suite.userToken)
	suite.Require().True(resp.Available, "the artifacts are still shown")
	suite.Len(resp.PolicyFiles, 1)
	suite.Nil(resp.Replay)
	suite.Require().NotEmpty(resp.Errors)
	suite.Equal("rego_type_error", resp.Errors[0].Code)
}

func (suite *ArtifactApiIntegrationSuite) TestPlaybackNeedsAnyToken() {
	stored := suite.storeEvaluation()
	id := suite.createPlaybackEvidence("not-satisfied", []string{"unapproved-port"}, suite.refs(stored))

	code, _ := suite.playback(id, "")
	suite.Equal(http.StatusUnauthorized, code, "anonymous")
	code, resp := suite.playback(id, suite.agentToken)
	suite.Equal(http.StatusOK, code, "agent")
	suite.True(resp.Available)

	code, _ = suite.playback(uuid.New().String(), suite.userToken)
	suite.Equal(http.StatusNotFound, code)
	code, _ = suite.playback("not-a-uuid", suite.userToken)
	suite.Equal(http.StatusBadRequest, code)
}
