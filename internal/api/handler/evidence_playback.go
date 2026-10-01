package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/artifact"
	"github.com/compliance-framework/api/internal/service/relational"
	artifactsvc "github.com/compliance-framework/api/internal/service/relational/artifacts"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/compliance-framework/api/pkg/policyeval"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

// maxPlaybackJSONBytes bounds each JSON document returned for display. Inputs can be very
// large (a whole cluster, say); the full artifact stays downloadable by digest.
const maxPlaybackJSONBytes = 1 << 20

// Evidence labels and props the agent writes and playback reads.
const (
	evidencePolicyLabel = "_policy"
	evidenceViolationID = "_violation_id"
)

// EvidencePlaybackResponse is everything an evidence's policy evaluation was made of, and
// the result of replaying it, compared with what the evidence recorded.
type EvidencePlaybackResponse struct {
	// Available is false when the evidence cannot be played back; Reason says why.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`

	// Package is the policy package that produced the evidence.
	Package     string                     `json:"package,omitempty"`
	EvaluatedAt *time.Time                 `json:"evaluatedAt,omitempty"`
	Artifacts   *EvidencePlaybackArtifacts `json:"artifacts,omitempty"`

	PolicyFiles []EvidencePlaybackFile `json:"policyFiles"`
	// JSON documents are pretty-printed strings, shown as they are.
	PolicyDataJSON *string `json:"policyDataJson"`
	BundleDataJSON *string `json:"bundleDataJson"`
	InputJSON      string  `json:"inputJson"`
	// InputTruncated means InputJSON holds only the first part of the input; the full input
	// is the input artifact.
	InputTruncated bool `json:"inputTruncated"`

	Recorded   EvidencePlaybackRecorded    `json:"recorded"`
	Replay     *EvidencePlaybackReplay     `json:"replay"`
	Comparison *EvidencePlaybackComparison `json:"comparison"`
	Prints     []string                    `json:"prints"`
	// Errors are why the replay could not run, for example a policy the sandbox forbids.
	Errors []policyeval.EvalError `json:"errors"`
}

type EvidencePlaybackArtifacts struct {
	Bundle     artifact.Info  `json:"bundle"`
	Input      artifact.Info  `json:"input"`
	PolicyData *artifact.Info `json:"policyData"`
}

type EvidencePlaybackFile struct {
	Path   string `json:"path"`
	Source string `json:"source"`
	// ContainsPackage marks the file defining the package that produced the evidence.
	ContainsPackage bool `json:"containsPackage"`
}

type EvidencePlaybackRecorded struct {
	Status       string   `json:"status"`
	ViolationIDs []string `json:"violationIds"`
}

type EvidencePlaybackReplay struct {
	Status     string                      `json:"status"`
	Title      *string                     `json:"title"`
	Violations []EvidencePlaybackViolation `json:"violations"`
	RawJSON    string                      `json:"rawJson"`
	// Error explains why the agent would not have turned the result into evidence.
	Error string `json:"error,omitempty"`
}

// EvidencePlaybackViolation is a replayed violation and where in the policy it came from.
type EvidencePlaybackViolation struct {
	policyeval.Violation
	// Rules are the `violation` rules that produced it, by file and line. Empty when they
	// could not be located.
	Rules []policyeval.RuleLocation `json:"rules"`
}

type EvidencePlaybackComparison struct {
	StatusMatches bool `json:"statusMatches"`
	// MissingViolationIDs were recorded but not found by the replay.
	MissingViolationIDs []string `json:"missingViolationIds"`
	// NewViolationIDs were found by the replay but not recorded.
	NewViolationIDs []string `json:"newViolationIds"`
	// UnidentifiedViolations have no id, so cannot be compared.
	UnidentifiedViolations int `json:"unidentifiedViolations"`
}

// WithEvidencePlayback lets the handler replay stored evidence.
func (h *PlaybackHandler) WithEvidencePlayback(evidence *evidencesvc.EvidenceService, artifacts *artifactsvc.Service) *PlaybackHandler {
	h.evidence = evidence
	h.artifacts = artifacts
	return h
}

// RegisterEvidence registers the evidence playback route.
func (h *PlaybackHandler) RegisterEvidence(api *echo.Group, middlewares ...echo.MiddlewareFunc) {
	api.GET("/:id/playback", h.EvidencePlayback, middlewares...)
}

// EvidencePlayback godoc
//
//	@Summary		Play back an evidence's policy evaluation
//	@Description	Loads the policy bundle, input and policy data stored for the evidence, replays the evaluation in the playback sandbox at the evidence's end time, and compares the result with what the evidence recorded. JSON documents are returned as pretty-printed strings; inputs over 1 MiB are truncated (the full input is the input artifact). Evidence recorded without artifacts returns available false. Needs any user or agent token.
//	@Tags			Playback
//	@Produce		json
//	@Param			id	path		string	true	"Evidence ID"
//	@Success		200	{object}	handler.GenericDataResponse[handler.EvidencePlaybackResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		429	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/evidence/{id}/playback [get]
func (h *PlaybackHandler) EvidencePlayback(ctx echo.Context) error {
	id, err := uuid.Parse(ctx.Param("id"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid evidence id: %w", err)))
	}

	evidence, err := h.evidence.GetByID(id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	if err != nil {
		h.sugar.Errorw("Failed to load evidence for playback", "id", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		return ctx.JSON(http.StatusTooManyRequests, api.NewError(errors.New("too many playback evaluations in progress, retry shortly")))
	}

	evalCtx, cancel := context.WithTimeout(ctx.Request().Context(), h.timeout)
	defer cancel()

	resp, err := h.playEvidence(evalCtx, evidence)
	if err != nil {
		h.sugar.Errorw("Failed to play back evidence", "id", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, GenericDataResponse[*EvidencePlaybackResponse]{Data: resp})
}

func (h *PlaybackHandler) playEvidence(ctx context.Context, evidence *relational.Evidence) (*EvidencePlaybackResponse, error) {
	resp := &EvidencePlaybackResponse{
		PolicyFiles: []EvidencePlaybackFile{},
		Prints:      []string{},
		Errors:      []policyeval.EvalError{},
		Recorded:    recordedResult(evidence),
		Package:     evidenceLabel(evidence, evidencePolicyLabel),
	}

	digests := map[string]string{}
	for _, prop := range evidence.Props {
		if artifact.IsReservedProp(prop.Name) {
			digests[prop.Name] = prop.Value
		}
	}
	if digests[artifact.PropPolicyBundleDigest] == "" || digests[artifact.PropPolicyInputDigest] == "" {
		resp.Reason = "This evidence was recorded without policy artifacts, so it cannot be played back. It was produced by an agent or plugin that predates playback, or its artifacts could not be stored."
		return resp, nil
	}

	bundle, err := h.loadArtifact(ctx, digests[artifact.PropPolicyBundleDigest])
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return notStored(resp, "policy bundle"), nil
	}
	input, err := h.loadArtifact(ctx, digests[artifact.PropPolicyInputDigest])
	if err != nil {
		return nil, err
	}
	if input == nil {
		return notStored(resp, "input"), nil
	}
	var policyData *relational.Artifact
	if digest := digests[artifact.PropPolicyDataDigest]; digest != "" {
		if policyData, err = h.loadArtifact(ctx, digest); err != nil {
			return nil, err
		}
		if policyData == nil {
			return notStored(resp, "policy data"), nil
		}
	}

	resp.Artifacts = &EvidencePlaybackArtifacts{Bundle: infoOf(bundle), Input: infoOf(input)}
	if policyData != nil {
		info := infoOf(policyData)
		resp.Artifacts.PolicyData = &info
	}

	unpacked, err := artifact.ReadBundleTar(bundle.Content)
	if err != nil {
		return unreadable(resp, "policy bundle", err), nil
	}
	for path, source := range unpacked.Modules {
		resp.PolicyFiles = append(resp.PolicyFiles, EvidencePlaybackFile{Path: path, Source: source})
	}
	sort.Slice(resp.PolicyFiles, func(i, j int) bool { return resp.PolicyFiles[i].Path < resp.PolicyFiles[j].Path })

	resp.InputJSON, resp.InputTruncated = displayJSON(input.Content)
	if policyData != nil {
		text, _ := displayJSON(policyData.Content)
		resp.PolicyDataJSON = &text
	}
	if len(unpacked.Data) > 0 {
		raw, err := json.Marshal(unpacked.Data)
		if err != nil {
			return nil, err
		}
		text, _ := displayJSON(raw)
		resp.BundleDataJSON = &text
	}

	inputValue, err := decodeJSON(input.Content)
	if err != nil {
		return unreadable(resp, "input", err), nil
	}
	data := unpacked.Data
	if policyData != nil {
		overlay, err := decodeJSON(policyData.Content)
		if err != nil {
			return unreadable(resp, "policy data", err), nil
		}
		overlayMap, ok := overlay.(map[string]any)
		if !ok {
			return unreadable(resp, "policy data", errors.New("it is not a JSON object")), nil
		}
		data = policyeval.MergeData(data, overlayMap)
	}

	resp.Available = true
	evaluatedAt := evidence.End
	resp.EvaluatedAt = &evaluatedAt

	request := policyeval.EvaluateModulesRequest{
		Modules:     unpacked.Modules,
		Input:       inputValue,
		Data:        data,
		EvaluatedAt: &evaluatedAt,
	}
	replayed, err := policyeval.EvaluateModules(ctx, request)
	if err != nil {
		var evalErrs *policyeval.EvalErrors
		if !errors.As(err, &evalErrs) {
			return nil, err
		}
		resp.Errors = evalErrs.Errors
		return resp, nil
	}
	resp.Prints = replayed.Prints

	result := pickResult(replayed.Results, resp.Package)
	if result == nil {
		resp.Errors = append(resp.Errors, policyeval.EvalError{
			Code:    "package_not_found",
			Message: fmt.Sprintf("the bundle has no package %q", resp.Package),
		})
		return resp, nil
	}
	if resp.Package == "" {
		resp.Package = result.Package
	}
	for i := range resp.PolicyFiles {
		resp.PolicyFiles[i].ContainsPackage = resp.PolicyFiles[i].Path == result.File
	}

	raw, err := json.MarshalIndent(result.Raw, "", "  ")
	if err != nil {
		return nil, err
	}
	// Locating is best effort: the violations are shown without locations if it fails.
	rules, err := policyeval.LocateViolations(ctx, request, resp.Package)
	if err != nil {
		h.sugar.Warnw("Failed to locate the rules behind replayed violations", "package", resp.Package, "error", err)
	}
	violations := make([]EvidencePlaybackViolation, 0, len(result.Violations))
	for _, violation := range result.Violations {
		violations = append(violations, EvidencePlaybackViolation{Violation: violation, Rules: policyeval.RulesFor(rules, violation)})
	}

	resp.Replay = &EvidencePlaybackReplay{
		Status:     result.Status,
		Title:      result.Title,
		Violations: violations,
		RawJSON:    string(raw),
		Error:      result.Error,
	}
	resp.Comparison = compareResults(resp.Recorded, resp.Replay)
	return resp, nil
}

// loadArtifact returns the stored artifact, or nil if it is not stored.
func (h *PlaybackHandler) loadArtifact(ctx context.Context, digest string) (*relational.Artifact, error) {
	stored, err := h.artifacts.Get(ctx, digest)
	if errors.Is(err, artifactsvc.ErrNotFound) {
		return nil, nil
	}
	return stored, err
}

func notStored(resp *EvidencePlaybackResponse, what string) *EvidencePlaybackResponse {
	resp.Reason = fmt.Sprintf("The %s artifact this evidence refers to is not stored, so it cannot be played back.", what)
	return resp
}

func unreadable(resp *EvidencePlaybackResponse, what string, err error) *EvidencePlaybackResponse {
	resp.Reason = fmt.Sprintf("The stored %s cannot be read, so the evidence cannot be played back: %v", what, err)
	return resp
}

func infoOf(a *relational.Artifact) artifact.Info {
	return artifact.Info{Digest: a.Digest, MediaType: a.MediaType, SizeBytes: a.SizeBytes}
}

// displayJSON pretty-prints canonical JSON, truncated to maxPlaybackJSONBytes on a UTF-8
// boundary.
func displayJSON(raw []byte) (string, bool) {
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		out.Reset()
		out.Write(raw)
	}
	text := out.Bytes()
	if len(text) <= maxPlaybackJSONBytes {
		return string(text), false
	}
	cut := maxPlaybackJSONBytes
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return string(text[:cut]), true
}

// decodeJSON decodes as the playback endpoint does, keeping numbers exact.
func decodeJSON(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var v any
	if err := decoder.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func evidenceLabel(evidence *relational.Evidence, name string) string {
	for _, label := range evidence.Labels {
		if label.Name == name {
			return label.Value
		}
	}
	return ""
}

func recordedResult(evidence *relational.Evidence) EvidencePlaybackRecorded {
	recorded := EvidencePlaybackRecorded{ViolationIDs: []string{}}
	recorded.Status = evidence.Status.Data().State
	for _, prop := range evidence.Props {
		if prop.Name == evidenceViolationID {
			recorded.ViolationIDs = append(recorded.ViolationIDs, prop.Value)
		}
	}
	sort.Strings(recorded.ViolationIDs)
	return recorded
}

// pickResult returns the result for pkg, or the only result when pkg is not known.
func pickResult(results []policyeval.EvaluateResult, pkg string) *policyeval.EvaluateResult {
	for i := range results {
		if results[i].Package == pkg {
			return &results[i]
		}
	}
	if pkg == "" && len(results) == 1 {
		return &results[0]
	}
	return nil
}

func compareResults(recorded EvidencePlaybackRecorded, replay *EvidencePlaybackReplay) *EvidencePlaybackComparison {
	comparison := &EvidencePlaybackComparison{
		StatusMatches:       recorded.Status == replay.Status,
		MissingViolationIDs: []string{},
		NewViolationIDs:     []string{},
	}
	replayed := map[string]bool{}
	for _, v := range replay.Violations {
		if v.ID == nil || *v.ID == "" {
			comparison.UnidentifiedViolations++
			continue
		}
		replayed[*v.ID] = true
	}
	wasRecorded := map[string]bool{}
	for _, id := range recorded.ViolationIDs {
		wasRecorded[id] = true
		if !replayed[id] {
			comparison.MissingViolationIDs = append(comparison.MissingViolationIDs, id)
		}
	}
	for id := range replayed {
		if !wasRecorded[id] {
			comparison.NewViolationIDs = append(comparison.NewViolationIDs, id)
		}
	}
	sort.Strings(comparison.NewViolationIDs)
	return comparison
}
