package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/service/relational/agentcfg"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

const (
	// headerRemoteConfig marks responses from the remote-configuration routes, so an agent can
	// tell them apart from a proxy's.
	headerRemoteConfig = "X-CCF-Remote-Config"

	maxReportHostnameLen     = 255
	maxReportAgentVersionLen = 64
	maxReportErrorBytes      = 8 << 10
	maxReportWarnings        = 500

	// Bounds on the summary columns ListInstances returns for every instance.
	maxReportWarningMessageBytes = 1 << 10
	maxReportWarningPathBytes    = 1 << 10
	maxReportWarningCodeBytes    = 64 // codes are an open set: a newer agent may send ones this API does not know
	maxReportUnsafe              = 200
	maxReportChangePathBytes     = 1 << 10
	maxReportChangeValueBytes    = 2048
	maxReportChangeSafetyBytes   = 64 // safety and reason are cut, not rejected, for the same reason
	maxReportChangeReasonBytes   = 64

	// maxReportSummaryEncodedBytes bounds the summary fields of one stored report (hostname,
	// agent-version, error, warnings, unsafe, plugins, remote-config) as the instance list
	// encodes them: encoding/json with HTML escaping on, as echo's DefaultJSONSerializer does.
	// The byte caps above are on raw text, which escaping can grow up to six times (`<`, `&`
	// and control characters become \u00XX), so normalizeReport also enforces this budget by
	// dropping trailing list entries (applyReportSummaryBudget). A plain-text report at every
	// cap encodes to about 2.9 MB, so it is never cut.
	maxReportSummaryEncodedBytes = 3 << 20
	// maxReportErrorEncodedBytes is what the error text keeps once the summary budget is
	// exceeded: maxReportErrorBytes of text without escapes.
	maxReportErrorEncodedBytes = maxReportErrorBytes + 2

	// R76: plugins.
	maxReportPlugins             = 500
	maxReportPluginNameLen       = 255
	maxReportPluginSourceLen     = 2048
	maxReportPluginLibVersionLen = 64

	// remote-config, a summary column too. Its JSON stays within 64 KiB: two lists of at
	// most maxReportRemoteListEntries entries, each at most maxReportRemoteEntryBytes once
	// JSON-encoded (2 × 100 × 257 bytes with the commas), plus mode and poll_interval (at
	// most 6× their byte caps once escaped) and the keys.
	maxReportRemoteListEntries     = 100
	maxReportRemoteEntryBytes      = 256 // JSON-encoded, quotes included
	maxReportRemoteModeLen         = 32
	maxReportRemotePollIntervalLen = 64
)

var effectiveDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// AgentConfigSyncHandler serves the agent-facing remote-configuration routes. They accept
// agent JWTs only (never anonymous, even with public agent endpoints on) and act on the
// authenticated agent's own configuration.
type AgentConfigSyncHandler struct {
	sugar *zap.SugaredLogger
	svc   *agentcfg.Service
}

func NewAgentConfigSyncHandler(sugar *zap.SugaredLogger, svc *agentcfg.Service) *AgentConfigSyncHandler {
	return &AgentConfigSyncHandler{sugar: sugar, svc: svc}
}

// Register mounts GET /config and PUT /instances/:instanceId/config-report on the /agent
// group. Pass the strict agent JWT middleware and the agent:sync guard.
func (h *AgentConfigSyncHandler) Register(g *echo.Group, middlewares ...echo.MiddlewareFunc) {
	g.GET("/config", h.GetConfig, middlewares...)
	g.PUT("/instances/:instanceId/config-report", h.PutReport, middlewares...)
}

// agentAuthFrom returns the authenticated agent, or nil. The handler requires it even though
// the route middleware does too: Cedar grants the agent role to anonymous subjects when
// public agent endpoints are on (defence in depth).
func agentAuthFrom(ctx echo.Context) *middleware.AgentAuthContext {
	auth, _ := ctx.Get("agent_auth").(*middleware.AgentAuthContext)
	if auth == nil || auth.Agent == nil || auth.Agent.ID == nil {
		return nil
	}
	return auth
}

func setRemoteConfigHeaders(ctx echo.Context) {
	ctx.Response().Header().Set(headerRemoteConfig, "1")
	ctx.Response().Header().Set(echo.HeaderCacheControl, "no-cache")
}

// GetConfig godoc
//
//	@Summary		Get this agent's configuration overlay
//	@Description	Returns the authenticated agent's current remote-configuration overlay (an RFC 7396 merge patch over its local config file, snake_case) with an opaque ETag. Send the raw ETag back as If-None-Match to get a 304 when nothing changed; never construct one. Revision 0 means no overlay. Agent JWT only; a 404 means the API predates remote configuration.
//	@Tags			Agents
//	@Produce		json
//	@Param			If-None-Match	header		string	false	"ETag of the overlay the agent already has"
//	@Success		200				{object}	handler.GenericDataResponse[agentconfig.OverlayDocument]
//	@Success		304				"Not Modified"
//	@Failure		401				{object}	api.Error
//	@Failure		403				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/agent/config [get]
func (h *AgentConfigSyncHandler) GetConfig(ctx echo.Context) error {
	auth := agentAuthFrom(ctx)
	if auth == nil {
		return ctx.JSON(http.StatusUnauthorized, api.NewError(errors.New("agent authentication required")))
	}
	agentID := *auth.Agent.ID
	reqCtx := ctx.Request().Context()
	ifNoneMatch := ctx.Request().Header.Get("If-None-Match")

	// Nearly every poll ends in 304: check the agent's ETag against the revision head first,
	// and load the overlay only when the agent's copy is stale.
	if ifNoneMatch != "" {
		head, err := h.svc.CurrentHead(reqCtx, agentID)
		if err != nil {
			h.sugar.Errorw("Failed to load agent configuration", "agentID", agentID, "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
		}
		rev, rowID := int64(0), uuid.Nil
		if head != nil {
			rev, rowID = head.Revision, head.ID
		}
		if etag := agentconfig.ETagForRevision(rev, rowID, agentID); agentconfig.MatchIfNoneMatch(ifNoneMatch, etag) {
			setRemoteConfigHeaders(ctx)
			ctx.Response().Header().Set(headerETag, etag)
			return ctx.NoContent(http.StatusNotModified)
		}
	}

	cur, err := h.svc.Current(reqCtx, agentID)
	if err != nil {
		h.sugar.Errorw("Failed to load agent configuration", "agentID", agentID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}
	doc := agentconfig.OverlayDocument{Revision: 0, Overlay: json.RawMessage(`{}`)}
	rowID := uuid.Nil
	if cur != nil {
		doc.Revision = cur.Revision
		doc.Overlay = json.RawMessage(cur.Overlay)
		createdAt := cur.CreatedAt.UTC()
		doc.CreatedAt = &createdAt
		rowID = *cur.ID
	}
	etag := agentconfig.ETagForRevision(doc.Revision, rowID, agentID)

	setRemoteConfigHeaders(ctx)
	ctx.Response().Header().Set(headerETag, etag)
	if agentconfig.MatchIfNoneMatch(ifNoneMatch, etag) {
		return ctx.NoContent(http.StatusNotModified)
	}
	return ctx.JSON(http.StatusOK, GenericDataResponse[agentconfig.OverlayDocument]{Data: doc})
}

// PutReport godoc
//
//	@Summary		Report this instance's effective configuration
//	@Description	Stores the authenticated agent instance's config report: mode, applied/attempted revision, status (applied, rejected, failed or not-applicable; the server derives pending and unknown), the redacted base and effective configs (snake_case), the effective digest, plugins (with their agent-library version), unsafe changes, warnings and the normalized local remote_config block. The server re-redacts base and effective as a best effort, replaces error, warning messages, plugin sources, unsafe change values and remote-config strings that contain a secret with ••••, and stores effective-digest as sent. Long warning messages, unsafe lists and remote-config are truncated (truncated=true); a remote-config list entry over the length cap is dropped, not cut. A NUL character anywhere is a 400. Body limit 4 MiB. A 409 means the per-agent instance cap is reached; back off.
//	@Tags			Agents
//	@Accept			json
//	@Param			instanceId	path	string				true	"Agent instance ID (UUID)"
//	@Param			report		body	agentconfig.Report	true	"Config report"
//	@Success		204			"No Content"
//	@Failure		400			{object}	api.Error
//	@Failure		401			{object}	api.Error
//	@Failure		403			{object}	api.Error
//	@Failure		409			{object}	api.Error
//	@Failure		413			{object}	api.Error
//	@Failure		415			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/agent/instances/{instanceId}/config-report [put]
func (h *AgentConfigSyncHandler) PutReport(ctx echo.Context) error {
	auth := agentAuthFrom(ctx)
	if auth == nil {
		return ctx.JSON(http.StatusUnauthorized, api.NewError(errors.New("agent authentication required")))
	}
	setRemoteConfigHeaders(ctx)
	agentID := *auth.Agent.ID

	instanceID, err := uuid.Parse(ctx.Param("instanceId"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.InvalidUUID())
	}
	body, bodyErr := readJSONBody(ctx, agentconfig.MaxReportBytes)
	if bodyErr != nil {
		return bodyErr.respond(ctx)
	}
	var report agentconfig.Report
	if err := json.Unmarshal(body, &report); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid report body: %w", err)))
	}
	scrubbed, err := normalizeReport(&report)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if scrubbed {
		h.sugar.Warnw("Agent config report carried a secret in free text; masked server-side",
			"agentID", agentID, "instanceID", instanceID)
	}

	// Best-effort server-side re-redaction; the digest is stored exactly as sent (R55).
	for _, doc := range []struct {
		name string
		raw  *json.RawMessage
	}{{"base", &report.Base}, {"effective", &report.Effective}} {
		redacted, changed, err := agentconfig.RedactDocument(*doc.raw)
		if err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("%s: %w", doc.name, err)))
		}
		if changed {
			h.sugar.Warnw("Agent config report was not fully redacted; re-redacted server-side",
				"agentID", agentID, "instanceID", instanceID, "document", doc.name)
		}
		*doc.raw = redacted
	}
	var credentialID *uuid.UUID
	if auth.Key != nil && auth.Key.ID != nil {
		id := *auth.Key.ID
		credentialID = &id
	}
	if err := h.svc.UpsertReport(ctx.Request().Context(), agentID, credentialID, instanceID, report); err != nil {
		if errors.Is(err, agentcfg.ErrInstanceLimit) {
			return ctx.JSON(http.StatusConflict, api.NewError(agentcfg.ErrInstanceLimit))
		}
		h.sugar.Errorw("Failed to store agent config report", "agentID", agentID, "instanceID", instanceID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}
	return ctx.NoContent(http.StatusNoContent)
}

// scrubReportText masks the free-text fields of a report that contain a secret by content
// (agentconfig.ScrubSecretText): error, warning messages, plugin sources, unsafe change
// values (a source or env name) and the strings of remote-config. It reports whether
// anything was masked.
func scrubReportText(r *agentconfig.Report) bool {
	scrubbed := false
	scrub := func(s *string) {
		if masked, ok := agentconfig.ScrubSecretText(*s); ok {
			*s = masked
			scrubbed = true
		}
	}
	if r.Error != nil {
		scrub(r.Error)
	}
	for i := range r.Warnings {
		scrub(&r.Warnings[i].Message)
	}
	for i := range r.Plugins {
		scrub(&r.Plugins[i].Source)
	}
	for i := range r.Unsafe {
		scrub(&r.Unsafe[i].Value)
	}
	if rc := r.RemoteConfig; rc != nil {
		scrub(&rc.Mode)
		scrub(&rc.PollInterval)
		for i := range rc.TrustedSources {
			scrub(&rc.TrustedSources[i])
		}
		for i := range rc.OverridableConfigFlags {
			scrub(&rc.OverridableConfigFlags[i])
		}
	}
	return scrubbed
}

// checkReportNUL rejects a NUL character anywhere in a report: Postgres stores neither NUL
// in text columns nor the \u0000 escape in jsonb, so the insert would fail with a 500.
func checkReportNUL(r *agentconfig.Report) error {
	for name, v := range map[string]string{
		"hostname": r.Hostname, "agent-version": r.AgentVersion, "effective-digest": r.EffectiveDigest,
	} {
		if strings.ContainsRune(v, 0) {
			return fmt.Errorf("%s must not contain a NUL character", name)
		}
	}
	if r.Error != nil && strings.ContainsRune(*r.Error, 0) {
		return errors.New("error must not contain a NUL character")
	}
	for name, raw := range map[string]json.RawMessage{"base": r.Base, "effective": r.Effective} {
		if hasJSONNULEscape(raw) {
			return fmt.Errorf("%s must not contain a NUL character", name)
		}
	}
	// The remaining parts are stored as jsonb; encoding/json escapes a NUL as \u0000.
	for name, v := range map[string]any{
		"warnings": r.Warnings, "unsafe": r.Unsafe, "plugins": r.Plugins, "remote-config": r.RemoteConfig,
	} {
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if hasJSONNULEscape(raw) {
			return fmt.Errorf("%s must not contain a NUL character", name)
		}
	}
	return nil
}

// hasJSONNULEscape reports whether raw JSON contains the \u0000 escape (an unescaped
// backslash followed by u0000), i.e. a string that decodes to a NUL character.
func hasJSONNULEscape(raw []byte) bool {
	const esc = `\u0000`
	for i := 0; ; {
		j := bytes.Index(raw[i:], []byte(esc))
		if j < 0 {
			return false
		}
		at := i + j
		backslashes := 0
		for k := at - 1; k >= 0 && raw[k] == '\\'; k-- {
			backslashes++
		}
		if backslashes%2 == 0 {
			return true
		}
		i = at + len(esc)
	}
}

// normalizeReport validates the enums and shapes of a report, applies the count caps, masks
// the free-text fields that contain a secret (scrubReportText), then applies the length caps
// and the encoded summary budget (applyReportSummaryBudget), truncating, not rejecting.
// Masking runs before truncation so a secret cut at a cap cannot slip past the content
// checks. scrubbed reports whether anything was masked.
func normalizeReport(r *agentconfig.Report) (scrubbed bool, err error) {
	if !slices.Contains(agentconfig.Modes, r.Mode) {
		return false, fmt.Errorf("mode must be one of %s", strings.Join(agentconfig.Modes, ", "))
	}
	if !slices.Contains(agentconfig.AgentStatuses, r.Status) {
		return false, fmt.Errorf("status must be one of %s", strings.Join(agentconfig.AgentStatuses, ", "))
	}
	if r.Reason != "" && !slices.Contains(agentconfig.Reasons, r.Reason) {
		return false, fmt.Errorf("reason %q is not a known reason", r.Reason)
	}
	if r.AppliedRevision != nil && *r.AppliedRevision < 0 {
		return false, errors.New("applied-revision must not be negative")
	}
	if r.AttemptedRevision != nil && *r.AttemptedRevision < 0 {
		return false, errors.New("attempted-revision must not be negative")
	}
	if !isJSONObject(r.Base) {
		return false, errors.New("base must be a JSON object")
	}
	if !isJSONObject(r.Effective) {
		return false, errors.New("effective must be a JSON object")
	}
	if err := checkReportNUL(r); err != nil {
		return false, err
	}
	if !effectiveDigestPattern.MatchString(r.EffectiveDigest) {
		return false, errors.New("effective-digest must match sha256:<64 lowercase hex>")
	}
	for i, p := range r.Plugins {
		if strings.TrimSpace(p.Name) == "" {
			return false, fmt.Errorf("plugins[%d].name is required", i)
		}
	}

	// Count caps first, so masking only scans what is kept.
	if len(r.Plugins) > maxReportPlugins {
		r.Plugins = r.Plugins[:maxReportPlugins]
		r.Truncated = true
	}
	if len(r.Warnings) > maxReportWarnings {
		r.Warnings = r.Warnings[:maxReportWarnings]
		r.Truncated = true
	}
	if len(r.Unsafe) > maxReportUnsafe {
		r.Unsafe = r.Unsafe[:maxReportUnsafe]
		r.Truncated = true
	}
	if rc := r.RemoteConfig; rc != nil {
		if len(rc.TrustedSources) > maxReportRemoteListEntries {
			rc.TrustedSources = rc.TrustedSources[:maxReportRemoteListEntries]
			r.Truncated = true
		}
		if len(rc.OverridableConfigFlags) > maxReportRemoteListEntries {
			rc.OverridableConfigFlags = rc.OverridableConfigFlags[:maxReportRemoteListEntries]
			r.Truncated = true
		}
	}

	scrubbed = scrubReportText(r)

	for i := range r.Plugins {
		p := &r.Plugins[i]
		p.Name = truncateUTF8(p.Name, maxReportPluginNameLen)
		p.Source = truncateUTF8(p.Source, maxReportPluginSourceLen)
		p.LibVersion = truncateUTF8(strings.TrimSpace(p.LibVersion), maxReportPluginLibVersionLen)
	}
	for i := range r.Warnings {
		w := &r.Warnings[i]
		w.Message = truncateReportField(r, w.Message, maxReportWarningMessageBytes)
		w.Path = truncateReportField(r, w.Path, maxReportWarningPathBytes)
		w.Code = truncateReportField(r, w.Code, maxReportWarningCodeBytes)
	}
	for i := range r.Unsafe {
		c := &r.Unsafe[i]
		c.Path = truncateReportField(r, c.Path, maxReportChangePathBytes)
		c.Value = truncateReportField(r, c.Value, maxReportChangeValueBytes)
		c.Safety = agentconfig.Safety(truncateReportField(r, string(c.Safety), maxReportChangeSafetyBytes))
		c.Reason = truncateReportField(r, c.Reason, maxReportChangeReasonBytes)
	}
	if rc := r.RemoteConfig; rc != nil {
		rc.Mode = truncateReportField(r, rc.Mode, maxReportRemoteModeLen)
		rc.PollInterval = truncateReportField(r, rc.PollInterval, maxReportRemotePollIntervalLen)
		rc.TrustedSources = dropLongRemoteEntries(r, rc.TrustedSources)
		rc.OverridableConfigFlags = dropLongRemoteEntries(r, rc.OverridableConfigFlags)
	}
	r.Hostname = truncateUTF8(strings.TrimSpace(r.Hostname), maxReportHostnameLen)
	r.AgentVersion = truncateUTF8(strings.TrimSpace(r.AgentVersion), maxReportAgentVersionLen)
	if r.Error != nil {
		msg := truncateUTF8(*r.Error, maxReportErrorBytes)
		r.Error = &msg
	}
	if err := applyReportSummaryBudget(r); err != nil {
		return false, err
	}
	return scrubbed, nil
}

// encodedLen is the length of v encoded as the instance list encodes it (encoding/json with
// HTML escaping, which json.Marshal applies).
func encodedLen(v any) (int, error) {
	raw, err := json.Marshal(v)
	return len(raw), err
}

// encodedEntryLens returns the encoded length of each entry of a list.
func encodedEntryLens[T any](entries []T) ([]int, error) {
	lens := make([]int, len(entries))
	for i := range entries {
		n, err := encodedLen(entries[i])
		if err != nil {
			return nil, err
		}
		lens[i] = n
	}
	return lens, nil
}

// applyReportSummaryBudget keeps the encoded summary fields of a normalized report within
// maxReportSummaryEncodedBytes. Within budget, the report is left unchanged. Over it, the
// report is marked truncated, the error text is cut to maxReportErrorEncodedBytes encoded,
// and the last entry of the largest list (warnings, unsafe or plugins) is dropped until the
// report fits. The other fields are small once capped (remote-config within 64 KiB encoded,
// the hostname and version within six times their byte caps), so dropping entries always
// reaches the budget.
func applyReportSummaryBudget(r *agentconfig.Report) error {
	fixed := 0
	for _, v := range []any{r.Hostname, r.AgentVersion, r.RemoteConfig} {
		n, err := encodedLen(v)
		if err != nil {
			return err
		}
		fixed += n
	}
	errLen := 0
	if r.Error != nil {
		n, err := encodedLen(*r.Error)
		if err != nil {
			return err
		}
		errLen = n
	}
	// Per list: the encoded length of each entry, how many are kept, and the kept entries'
	// encoded length as a JSON array.
	type list struct {
		entries []int
		kept    int
		size    int
	}
	newList := func(entries []int) list {
		l := list{entries: entries, kept: len(entries), size: 2 + max(0, len(entries)-1)}
		for _, n := range entries {
			l.size += n
		}
		return l
	}
	warnings, err := encodedEntryLens(r.Warnings)
	if err != nil {
		return err
	}
	unsafe, err := encodedEntryLens(r.Unsafe)
	if err != nil {
		return err
	}
	plugins, err := encodedEntryLens(r.Plugins)
	if err != nil {
		return err
	}
	lists := [3]list{newList(warnings), newList(unsafe), newList(plugins)}
	total := fixed + errLen + lists[0].size + lists[1].size + lists[2].size
	if total <= maxReportSummaryEncodedBytes {
		return nil
	}
	r.Truncated = true
	if r.Error != nil && errLen > maxReportErrorEncodedBytes {
		msg, n, err := truncateEncoded(*r.Error, maxReportErrorEncodedBytes)
		if err != nil {
			return err
		}
		r.Error = &msg
		total -= errLen - n
	}
	for total > maxReportSummaryEncodedBytes {
		largest := &lists[0]
		for i := range lists[1:] {
			if lists[i+1].size > largest.size {
				largest = &lists[i+1]
			}
		}
		if largest.kept == 0 {
			break // unreachable: the fixed fields are far below the budget
		}
		largest.kept--
		dropped := largest.entries[largest.kept]
		if largest.kept > 0 {
			dropped++ // its comma
		}
		largest.size -= dropped
		total -= dropped
	}
	r.Warnings = r.Warnings[:lists[0].kept]
	r.Unsafe = r.Unsafe[:lists[1].kept]
	r.Plugins = r.Plugins[:lists[2].kept]
	return nil
}

// truncateEncoded cuts s to a rune-boundary prefix whose JSON encoding is at most limit bytes
// (at most a few bytes shorter than the longest such prefix) and returns it with its encoded
// length.
func truncateEncoded(s string, limit int) (string, int, error) {
	cut := truncateUTF8(s, limit-2) // quotes included, each byte encodes to at least one byte
	for {
		n, err := encodedLen(cut)
		if err != nil || n <= limit {
			return cut, n, err
		}
		// A byte encodes to at most six, so drop at least a sixth of the overshoot.
		cut = truncateUTF8(cut, len(cut)-max(1, (n-limit+5)/6))
	}
}

// truncateReportField cuts s to n bytes (truncateUTF8) and marks the report truncated when
// it did.
func truncateReportField(r *agentconfig.Report, s string, n int) string {
	if len(s) <= n {
		return s
	}
	r.Truncated = true
	return truncateUTF8(s, n)
}

// dropLongRemoteEntries removes the trusted_sources or overridable_config_flags entries
// longer than maxReportRemoteEntryBytes once JSON-encoded, and marks the report truncated
// when it removed any. An entry is dropped, not cut: these are path.Match patterns, and a
// cut pattern can match more than the host trusts (".../*/x" cut to ".../*").
func dropLongRemoteEntries(r *agentconfig.Report, entries []string) []string {
	return slices.DeleteFunc(entries, func(e string) bool {
		encoded, err := json.Marshal(e)
		if err == nil && len(encoded) <= maxReportRemoteEntryBytes {
			return false
		}
		r.Truncated = true
		return true
	})
}

func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
