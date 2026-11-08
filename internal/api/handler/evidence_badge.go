package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	"github.com/labstack/echo/v5"
)

const complianceBadgeMaxParamLength = 255

const complianceBadgeMaxConcurrent = 4

// ComplianceBadge godoc
//
//	@Summary		Get an SVG compliance status badge
//	@Description	Returns an SVG badge for the latest evidence matching ALL supplied query parameters as label name/value pairs, e.g. ?provider=aws&environment=production.
//	@Description	Aggregates the latest evidence from each matching stream, so a failure in another stream can make the badge red (not-satisfied).
//	@Description	Requires 1 to CCF_EVIDENCE_BADGE_MAX_PARAMS labels (default 3). Each key must occur exactly once (keys must be unique case-insensitively) with a non-empty value. No labels are implicit. Names and values are limited to 255 characters without surrounding whitespace or control characters; internal spaces are allowed.
//	@Description	Labels can be sent in two equivalent forms, which may be mixed: one ?<label-name>=<label-value> query parameter per label, or the repeatable label parameter as label=<label-name>:<label-value> (split at the first colon). Swagger UI exposes only the label parameter; add one item per label pair.
//	@Description	The label key is reserved for the second form, so a label literally named "label" must be sent as label=label:<value>.
//	@Description	Authentication is conditional. When public evidence reads are enabled (CCF_STRICT_DISABLE_PUBLIC_AGENT_ENDPOINTS is false, the default) and the authorization policy permits the read, no credentials are required. Otherwise send an OAuth2 bearer token (Authorization: Bearer <token>) or the ccf_auth_token session cookie for a user or agent allowed to read evidence. A supplied Authorization header must always be valid.
//	@Tags			Evidence
//	@Produce		image/svg+xml
//	@Produce		application/json
//	@Param			label	query		[]string	false	"Label pair as name:value, e.g. provider:aws. Repeat for each label."	collectionFormat(multi)
//	@Success		200		{string}	string		"SVG compliance badge"
//	@Failure		400		{object}	api.Error	"Missing, duplicate, too many or invalid label parameters"
//	@Failure		401		{object}	api.Error	"Credentials are required (public evidence reads disabled) or the supplied token is invalid"
//	@Failure		403		{object}	api.Error	"The authorization policy denies reading evidence"
//	@Failure		429		{object}	api.Error	"Too many badge requests in progress"
//	@Failure		500		{object}	api.Error
//	@Router			/evidence/badge.svg [get]
func (h *EvidenceHandler) ComplianceBadge(ctx *echo.Context) error {
	select {
	case h.badgeSlots <- struct{}{}:
		defer func() { <-h.badgeSlots }()
	default:
		return ctx.JSON(http.StatusTooManyRequests, api.NewError(errors.New("too many compliance badge requests in progress, retry shortly")))
	}

	if countComplianceBadgeQueryComponents(ctx.Request().URL.RawQuery) > h.badgeMaxParams {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("provide between 1 and %d label query parameters", h.badgeMaxParams)))
	}

	params, err := url.ParseQuery(ctx.Request().URL.RawQuery)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid label query: %w", err)))
	}
	filter, err := parseComplianceBadgeParams(params, h.badgeMaxParams)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	rows, err := h.evidenceService.GetStatusCountsAtPoint(ctx.Request().Context(), filter, nil)
	if err != nil {
		h.sugar.Errorw("Failed to get compliance badge status", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	ctx.Response().Header().Set("Cache-Control", "no-store")
	return ctx.Blob(http.StatusOK, "image/svg+xml; charset=utf-8", []byte(complianceBadgeSVG(complianceBadgeStatus(rows))))
}

// complianceBadgeLabelParam is the reserved query key for repeatable name:value label pairs,
// which lets clients that only support fixed parameter names (such as Swagger UI) send labels.
const complianceBadgeLabelParam = "label"

type complianceBadgeLabel struct {
	name  string
	value string
}

// complianceBadgeLabels flattens ?name=value pairs and repeatable ?label=name:value pairs.
func complianceBadgeLabels(params url.Values) ([]complianceBadgeLabel, error) {
	labels := make([]complianceBadgeLabel, 0, len(params))
	for name, values := range params {
		if name != complianceBadgeLabelParam {
			if len(values) != 1 {
				return nil, fmt.Errorf("label %q must occur exactly once", name)
			}
			labels = append(labels, complianceBadgeLabel{name: name, value: values[0]})
			continue
		}
		for _, pair := range values {
			labelName, labelValue, ok := strings.Cut(pair, ":")
			if !ok {
				return nil, fmt.Errorf("%s parameter %q must use the form name:value", complianceBadgeLabelParam, pair)
			}
			labels = append(labels, complianceBadgeLabel{name: labelName, value: labelValue})
		}
	}
	slices.SortFunc(labels, func(a, b complianceBadgeLabel) int { return strings.Compare(a.name, b.name) })
	return labels, nil
}

// parseComplianceBadgeParams validates badge labels and builds their AND filter.
func parseComplianceBadgeParams(params url.Values, maxParams int) (labelfilter.Filter, error) {
	labels, err := complianceBadgeLabels(params)
	if err != nil {
		return labelfilter.Filter{}, err
	}
	if len(labels) == 0 || len(labels) > maxParams {
		return labelfilter.Filter{}, fmt.Errorf("provide between 1 and %d label query parameters", maxParams)
	}

	scopes := make([]labelfilter.Scope, 0, len(labels))
	seen := make(map[string]bool, len(labels))
	for _, label := range labels {
		name := label.name
		normalized := strings.ToLower(name)
		turkishNormalized := strings.ToLowerSpecial(unicode.TurkishCase, name)
		if seen[normalized] || seen[turkishNormalized] {
			return labelfilter.Filter{}, fmt.Errorf("label %q must occur exactly once", name)
		}
		seen[normalized] = true
		seen[turkishNormalized] = true
		for _, text := range []string{name, label.value} {
			if text == "" || strings.TrimSpace(text) != text {
				return labelfilter.Filter{}, fmt.Errorf("label %q must have a non-empty name and value without surrounding whitespace", name)
			}
			if !utf8.ValidString(text) || utf8.RuneCountInString(text) > complianceBadgeMaxParamLength {
				return labelfilter.Filter{}, fmt.Errorf("label %q names and values must be valid UTF-8 of at most %d characters", name, complianceBadgeMaxParamLength)
			}
			if strings.ContainsFunc(text, unicode.IsControl) {
				return labelfilter.Filter{}, fmt.Errorf("label %q must not contain control characters", name)
			}
		}
		scopes = append(scopes, labelfilter.Scope{
			Condition: &labelfilter.Condition{Label: name, Operator: "=", Value: label.value},
		})
	}
	return labelfilter.Filter{
		Scope: &labelfilter.Scope{
			Query: &labelfilter.Query{
				Operator: "and",
				Scopes:   scopes,
			},
		},
	}, nil
}

// countComplianceBadgeQueryComponents counts non-empty raw query components without allocating.
func countComplianceBadgeQueryComponents(rawQuery string) int {
	count := 0
	for i := 0; i < len(rawQuery); i++ {
		if rawQuery[i] != '&' && (i == 0 || rawQuery[i-1] == '&') {
			count++
		}
	}
	return count
}

// complianceBadgeStatus collapses evidence status counts into one badge status.
func complianceBadgeStatus(rows []evidencesvc.StatusCount) string {
	statusCounts := make([]relational.StatusCount, len(rows))
	for i, row := range rows {
		statusCounts[i] = relational.StatusCount{Count: row.Count, Status: row.Status}
	}
	return relational.CollapseEvidenceStatus(statusCounts)
}

// complianceBadgeSVG renders the compliance status as an SVG badge.
func complianceBadgeSVG(status string) string {
	color := "#9f9f9f"
	switch status {
	case relational.EvidenceStatusSatisfied:
		color = "#4c1"
	case relational.EvidenceStatusNotSatisfied:
		color = "#e05d44"
	default:
		status = "unknown"
	}

	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="174" height="20" role="img" aria-label="Compliance status: %s"><title>Compliance status: %s</title><linearGradient id="b" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="r"><rect width="174" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#r)"><path fill="#555" d="M0 0h84v20H0z"/><path fill="%s" d="M84 0h90v20H84z"/><path fill="url(#b)" d="M0 0h174v20H0z"/></g><g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,sans-serif" font-size="11"><text x="42" y="15">compliance</text><text x="129" y="15">%s</text></g></svg>`, status, status, color, status)
}
