package handler

import (
	"errors"
	"fmt"
	"maps"
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
//	@Description	Requires 1 to CCF_EVIDENCE_BADGE_MAX_PARAMS labels (default 3). Each key must occur once with a non-empty value. No labels are implicit. Names and values are limited to 255 characters without surrounding whitespace or control characters; internal spaces are allowed.
//	@Tags			Evidence
//	@Produce		image/svg+xml
//	@Success		200	{string}	string	"SVG compliance badge"
//	@Failure		400	{object}	api.Error
//	@Failure		429	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/evidence/badge.svg [get]
func (h *EvidenceHandler) ComplianceBadge(ctx *echo.Context) error {
	if h.badgeMaxParams <= 0 {
		h.sugar.Errorw("Invalid compliance badge parameter limit", "maxParams", h.badgeMaxParams)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	params, err := url.ParseQuery(ctx.Request().URL.RawQuery)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("invalid label query: %w", err)))
	}
	filter, err := parseComplianceBadgeParams(params, h.badgeMaxParams)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	select {
	case h.badgeSlots <- struct{}{}:
		defer func() { <-h.badgeSlots }()
	default:
		return ctx.JSON(http.StatusTooManyRequests, api.NewError(errors.New("too many compliance badge requests in progress, retry shortly")))
	}

	rows, err := h.evidenceService.GetStatusCountsAtPoint(filter, nil)
	if err != nil {
		h.sugar.Errorw("Failed to get compliance badge status", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.InternalServerError())
	}

	ctx.Response().Header().Set("Cache-Control", "no-store")
	return ctx.Blob(http.StatusOK, "image/svg+xml; charset=utf-8", []byte(complianceBadgeSVG(complianceBadgeStatus(rows))))
}

func parseComplianceBadgeParams(params url.Values, maxParams int) (labelfilter.Filter, error) {
	if len(params) == 0 || len(params) > maxParams {
		return labelfilter.Filter{}, fmt.Errorf("provide between 1 and %d label query parameters", maxParams)
	}

	scopes := make([]labelfilter.Scope, 0, len(params))
	seen := make(map[string]bool, len(params))
	for _, name := range slices.Sorted(maps.Keys(params)) {
		values := params[name]
		normalized := strings.ToLower(name)
		if len(values) != 1 || seen[normalized] {
			return labelfilter.Filter{}, fmt.Errorf("label %q must occur exactly once", name)
		}
		seen[normalized] = true
		for _, text := range []string{name, values[0]} {
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
			Condition: &labelfilter.Condition{Label: name, Operator: "=", Value: values[0]},
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

func complianceBadgeStatus(rows []evidencesvc.StatusCount) string {
	statusCounts := make([]relational.StatusCount, len(rows))
	for i, row := range rows {
		statusCounts[i] = relational.StatusCount{Count: row.Count, Status: row.Status}
	}
	return relational.CollapseEvidenceStatus(statusCounts)
}

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
