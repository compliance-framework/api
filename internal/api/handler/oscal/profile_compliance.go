package oscal

import (
	"errors"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type ProfileComplianceProgress struct {
	Scope          ProfileComplianceScope           `json:"scope"`
	Summary        ProfileComplianceSummary         `json:"summary"`
	Implementation *ProfileComplianceImplementation `json:"implementation,omitempty"`
	Groups         []ProfileComplianceGroup         `json:"groups"`
	Controls       []ProfileComplianceControl       `json:"controls"`
}

type ProfileComplianceScope struct {
	Type  string    `json:"type"`
	ID    uuid.UUID `json:"id"`
	Title string    `json:"title"`
}

type ProfileComplianceSummary struct {
	TotalControls    int  `json:"totalControls"`
	Satisfied        int  `json:"satisfied"`
	NotSatisfied     int  `json:"notSatisfied"`
	Unknown          int  `json:"unknown"`
	CompliancePct    int  `json:"compliancePercent"`
	AssessedPct      int  `json:"assessedPercent"`
	ImplementedTotal *int `json:"implementedControls,omitempty"`
}

type ProfileComplianceImplementation struct {
	ImplementedControls   int `json:"implementedControls"`
	ImplementationPct     int `json:"implementationPercent"`
	UnimplementedControls int `json:"unimplementedControls"`
}

type ProfileComplianceGroup struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	TotalControls int    `json:"totalControls"`
	Satisfied     int    `json:"satisfied"`
	NotSatisfied  int    `json:"notSatisfied"`
	Unknown       int    `json:"unknown"`
	CompliancePct int    `json:"compliancePercent"`
}

type ProfileComplianceControl struct {
	ControlID      string                         `json:"controlId"`
	CatalogID      uuid.UUID                      `json:"catalogId"`
	Title          string                         `json:"title"`
	GroupID        string                         `json:"groupId,omitempty"`
	GroupTitle     string                         `json:"groupTitle,omitempty"`
	Implemented    *bool                          `json:"implemented,omitempty"`
	StatusCounts   []ProfileComplianceStatusCount `json:"statusCounts"`
	ComputedStatus string                         `json:"computedStatus"`
}

type ProfileComplianceStatusCount struct {
	Count  int64  `json:"count"`
	Status string `json:"status"`
}

type profileControlKey struct {
	CatalogID uuid.UUID
	ControlID string
}

type profileComplianceControlScope struct {
	ControlID  string
	CatalogID  uuid.UUID
	Title      string
	GroupID    string
	GroupTitle string
}

type profileComplianceGroupAccumulator struct {
	ID            string
	Title         string
	TotalControls int
	Satisfied     int
	NotSatisfied  int
	Unknown       int
}

// ComplianceProgress godoc
//
//	@Summary		Get compliance progress for a Profile
//	@Description	Returns aggregated compliance progress for controls in a Profile, including summary, optional per-control rows, and group rollups.
//	@Tags			Profile
//	@Param			id				path	string	true	"Profile ID"
//	@Param			includeControls	query	bool	false	"Include per-control breakdown (default true)"
//	@Param			sspId			query	string	false	"System Security Plan ID for implementation coverage"
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[oscal.ProfileComplianceProgress]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/{id}/compliance-progress [get]
func (h *ProfileHandler) ComplianceProgress(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	includeControls := true
	includeControlsParam := strings.TrimSpace(ctx.QueryParam("includeControls"))
	if includeControlsParam != "" {
		parsed, parseErr := strconv.ParseBool(includeControlsParam)
		if parseErr != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(parseErr))
		}
		includeControls = parsed
	}

	profile, err := FindFullProfile(h.db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("error finding profile", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	catalog, err := GetControlCatalogFromBuiltProfile(profile, h.db)
	if err != nil {
		h.sugar.Errorw("error building control catalog", "id", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	scopeControls := flattenProfileComplianceControls(catalog)

	response := ProfileComplianceProgress{
		Scope: ProfileComplianceScope{
			Type:  "profile",
			ID:    id,
			Title: profile.Metadata.Title,
		},
		Summary: ProfileComplianceSummary{
			TotalControls: len(scopeControls),
		},
		Groups:   []ProfileComplianceGroup{},
		Controls: []ProfileComplianceControl{},
	}

	if len(scopeControls) == 0 {
		return ctx.JSON(http.StatusOK, handler.GenericDataResponse[ProfileComplianceProgress]{Data: response})
	}

	filtersByControl, err := h.loadFiltersByControl(scopeControls)
	if err != nil {
		h.sugar.Errorw("failed to load filters for profile controls", "profileID", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	sspImplementedControls := map[string]struct{}{}
	hasImplementationScope := false
	sspIDParam := strings.TrimSpace(ctx.QueryParam("sspId"))
	if sspIDParam != "" {
		sspID, parseErr := uuid.Parse(sspIDParam)
		if parseErr != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(parseErr))
		}

		sspImplementedControls, err = h.loadImplementedControlsForSSP(sspID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ctx.JSON(http.StatusNotFound, api.NewError(err))
			}
			h.sugar.Errorw("failed to load implemented requirements for SSP", "sspID", sspID, "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
		hasImplementationScope = true
	}

	groups := map[string]*profileComplianceGroupAccumulator{}
	controls := make([]ProfileComplianceControl, 0, len(scopeControls))

	satisfied := 0
	notSatisfied := 0
	unknown := 0
	implementedControls := 0

	for _, scopedControl := range scopeControls {
		controlKey := profileControlKey{CatalogID: scopedControl.CatalogID, ControlID: scopedControl.ControlID}
		statusCounts, statusErr := h.getStatusCountsForFilters(filtersByControl[controlKey])
		if statusErr != nil {
			h.sugar.Errorw("failed to compute status counts for control", "catalogID", scopedControl.CatalogID, "controlID", scopedControl.ControlID, "error", statusErr)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(statusErr))
		}

		computedStatus := computeProfileControlStatus(statusCounts)
		switch computedStatus {
		case "satisfied":
			satisfied++
		case "not-satisfied":
			notSatisfied++
		default:
			unknown++
		}

		if scopedControl.GroupID != "" {
			group, ok := groups[scopedControl.GroupID]
			if !ok {
				group = &profileComplianceGroupAccumulator{
					ID:    scopedControl.GroupID,
					Title: scopedControl.GroupTitle,
				}
				groups[scopedControl.GroupID] = group
			}
			group.TotalControls++
			switch computedStatus {
			case "satisfied":
				group.Satisfied++
			case "not-satisfied":
				group.NotSatisfied++
			default:
				group.Unknown++
			}
		}

		controlResponse := ProfileComplianceControl{
			ControlID:      scopedControl.ControlID,
			CatalogID:      scopedControl.CatalogID,
			Title:          scopedControl.Title,
			GroupID:        scopedControl.GroupID,
			GroupTitle:     scopedControl.GroupTitle,
			StatusCounts:   statusCounts,
			ComputedStatus: computedStatus,
		}

		if hasImplementationScope {
			implemented := false
			if _, ok := sspImplementedControls[scopedControl.ControlID]; ok {
				implemented = true
				implementedControls++
			}
			controlResponse.Implemented = &implemented
		}

		if includeControls {
			controls = append(controls, controlResponse)
		}
	}

	summary := ProfileComplianceSummary{
		TotalControls: len(scopeControls),
		Satisfied:     satisfied,
		NotSatisfied:  notSatisfied,
		Unknown:       unknown,
		CompliancePct: computePercent(satisfied, len(scopeControls)),
		AssessedPct:   computePercent(satisfied+notSatisfied, len(scopeControls)),
	}
	if hasImplementationScope {
		summary.ImplementedTotal = &implementedControls
	}
	response.Summary = summary

	groupResponse := make([]ProfileComplianceGroup, 0, len(groups))
	for _, group := range groups {
		groupResponse = append(groupResponse, ProfileComplianceGroup{
			ID:            group.ID,
			Title:         group.Title,
			TotalControls: group.TotalControls,
			Satisfied:     group.Satisfied,
			NotSatisfied:  group.NotSatisfied,
			Unknown:       group.Unknown,
			CompliancePct: computePercent(group.Satisfied, group.TotalControls),
		})
	}

	sort.Slice(groupResponse, func(i, j int) bool {
		if groupResponse[i].Title == groupResponse[j].Title {
			return groupResponse[i].ID < groupResponse[j].ID
		}
		return groupResponse[i].Title < groupResponse[j].Title
	})

	response.Groups = groupResponse

	if includeControls {
		sort.Slice(controls, func(i, j int) bool {
			if controls[i].GroupTitle == controls[j].GroupTitle {
				if controls[i].ControlID == controls[j].ControlID {
					return controls[i].CatalogID.String() < controls[j].CatalogID.String()
				}
				return controls[i].ControlID < controls[j].ControlID
			}
			return controls[i].GroupTitle < controls[j].GroupTitle
		})
		response.Controls = controls
	}

	if hasImplementationScope {
		response.Implementation = &ProfileComplianceImplementation{
			ImplementedControls:   implementedControls,
			ImplementationPct:     computePercent(implementedControls, len(scopeControls)),
			UnimplementedControls: len(scopeControls) - implementedControls,
		}
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[ProfileComplianceProgress]{Data: response})
}

func flattenProfileComplianceControls(catalog *relational.Catalog) []profileComplianceControlScope {
	if catalog == nil {
		return []profileComplianceControlScope{}
	}

	controlsByKey := map[profileControlKey]profileComplianceControlScope{}

	var collectControls func(controls []relational.Control, groupID, groupTitle string)
	collectControls = func(controls []relational.Control, groupID, groupTitle string) {
		for _, control := range controls {
			key := profileControlKey{CatalogID: control.CatalogID, ControlID: control.ID}
			if _, exists := controlsByKey[key]; !exists {
				controlsByKey[key] = profileComplianceControlScope{
					ControlID:  control.ID,
					CatalogID:  control.CatalogID,
					Title:      control.Title,
					GroupID:    groupID,
					GroupTitle: groupTitle,
				}
			}

			if len(control.Controls) > 0 {
				collectControls(control.Controls, groupID, groupTitle)
			}
		}
	}

	var collectGroups func(groups []relational.Group, rootGroupID, rootGroupTitle string)
	collectGroups = func(groups []relational.Group, rootGroupID, rootGroupTitle string) {
		for _, group := range groups {
			topGroupID := rootGroupID
			topGroupTitle := rootGroupTitle
			if topGroupID == "" {
				topGroupID = group.ID
				topGroupTitle = group.Title
			}

			collectControls(group.Controls, topGroupID, topGroupTitle)
			if len(group.Groups) > 0 {
				collectGroups(group.Groups, topGroupID, topGroupTitle)
			}
		}
	}

	collectControls(catalog.Controls, "", "")
	collectGroups(catalog.Groups, "", "")

	flattened := make([]profileComplianceControlScope, 0, len(controlsByKey))
	for _, control := range controlsByKey {
		flattened = append(flattened, control)
	}

	sort.Slice(flattened, func(i, j int) bool {
		if flattened[i].GroupTitle == flattened[j].GroupTitle {
			if flattened[i].ControlID == flattened[j].ControlID {
				return flattened[i].CatalogID.String() < flattened[j].CatalogID.String()
			}
			return flattened[i].ControlID < flattened[j].ControlID
		}
		return flattened[i].GroupTitle < flattened[j].GroupTitle
	})

	return flattened
}

func (h *ProfileHandler) loadFiltersByControl(scopeControls []profileComplianceControlScope) (map[profileControlKey][]labelfilter.Filter, error) {
	filtersByControl := make(map[profileControlKey][]labelfilter.Filter, len(scopeControls))
	if len(scopeControls) == 0 {
		return filtersByControl, nil
	}

	query := h.db.Model(&relational.Control{}).Preload("Filters")
	for idx, scopeControl := range scopeControls {
		condition := h.db.Where("catalog_id = ? AND id = ?", scopeControl.CatalogID, scopeControl.ControlID)
		if idx == 0 {
			query = query.Where(condition)
		} else {
			query = query.Or(condition)
		}
	}

	controls := []relational.Control{}
	if err := query.Find(&controls).Error; err != nil {
		return nil, err
	}

	for _, control := range controls {
		key := profileControlKey{CatalogID: control.CatalogID, ControlID: control.ID}
		filters := make([]labelfilter.Filter, 0, len(control.Filters))
		for _, filter := range control.Filters {
			filters = append(filters, filter.Filter.Data())
		}
		filtersByControl[key] = filters
	}

	return filtersByControl, nil
}

func (h *ProfileHandler) getStatusCountsForFilters(filters []labelfilter.Filter) ([]ProfileComplianceStatusCount, error) {
	if len(filters) == 0 {
		return []ProfileComplianceStatusCount{}, nil
	}

	latestQuery := h.db.Session(&gorm.Session{})
	latestQuery = relational.GetLatestEvidenceStreamsQuery(latestQuery)
	query, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, h.db, filters...)
	if err != nil {
		return nil, err
	}

	rows := []ProfileComplianceStatusCount{}
	if err := query.Model(&relational.Evidence{}).
		Select("count(*) as count, status->>'state' as status").
		Group("status->>'state'").
		Scan(&rows).Error; err != nil {
		return nil, err
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Status < rows[j].Status
	})

	return rows, nil
}

func (h *ProfileHandler) loadImplementedControlsForSSP(sspID uuid.UUID) (map[string]struct{}, error) {
	var ssp relational.SystemSecurityPlan
	if err := h.db.Preload("ControlImplementation.ImplementedRequirements").First(&ssp, "id = ?", sspID).Error; err != nil {
		return nil, err
	}

	implemented := make(map[string]struct{}, len(ssp.ControlImplementation.ImplementedRequirements))
	for _, requirement := range ssp.ControlImplementation.ImplementedRequirements {
		implemented[requirement.ControlId] = struct{}{}
	}

	return implemented, nil
}

func computeProfileControlStatus(rows []ProfileComplianceStatusCount) string {
	hasSatisfied := false
	for _, row := range rows {
		if row.Count <= 0 {
			continue
		}

		switch strings.ToLower(strings.TrimSpace(row.Status)) {
		case "not-satisfied":
			return "not-satisfied"
		case "satisfied":
			hasSatisfied = true
		}
	}

	if hasSatisfied {
		return "satisfied"
	}

	return "unknown"
}

func computePercent(part, total int) int {
	if total == 0 {
		return 0
	}

	return int(math.Round((float64(part) / float64(total)) * 100))
}
