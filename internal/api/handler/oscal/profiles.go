package oscal

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/defenseunicorns/go-oscal/src/pkg/versioning"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type ProfileHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
}

type rule struct {
	Name     string `json:"name"`
	Ns       string `json:"ns"`
	Operator string `json:"operator"` // equals | contains | regex | in
	Value    string `json:"value"`
}

func NewProfileHandler(sugar *zap.SugaredLogger, db *gorm.DB) *ProfileHandler {
	return &ProfileHandler{
		sugar: sugar,
		db:    db,
	}
}

func (h *ProfileHandler) Register(api *echo.Group) {
	api.GET("", h.List)
	api.POST("", h.Create)
	api.POST("/build-props", h.BuildByProps)
	api.GET("/:id", h.Get)
	api.GET("/:id/resolved", h.Resolved)

	api.GET("/:id/modify", h.GetModify)
	api.GET("/:id/back-matter", h.GetBackmatter)
	api.POST("/:id/resolve", h.Resolve)
	api.GET("/:id/full", h.GetFull)

	// imports
	api.GET("/:id/imports", h.ListImports)
	api.POST("/:id/imports/add", h.AddImport)
	api.GET("/:id/imports/:href", h.GetImport)
	api.PUT("/:id/imports/:href", h.UpdateImport)
	api.DELETE("/:id/imports/:href", h.DeleteImport)

	// merge
	api.GET("/:id/merge", h.GetMerge)
	api.PUT("/:id/merge", h.UpdateMerge)
}

// BuildByProps
//
//	@Summary		Build Profile by Control Props
//	@Description	Generates a Profile selecting controls from a catalog based on prop matching rules. Returns the created Profile and the matched control IDs.
//	@Tags			Profile
//	@Accept			json
//	@Produce		json
//	@Param			request	body		oscal.ProfileHandler.BuildByProps.request	true	"Prop matching request"
//	@Success		201		{object}	handler.GenericDataResponse[oscal.ProfileHandler.BuildByProps.response]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/build-props [post]
func (h *ProfileHandler) BuildByProps(ctx echo.Context) error {
	type request struct {
		CatalogID     string `json:"catalogId"`
		MatchStrategy string `json:"matchStrategy"` // all | any
		Rules         []rule `json:"rules"`
		Title         string `json:"title"`
		Version       string `json:"version"`
	}
	type response struct {
		ProfileID  uuid.UUID                `json:"profileId"`
		ControlIDs []string                 `json:"controlIds"`
		Profile    oscalTypes_1_1_3.Profile `json:"profile"`
	}
	var req request
	var raw map[string]any
	if err := json.NewDecoder(ctx.Request().Body).Decode(&raw); err != nil {
		h.sugar.Warnw("failed to decode BuildByProps request", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	// Accept both camelCase and kebab-case keys
	getStr := func(m map[string]any, keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				if s, ok := v.(string); ok {
					return s
				}
			}
		}
		return ""
	}
	req.CatalogID = getStr(raw, "catalogId", "catalog-id")
	req.MatchStrategy = getStr(raw, "matchStrategy", "match-strategy")
	req.Title = getStr(raw, "title")
	req.Version = getStr(raw, "version")
	if rv, ok := raw["rules"]; ok {
		if arr, ok := rv.([]any); ok {
			out := make([]rule, 0, len(arr))
			for _, it := range arr {
				if mm, ok := it.(map[string]any); ok {
					out = append(out, rule{
						Name:     getStr(mm, "name"),
						Ns:       getStr(mm, "ns"),
						Operator: getStr(mm, "operator"),
						Value:    getStr(mm, "value"),
					})
				}
			}
			req.Rules = out
		}
	}
	if req.CatalogID == "" || len(req.Rules) == 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("catalogId and rules are required")))
	}
	// filter out invalid rules (empty operator or value)
	validRules := make([]rule, 0, len(req.Rules))
	for _, r := range req.Rules {
		if strings.TrimSpace(r.Operator) != "" && strings.TrimSpace(r.Value) != "" {
			validRules = append(validRules, r)
		}
	}
	if len(validRules) == 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("rules must include non-empty operator and value")))
	}
	catUUID, err := uuid.Parse(req.CatalogID)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var controls []relational.Control
	if err := h.db.Where("catalog_id = ?", catUUID).Find(&controls).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("failed to list catalog controls", "catalogId", req.CatalogID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	matchAll := strings.ToLower(req.MatchStrategy) == "all"
	matched := make([]relational.Control, 0, len(controls))
	matchedIDs := make([]string, 0, len(controls))
	for i := range controls {
		if matchControlByProps(&controls[i], validRules, matchAll) {
			matched = append(matched, controls[i])
			matchedIDs = append(matchedIDs, controls[i].ID)
		}
	}
	now := time.Now()
	// build BackMatter resource and Import pointing to the catalog
	var catalog relational.Catalog
	if err := h.db.Preload("Metadata").First(&catalog, "id = ?", catUUID).Error; err != nil {
		h.sugar.Warnw("failed to load catalog metadata", "catalogId", req.CatalogID, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	resourceUUID := uuid.New()
	title := catalog.Metadata.Title
	resource := relational.BackMatterResource{
		ID:    resourceUUID,
		Title: &title,
		RLinks: []relational.ResourceLink{
			{
				Href:      "#" + req.CatalogID,
				MediaType: "application/ccf+oscal+json",
			},
		},
	}
	includeGroup := relational.SelectControlById{
		WithChildControls: "",
		WithIds:           datatypes.NewJSONSlice(matchedIDs),
	}
	newImport := relational.Import{
		Href: "#" + resourceUUID.String(),
	}
	profile := &relational.Profile{
		Metadata: relational.Metadata{
			Title:        req.Title,
			Version:      req.Version,
			OscalVersion: versioning.GetLatestSupportedVersion(),
			LastModified: &now,
		},
		Controls: matched,
	}
	if err := h.db.Create(profile).Error; err != nil {
		h.sugar.Errorw("failed to create profile from props", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	// Persist BackMatter and resource under this profile
	parentID := profile.ID.String()
	parentType := "profiles"
	bmRecord := &relational.BackMatter{
		ParentID:   &parentID,
		ParentType: &parentType,
	}
	if err := h.db.Create(bmRecord).Error; err != nil {
		h.sugar.Errorw("failed to create backmatter for profile", "profileId", profile.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if bmRecord.ID != nil {
		resource.BackMatterID = *bmRecord.ID
	}
	if err := h.db.Create(&resource).Error; err != nil {
		h.sugar.Errorw("failed to create backmatter resource", "profileId", profile.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	// Persist import and include-controls
	newImport.ProfileID = *profile.ID
	if err := h.db.Create(&newImport).Error; err != nil {
		h.sugar.Errorw("failed to create import", "profileId", profile.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if len(matchedIDs) > 0 && newImport.ID != nil {
		includeGroup.ParentID = *newImport.ID
		includeGroup.ParentType = "included"
		if err := h.db.Create(&includeGroup).Error; err != nil {
			h.sugar.Errorw("failed to create include-controls", "profileId", profile.ID, "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}
	if _, err := SyncProfileControls(h.db, *profile.ID); err != nil {
		h.sugar.Errorw("failed to sync profile controls", "profileId", profile.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	// Reload full profile with associations for response
	fullProfile, err := FindFullProfile(h.db, *profile.ID)
	if err != nil {
		h.sugar.Errorw("failed to reload full profile", "profileId", profile.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	oscalProfile := fullProfile.MarshalOscal()
	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[response]{
		Data: response{
			ProfileID:  *profile.ID,
			ControlIDs: matchedIDs,
			Profile:    *oscalProfile,
		},
	})
}

func matchControlByProps(ctl *relational.Control, rules []rule, matchAll bool) bool {
	if len(rules) == 0 {
		return false
	}
	eval := func(r rule, p relational.Prop) bool {
		if r.Name != "" && strings.ToLower(r.Name) != strings.ToLower(p.Name) {
			return false
		}
		if r.Ns != "" && strings.ToLower(r.Ns) != strings.ToLower(p.Ns) {
			return false
		}
		switch strings.ToLower(r.Operator) {
		case "equals":
			return strings.EqualFold(p.Value, r.Value)
		case "contains":
			return strings.Contains(strings.ToLower(p.Value), strings.ToLower(r.Value))
		case "regex":
			m, _ := func() (bool, error) {
				// simple regex match
				re, err := regexp.Compile(r.Value)
				if err != nil {
					return false, err
				}
				return re.MatchString(p.Value), nil
			}()
			return m
		case "in":
			parts := strings.Split(r.Value, ",")
			for _, v := range parts {
				if strings.EqualFold(strings.TrimSpace(v), p.Value) {
					return true
				}
			}
			return false
		default:
			return false
		}
	}
	matchedCount := 0
	for _, rule := range rules {
		ruleMatched := false
		for _, prop := range ctl.Props {
			if eval(rule, prop) {
				ruleMatched = true
				break
			}
		}
		if matchAll && !ruleMatched {
			return false
		}
		if !matchAll && ruleMatched {
			return true
		}
		if ruleMatched {
			matchedCount++
		}
	}
	return matchAll && matchedCount == len(rules)
}

// List godoc
//
//	@Summary		List Profiles
//	@Description	Retrieves all OSCAL profiles
//	@Tags			Profile
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[oscal.ProfileHandler.List.response]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles [get]
func (h *ProfileHandler) List(ctx echo.Context) error {
	type response struct {
		UUID     uuid.UUID                 `json:"uuid"`
		Metadata oscalTypes_1_1_3.Metadata `json:"metadata"`
	}

	var profiles []relational.Profile
	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Preload("Metadata.Roles").
		Find(&profiles).Error; err != nil {
		h.sugar.Errorw("error listing profiles", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	respProfiles := make([]response, len(profiles))
	for i, profile := range profiles {
		respProfiles[i] = response{
			UUID:     *profile.ID,
			Metadata: *profile.Metadata.MarshalOscal(),
		}
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[response]{Data: respProfiles})
}

// Get godoc
//
//	@Summary		Get Profile
//	@Description	Get an OSCAL profile with the uuid provided
//	@Tags			Profile
//	@Param			id	path	string	true	"Profile ID"
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[oscal.ProfileHandler.Get.response]
//	@Failure		404	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/{id} [get]
func (h *ProfileHandler) Get(ctx echo.Context) error {
	type response struct {
		UUID     uuid.UUID                 `json:"uuid"`
		Metadata oscalTypes_1_1_3.Metadata `json:"metadata"`
	}

	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var profile relational.Profile
	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Where("id = ?", id).
		First(&profile).Error; err != nil {
		h.sugar.Warnw("error getting profile", "id", idParam, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	responseProfile := response{
		UUID:     *profile.ID,
		Metadata: *profile.Metadata.MarshalOscal(),
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[response]{Data: responseProfile})
}

// Resolved godoc
//
//	@Summary		Get Resolved Profile
//	@Description	Returns a resolved OSCAL catalog based on a given Profile ID, applying all imports and modifications.
//	@Tags			Profile
//	@Param			id	path	string	true	"Profile ID"
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Catalog]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/{id}/resolved [get]
func (h *ProfileHandler) Resolved(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
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
	// Catalog ID just for showing - not a real catalog
	uid := uuid.New()
	catalog.ID = &uid
	if err != nil {
		h.sugar.Errorw("error building control catalog", "id", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	catalog.Metadata = profile.Metadata
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Catalog]{Data: *catalog.MarshalOscal()})
}

// ListImports godoc
//
//	@Summary		List Imports
//	@Description	List imports for a specific profile
//	@Tags			Profile
//	@Param			id	path	string	true	"Profile ID"
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[oscalTypes_1_1_3.Import]
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/{id}/imports [get]
func (h *ProfileHandler) ListImports(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var profile relational.Profile
	if err := h.db.
		Preload("Imports").Preload("Imports.IncludeControls").Preload("Imports.ExcludeControls").
		Where("id = ?", id).First(&profile).Error; err != nil {
		h.sugar.Warnw("error listing imports", "id", idParam, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	imports := make([]oscalTypes_1_1_3.Import, len(profile.Imports))
	for i, imp := range profile.Imports {
		imports[i] = imp.MarshalOscal()
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[oscalTypes_1_1_3.Import]{Data: imports})
}

// GetImport godoc
//
//	@Summary		Get Import from Profile by Backmatter Href
//	@Description	Retrieves a specific import from a profile by its backmatter href
//	@Tags			Profile
//	@Param			id		path	string	true	"Profile UUID"
//	@Param			href	path	string	true	"Import Href"
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Import]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/{id}/imports/{href} [get]
func (h *ProfileHandler) GetImport(ctx echo.Context) error {
	profileId := ctx.Param("id")
	importHref := ctx.Param("href")

	id, err := uuid.Parse(profileId)

	if err != nil {
		h.sugar.Warnw("error parsing UUID", "id", profileId, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var profileImport relational.Import
	if err := h.db.Preload("IncludeControls").Preload("ExcludeControls").First(&profileImport, "profile_id = ? AND href = ?", id, importHref).Error; err != nil {
		h.sugar.Warnw("error getting import", "profile_id", profileId, "href", importHref, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalImport := profileImport.MarshalOscal()
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Import]{Data: oscalImport})
}

// AddImport godoc
//
//	@Summary		Add Import to Profile
//	@Description	Adds an import to a profile by its UUID and type (catalog/profile). Only catalogs are currently supported currently
//	@Tags			Profile
//	@Param			id	path	string	true	"Profile ID"
//	@Accept			json
//	@Produce		json
//	@Param			request	body		oscal.ProfileHandler.AddImport.request	true	"Request data"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Import]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		409		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/{id}/imports/add [post]
func (h *ProfileHandler) AddImport(ctx echo.Context) error {
	type request struct {
		Type string `json:"type"` // catalog / profile
		UUID string `json:"uuid"`
	}

	reqData := &request{}
	if err := ctx.Bind(reqData); err != nil {
		h.sugar.Warnw("error binding request data", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if reqData.Type != "catalog" && reqData.Type != "profile" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("type must be either 'catalog' or 'profile'")))
	}

	// Add error message for unimplemented type 'profile'
	if reqData.Type == "profile" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("profile is not implemented yet, use catalog instead")))
	}

	profileId := ctx.Param("id")
	id, err := uuid.Parse(profileId)
	if err != nil {
		h.sugar.Warnw("error parsing UUID", "id", profileId, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var profile relational.Profile
	if err := h.db.Preload("BackMatter").
		Preload("BackMatter.Resources").
		First(&profile, "id = ?", id).Error; err != nil {
		h.sugar.Warnw("error getting profile", "id", profileId, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	idFragment := "#" + reqData.UUID
	found := importExistsInProfile(&profile, idFragment)

	if found {
		return ctx.JSON(http.StatusConflict, api.NewError(errors.New("import already exists")))
	}

	var catalog relational.Catalog
	if err := h.db.Preload("Metadata").First(&catalog, "id = ?", reqData.UUID).Error; err != nil {
		h.sugar.Warnw("error getting catalog", "id", reqData.UUID, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	resourceUUID := uuid.New()
	resource := relational.BackMatterResource{
		ID:    resourceUUID,
		Title: &catalog.Metadata.Title,
		RLinks: []relational.ResourceLink{
			{
				Href:      idFragment,
				MediaType: "application/ccf+oscal+json",
			},
		},
	}

	newImport := relational.Import{
		Href: fmt.Sprintf("#%s", resourceUUID.String()),
	}

	profile.BackMatter.Resources = append(profile.BackMatter.Resources, resource)
	profile.Imports = append(profile.Imports, newImport)

	if err := h.db.Save(&profile).Error; err != nil {
		h.sugar.Errorw("error saving profile with new import", "id", profileId, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Import]{Data: newImport.MarshalOscal()})
}

// UpdateImport godoc
//
//	@Summary		Update Import in Profile
//	@Description	Updates an existing import in a profile by its href
//	@Tags			Profile
//	@Param			id		path	string	true	"Profile ID"
//	@Param			href	path	string	true	"Import Href"
//	@Accept			json
//	@Produce		json
//	@Param			request	body		oscalTypes_1_1_3.Import	true	"Import data to update"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Import]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/{id}/imports/{href} [put]
func (h *ProfileHandler) UpdateImport(ctx echo.Context) error {
	profileId := ctx.Param("id")
	id, err := uuid.Parse(profileId)
	if err != nil {
		h.sugar.Warnw("error parsing UUID", "id", profileId, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	href := ctx.Param("href")
	if href == "" {
		h.sugar.Warnw("empty href parameter", "profile_id", profileId)
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("href parameter is required")))
	}

	var profileImport relational.Import
	if err := h.db.Preload("IncludeControls").Preload("ExcludeControls").First(&profileImport, "profile_id = ? AND href = ?", id, href).Error; err != nil {
		h.sugar.Warnw("error getting import", "profile_id", profileId, "href", href, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var updateData oscalTypes_1_1_3.Import
	if err := ctx.Bind(&updateData); err != nil {
		h.sugar.Warnw("error binding update data", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	if updateData.Href != href {
		h.sugar.Warnw("href mismatch", "expected", href, "received", updateData.Href)
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("href in request body does not match URL parameter")))
	}

	updatedImport := relational.Import{}
	updatedImport.UnmarshalOscal(updateData)
	updatedImport.ID = profileImport.ID
	updatedImport.ProfileID = profileImport.ProfileID

	// Overwrite associations: update the import and remove all other associations for this import
	if err := h.db.Model(&profileImport).Association("IncludeControls").Replace(updatedImport.IncludeControls); err != nil {
		h.sugar.Errorw("error updating IncludeControls association", "profile_id", profileId, "href", href, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if err := h.db.Model(&profileImport).Association("ExcludeControls").Replace(updatedImport.ExcludeControls); err != nil {
		h.sugar.Errorw("error updating ExcludeControls association", "profile_id", profileId, "href", href, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Save the updated import itself
	if err := h.db.Model(&profileImport).Updates(updatedImport).Error; err != nil {
		h.sugar.Errorw("error updating import", "profile_id", profileId, "href", href, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Sync ProfileControl pivot table synchronously so errors can be reported to the client
	if _, err := SyncProfileControls(h.db, id); err != nil {
		h.sugar.Errorw("Failed to sync profile controls after import update", "profileId", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalImport := updatedImport.MarshalOscal()
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Import]{Data: oscalImport})
}

// DeleteImport godoc
//
//	@Summary		Delete Import from Profile
//	@Description	Deletes an import from a profile by its href
//	@Tags			Profile
//	@Param			id		path	string	true	"Profile ID"
//	@Param			href	path	string	true	"Import Href"
//	@Produce		json
//	@Success		204	"Import deleted successfully"
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/{id}/imports/{href} [delete]
func (h *ProfileHandler) DeleteImport(ctx echo.Context) error {
	profileId := ctx.Param("id")
	href := ctx.Param("href")

	id, err := uuid.Parse(profileId)
	if err != nil {
		h.sugar.Warnw("error parsing UUID", "id", profileId, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var profileImport relational.Import
	if err := h.db.First(&profileImport, "profile_id = ? AND href = ?", id, href).Error; err != nil {
		h.sugar.Warnw("error getting import", "profile_id", profileId, "href", href, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Remove associations first
	if err := h.db.Model(&profileImport).Association("IncludeControls").Clear(); err != nil {
		h.sugar.Errorw("error clearing IncludeControls association", "profile_id", profileId, "href", href, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if err := h.db.Model(&profileImport).Association("ExcludeControls").Clear(); err != nil {
		h.sugar.Errorw("error clearing ExcludeControls association", "profile_id", profileId, "href", href, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	referenceUUID := strings.TrimPrefix(profileImport.Href, "#")
	var resourceToDelete relational.BackMatterResource
	if err := h.db.Where("id = ?", referenceUUID).First(&resourceToDelete).Error; err != nil {
		h.sugar.Errorw("error finding resource to delete", "profile_id", profileId, "href", href, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Delete the resource from the backmatter
	if err := h.db.Delete(&resourceToDelete).Error; err != nil {
		h.sugar.Errorw("error deleting resource", "profile_id", profileId, "href", href, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err := h.db.Delete(&profileImport).Error; err != nil {
		h.sugar.Errorw("error deleting import", "profile_id", profileId, "href", href, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Sync ProfileControl pivot table synchronously so that errors can be surfaced to the client
	if _, err := SyncProfileControls(h.db, id); err != nil {
		h.sugar.Errorw("Failed to sync profile controls after import deletion", "profile_id", profileId, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetMerge godoc
//
//	@Summary		Get merge section
//	@Description	Retrieves the merge section for a specific profile.
//	@Tags			Profile
//	@Param			id	path	string	true	"Profile ID"
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Merge]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/{id}/merge [get]
func (h *ProfileHandler) GetMerge(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var profile relational.Profile
	if err := h.db.
		Preload("Merge").
		Where("id = ?", id).
		First(&profile).Error; err != nil {
		h.sugar.Warnw("error getting profile", "id", idParam, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Merge]{Data: *profile.Merge.MarshalOscal()})
}

// UpdateMerge godoc
//
//	@Summary		Update Merge
//	@Description	Updates the merge information for a specific profile
//	@Tags			Profile
//	@Param			id	path	string	true	"Profile ID"
//	@Accept			json
//	@Produce		json
//	@Param			request	body		oscalTypes_1_1_3.Merge	true	"Merge data to update"
//	@Success		200		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Merge]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/{id}/merge [put]
func (h *ProfileHandler) UpdateMerge(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var profile relational.Profile
	if err := h.db.Where("id = ?", id).First(&profile).Error; err != nil {
		h.sugar.Warnw("error getting profile", "id", idParam, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var payload oscalTypes_1_1_3.Merge
	if err := ctx.Bind(&payload); err != nil {
		h.sugar.Errorw("error binding request data", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var relationalMerge relational.Merge
	if err := h.db.Where("profile_id = ?", id).First(&relationalMerge).Error; err != nil {
		h.sugar.Warnw("error finding merge", "id", idParam, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			h.sugar.Infow("merge not found, creating new one", "id", idParam)
			relationalMerge = relational.Merge{
				ProfileID: id,
			}
			if err = h.db.Create(&relationalMerge).Error; err != nil {
				h.sugar.Errorw("error creating merge", "id", idParam, "error", err)
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
		} else {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}

	}

	relationalPayload := relational.Merge{}
	relationalPayload.UnmarshalOscal(payload)

	relationalMerge.AsIs = relationalPayload.AsIs
	relationalMerge.Combine = relationalPayload.Combine
	relationalMerge.Flat = relationalPayload.Flat

	if err := h.db.Save(&relationalMerge).Error; err != nil {
		h.sugar.Errorw("error saving merge", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Sync ProfileControl pivot table synchronously to ensure completion before responding
	if _, err := SyncProfileControls(h.db, id); err != nil {
		h.sugar.Warnw("Failed to sync profile controls after merge update", "profileId", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	outputOscal := relationalMerge.MarshalOscal()
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Merge]{Data: *outputOscal})

}

// GetBackmatter godoc
//
//	@Summary		Get Backmatter
//	@Description	Get the BackMatter for a specific profile
//	@Tags			Profile
//	@Param			id	path	string	true	"Profile ID"
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/{id}/back-matter [get]
func (h *ProfileHandler) GetBackmatter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var profile relational.Profile

	if err := h.db.Preload("BackMatter").Preload("BackMatter.Resources").Where("id = ?", id).First(&profile).Error; err != nil {
		h.sugar.Warnw("error getting profile", "id", idParam, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	oscalBackmatter := *profile.BackMatter.MarshalOscal()
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.BackMatter]{Data: oscalBackmatter})
}

// Resolve godoc
//
//	@Summary		Resolves a Profile as a stored catalog
//	@Description	Resolves a Profiled identified by the "profile ID" param and stores a new catalog in the database
//	@Tags			Profile
//	@Param			id	path	string	true	"Profile ID"
//	@Produce		json
//	@Success		201	{object}	handler.GenericDataResponse[oscal.ProfileHandler.Resolve.response]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/{id}/resolve [post]
func (h *ProfileHandler) Resolve(ctx echo.Context) error {
	type response struct {
		ID string `json:"id"`
	}
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	profile, err := FindFullProfile(h.db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("error finding profile", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	newID, _ := uuid.NewUUID()
	catalog := relational.Catalog{
		UUIDModel: relational.UUIDModel{
			ID: &newID,
		},
	}

	// TODO[gusfcarvalho] - I don't even believe this method is needed / used everywhere.
	// These updates are just to make sure this method still works correctly
	// We might want to deprecate this entire method eventually

	catalogUUids, allControls, err := ResolveControls(profile, h.db)
	if err != nil {
		h.sugar.Errorw("error resolving catalog controls", "profile", profile, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	updateCatalogID(allControls, newID)
	now := time.Now()

	catalog.Metadata = profile.Metadata
	catalog.Metadata.UUIDModel = relational.UUIDModel{}
	catalog.Metadata.LastModified = &now

	generatedProps := []relational.Prop{
		{
			Name:  "generated_profile_title",
			Value: profile.Metadata.Title,
		},
		{
			Name:  "generated_profile_uuid",
			Value: idParam,
		},
	}
	catalog.Metadata.Props = append(catalog.Metadata.Props, generatedProps...)

	catalog.Controls = append(catalog.Controls, allControls...)

	backmatters, err := GetCatalogBackmatter(h.db, catalogUUids)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("error resolving catalog backmatters", "id", idParam, "catalog_uuids", catalogUUids, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	catalog.BackMatter = CombineBackmatter(backmatters)

	if err := h.db.Save(&catalog).Error; err != nil {
		h.sugar.Errorw("error saving new catalog to database", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	resp := response{
		ID: catalog.ID.String(),
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[response]{Data: resp})
}

func updateCatalogID(controls []relational.Control, newCatalogID uuid.UUID) []relational.Control {

	for i := range controls {
		controls[i].CatalogID = newCatalogID
	}
	return controls
}

// Create godoc
//
//	@Summary		Create a new OSCAL Profile
//	@Description	Creates a new OSCAL Profile.
//	@Tags			Profile
//	@Accept			json
//	@Produce		json
//	@Param			profile	body		oscalTypes_1_1_3.Profile	true	"Profile object"
//	@Success		201		{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Profile]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles [post]
func (h *ProfileHandler) Create(ctx echo.Context) error {
	now := time.Now()

	var oscalProfile oscalTypes_1_1_3.Profile
	if err := ctx.Bind(&oscalProfile); err != nil {
		h.sugar.Warnw("error binding profile", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	profileRel := &relational.Profile{}
	profileRel.UnmarshalOscal(oscalProfile)
	profileRel.Metadata.LastModified = &now
	profileRel.Metadata.OscalVersion = versioning.GetLatestSupportedVersion()

	if profileRel.Modify == nil {
		profileRel.Modify = &relational.Modify{}
	}

	if profileRel.Merge == nil {
		profileRel.Merge = &relational.Merge{}
	}

	if err := h.db.Create(profileRel).Error; err != nil {
		h.sugar.Errorw("error creating profile", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Sync ProfileControl pivot table synchronously so errors can be reported to the client
	if _, err := SyncProfileControls(h.db, *profileRel.ID); err != nil {
		h.sugar.Errorw("error syncing profile controls after creation", "profileId", profileRel.ID, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Profile]{Data: *profileRel.MarshalOscal()})
}

// GetFull godoc
//
//	@Summary		Get full Profile
//	@Description	Retrieves the full OSCAL Profile, including all nested content.
//	@Tags			Profile
//	@Produce		json
//	@Param			id	path		string	true	"Profile ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Profile]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/{id}/full [get]
func (h *ProfileHandler) GetFull(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Errorw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	profile, err := FindFullProfile(h.db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Errorw("error finding profile", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Profile]{Data: *profile.MarshalOscal()})
}

// GetModify godoc
//
//	@Summary		Get modify section
//	@Description	Retrieves the modify section for a specific profile.
//	@Tags			Profile
//	@Param			id	path	string	true	"Profile ID"
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[oscalTypes_1_1_3.Modify]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/profiles/{id}/modify [get]
func (h *ProfileHandler) GetModify(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var profile relational.Profile
	if err := h.db.
		Preload("Modify").
		Preload("Modify.SetParameters").
		Preload("Modify.Alters").
		Preload("Modify.Alters.Adds").
		Where("id = ?", id).
		First(&profile).Error; err != nil {
		h.sugar.Warnw("error getting profile", "id", idParam, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Modify]{Data: *profile.Modify.MarshalOscal()})
}

// Helper functions
// CombineBackmatter merges multiple BackMatter slices into a single BackMatter by concatenating all resources.
func CombineBackmatter(backmatters *[]relational.BackMatter) *relational.BackMatter {
	backmatter := relational.BackMatter{}
	for _, data := range *backmatters {
		resources := make([]relational.BackMatterResource, len(data.Resources))
		for i, resource := range data.Resources {
			var newResource relational.BackMatterResource
			newResource.UnmarshalOscal(*resource.MarshalOscal())
			resources[i] = resource
		}
		backmatter.Resources = append(backmatter.Resources, resources...)
	}
	return &backmatter
}

// GetCatalogBackmatter retrieves back matter records for the given catalog UUIDs,
// preloading associated resources from the database.
func GetCatalogBackmatter(db *gorm.DB, uuids []uuid.UUID) (*[]relational.BackMatter, error) {
	var backmatters *[]relational.BackMatter
	if err := db.Preload("Resources").Find(&backmatters, "parent_id IN ? AND parent_type = 'catalogs'", uuids).Error; err != nil {
		return nil, err
	}
	return backmatters, nil
}

// CollectControlIDs recursively extracts control IDs and their CatalogIDs from a list of controls
func CollectControlIDs(controls []relational.Control, controlsMap map[string]uuid.UUID) {
	for _, ctrl := range controls {
		controlsMap[ctrl.ID] = ctrl.CatalogID
		if len(ctrl.Controls) > 0 {
			CollectControlIDs(ctrl.Controls, controlsMap)
		}
	}
}

// CollectControlIDsFromGroups recursively extracts control IDs and their CatalogIDs from groups
func CollectControlIDsFromGroups(groups []relational.Group, controlsMap map[string]uuid.UUID) {
	for _, group := range groups {
		CollectControlIDs(group.Controls, controlsMap)
		if len(group.Groups) > 0 {
			CollectControlIDsFromGroups(group.Groups, controlsMap)
		}
	}
}

// GetControlIDsMapFromProfile resolves a profile and returns a map of control IDs to their CatalogIDs.
func GetControlIDsMapFromProfile(profile *relational.Profile, db *gorm.DB) (map[string]uuid.UUID, error) {
	catalog, err := BuildControlCatalogForProfile(profile, db)
	if err != nil {
		return nil, err
	}

	idsMap := make(map[string]uuid.UUID)
	CollectControlIDs(catalog.Controls, idsMap)
	CollectControlIDsFromGroups(catalog.Groups, idsMap)

	return idsMap, nil
}

// SyncProfileControls resolves all controls for a profile and updates the ProfileControl pivot table.
func SyncProfileControls(db *gorm.DB, profileID uuid.UUID) ([]string, error) {
	profile, err := FindFullProfile(db, profileID)
	if err != nil {
		return nil, err
	}

	// Capture the modification time to detect concurrent changes
	originalLastModified := profile.Metadata.LastModified

	idsMap, err := GetControlIDsMapFromProfile(profile, db)
	if err != nil {
		return nil, err
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		var currentProfile relational.Profile
		// Preload Metadata to check LastModified
		if err := tx.Preload("Metadata").First(&currentProfile, "id = ?", profileID).Error; err != nil {
			return err
		}

		// Safety check: If the profile has been modified since we started resolution, abort.
		// This prevents older background resolutions from overwriting newer ones.
		if originalLastModified != nil && currentProfile.Metadata.LastModified != nil {
			if currentProfile.Metadata.LastModified.After(*originalLastModified) {
				return fmt.Errorf("profile was modified during resolution; skipping stale sync")
			}
		}

		controls := []relational.Control{}
		for id, catalogID := range idsMap {
			controls = append(controls, relational.Control{ID: id, CatalogID: catalogID})
		}

		// Use GORM Association API to sync the many-to-many relationship
		if err := tx.Model(&currentProfile).Association("Controls").Replace(controls); err != nil {
			return err
		}

		return nil
	})
	controlIDs := make([]string, 0, len(idsMap))
	for id := range idsMap {
		controlIDs = append(controlIDs, id)
	}
	return controlIDs, err
}

// findPartRecursive performs a depth-first search through a slice of Parts
// to locate a Part with the specified targetID, returning a pointer or nil if not found.
func findPartRecursive(parts []relational.Part, targetID string) *relational.Part {
	for i := range parts {
		if parts[i].ID == targetID {
			return &parts[i]
		}
		if strings.HasPrefix(targetID, parts[i].ID) {
			if p := findPartRecursive(parts[i].Parts, targetID); p != nil {
				return p
			}
		}
	}
	return nil
}

// buildSetParams creates a map from parameter IDs to their settings for quick lookup.
func buildSetParams(settings []relational.ParameterSetting) map[string]relational.ParameterSetting {
	m := make(map[string]relational.ParameterSetting, len(settings))
	for _, s := range settings {
		m[s.ParamID] = s
	}
	return m
}

// buildAdditions groups all Alteration additions by control ID into a map for efficient access.
func buildAdditions(alters []relational.Alteration) map[string][]relational.Addition {
	m := make(map[string][]relational.Addition)
	for _, alt := range alters {
		m[alt.ControlID] = alt.Adds
	}
	return m
}

// applySetParameters updates the Params slice of a control based on provided ParameterSetting constraints.
func applySetParameters(ctrl relational.Control, setParams map[string]relational.ParameterSetting) relational.Control {
	for i, param := range ctrl.Params {
		if sp, ok := setParams[param.ID]; ok {
			param.Constraints = sp.Constraints
			ctrl.Params[i] = param
		}
	}
	return ctrl
}

// applyAdditions applies a list of additions to a control and its nested parts, modifying titles, props, params, links, and parts.
func applyAdditions(ctrl relational.Control, additions []relational.Addition) relational.Control {
	for _, addition := range additions {
		if ctrl.ID == addition.ByID {
			switch addition.Position {
			case "starting":
			case "ending":
				applyAdditionsToControl(&ctrl, addition, addition.Position)
			case "before": // nolint:SA9003
			case "after": // nolint:SA9003
				// TODO - inject the addition either before or after the current id
			}
		} else if part := findPartRecursive(ctrl.Parts, addition.ByID); part != nil {
			switch addition.Position {
			case "starting":
			case "ending":
				applyAdditionsToPart(part, addition, addition.Position)
			case "before": // nolint:SA9003
			case "after": // nolint:SA9003
				// TODO - inject the addition either before or after the current id
			}
		}
	}
	return ctrl
}

// applyAdditionsToPart applies a single Addition to the specified Part at the given position ("starting" or "ending"),
// recursively descending into its child parts.
func applyAdditionsToPart(part *relational.Part, addition relational.Addition, position string) {
	if addition.Title != "" {
		part.Title = addition.Title
	}
	if addition.Props != nil {
		switch position {
		case "starting":
			part.Props = append(addition.Props, part.Props...)
		case "ending":
			part.Props = append(part.Props, addition.Props...)
		}
	}
	if addition.Links != nil {
		switch position {
		case "starting":
			part.Links = append(addition.Links, part.Links...)
		case "ending":
			part.Links = append(part.Links, addition.Links...)
		}
	}
	if addition.Parts != nil {
		switch position {
		case "starting":
			part.Parts = append(addition.Parts, part.Parts...)
		case "ending":
			part.Parts = append(part.Parts, addition.Parts...)
		}
	}
}

// applyAdditionsToControl applies a single Addition to the specified Control at the given position,
// then recurses into its Parts to apply the same addition where needed.
func applyAdditionsToControl(ctrl *relational.Control, addition relational.Addition, position string) {
	if addition.Title != "" {
		ctrl.Title = addition.Title
	}
	if addition.Props != nil {
		switch position {
		case "starting":
		case "ending":
			ctrl.Props = append(addition.Props, ctrl.Props...)
		}
	}
	if addition.Params != nil {
		switch position {
		case "starting":
		case "ending":
			ctrl.Params = append(addition.Params, ctrl.Params...)
		}
	}
	if addition.Links != nil {
		switch position {
		case "starting":
		case "ending":
			ctrl.Links = append(addition.Links, ctrl.Links...)
		}
	}
	if addition.Parts != nil {
		switch position {
		case "starting":
		case "ending":
			ctrl.Parts = append(addition.Parts, ctrl.Parts...)
		}
	}
}

// processImport loads controls of a given import from the database, applies parameter settings and additions,
// and returns the catalog UUID along with the modified controls.
func processImport(db *gorm.DB, profile *relational.Profile, imp relational.Import, setParams map[string]relational.ParameterSetting, additions map[string][]relational.Addition) (*uuid.UUID, []relational.Control, error) {
	ids := GatherControlIds(imp)
	catalogID, err := FindOscalCatalogFromBackMatter(profile, imp.Href)
	if err != nil {
		return nil, nil, err
	}

	var controls []relational.Control
	if err := db.Preload("Controls").Preload("Controls.Controls").Find(&controls, "catalog_id = ? AND id IN ?", catalogID, ids).Error; err != nil {
		return nil, nil, err
	}

	newControls := make([]relational.Control, len(controls))

	for i := range controls {
		ctrl := relational.Control{}

		ctrl.UnmarshalOscal(*controls[i].MarshalOscal(), controls[i].CatalogID)
		ctrl.ParentID = controls[i].ParentID
		ctrl.ParentType = controls[i].ParentType

		ctrl = applySetParameters(ctrl, setParams)
		if list, ok := additions[controls[i].ID]; ok {
			ctrl = applyAdditions(ctrl, list)
		}
		newControls[i] = ctrl
	}
	return &catalogID, newControls, nil
}

func rollUpToRootControl(db *gorm.DB, control relational.Control) (relational.Control, error) {
	if control.ParentType == nil {
		return control, nil
	}

	tx := db.Session(&gorm.Session{})
	if *control.ParentType == "controls" {
		parent := relational.Control{}
		if err := tx.First(&parent, "id = ?", control.ParentID).Error; err != nil {
			return control, err
		}
		parent.Controls = append(parent.Controls, control)
		return rollUpToRootControl(tx, parent)
	}

	return control, nil
}

func rollUpToRootGroup(db *gorm.DB, group relational.Group) (relational.Group, error) {
	if group.ParentType == nil {
		return group, nil
	}

	tx := db.Session(&gorm.Session{})
	if *group.ParentType == "groups" {
		parent := relational.Group{}
		if err := tx.First(&parent, "id = ?", *group.ParentID).Error; err != nil {
			return group, err
		}
		parent.Groups = append(parent.Groups, group)
		return rollUpToRootGroup(tx, parent)
	}

	return group, nil
}

func mergeControls(controls ...relational.Control) []relational.Control {
	mapped := map[string]relational.Control{}
	for _, control := range controls {
		if sub, ok := mapped[control.ID]; ok {
			control.Controls = append(control.Controls, sub.Controls...)
		}

		control.Controls = mergeControls(control.Controls...)
		mapped[control.ID] = control
	}

	flattened := []relational.Control{}
	for _, control := range mapped {
		flattened = append(flattened, control)
	}
	return flattened
}

func mergeGroups(groups ...relational.Group) []relational.Group {
	mapped := map[string]relational.Group{}
	for _, group := range groups {
		if sub, ok := mapped[group.ID]; ok {
			group.Groups = append(group.Groups, sub.Groups...)
			group.Controls = append(group.Controls, sub.Controls...)
		}

		group.Controls = mergeControls(group.Controls...)
		group.Groups = mergeGroups(group.Groups...)
		mapped[group.ID] = group
	}
	flattened := []relational.Group{}
	for _, group := range mapped {
		flattened = append(flattened, group)
	}
	return flattened
}
func rollUpControlsToCatalog(db *gorm.DB, allControls []relational.Control) (*relational.Catalog, error) {
	catalog := &relational.Catalog{
		Controls: []relational.Control{},
		Groups:   []relational.Group{},
	}

	// Now we have all of the controls, let's roll them up into their root controls
	for _, control := range allControls {
		// If it has no parent, it's already the root
		if control.ParentType == nil {
			catalog.Controls = append(catalog.Controls, control)
			continue
		}

		// Roll it up all the way to the highest parenting control
		rootControl, err := rollUpToRootControl(db, control)
		if err != nil {
			return nil, err
		}

		// If the root control has no parent, add it straight to the catalog
		if rootControl.ParentType == nil {
			catalog.Controls = append(catalog.Controls, rootControl)
			continue
		}

		// If the control has a group as a parent, roll it up.
		if *rootControl.ParentType == "groups" {
			group := &relational.Group{}
			if err = db.First(group, "id = ?", *rootControl.ParentID).Error; err != nil {
				return nil, err
			}
			group.Controls = append(group.Controls, rootControl)
			rootGroup, err := rollUpToRootGroup(db, *group)
			if err != nil {
				return nil, err
			}
			catalog.Groups = append(catalog.Groups, rootGroup)
			continue
		}
	}

	// Merge groups and controls
	catalog.Controls = mergeControls(catalog.Controls...)
	catalog.Groups = mergeGroups(catalog.Groups...)

	return catalog, nil
}

func GetControlCatalogFromBuiltProfile(profile *relational.Profile, db *gorm.DB) (*relational.Catalog, error) {
	// If profile.Controls is empty, return an empty catalog to avoid returning massive dataset
	if len(profile.Controls) == 0 {
		return &relational.Catalog{}, nil
	}

	q := db.Model(&relational.Control{})
	for i, control := range profile.Controls {
		cond := db.Where("id = ? and catalog_id = ?", control.ID, control.CatalogID)
		if i == 0 {
			q = q.Where(cond)
		} else {
			q = q.Or(cond)
		}
	}
	var allControls []relational.Control
	if err := q.Find(&allControls).Error; err != nil {
		return nil, err
	}

	return rollUpControlsToCatalog(db, allControls)
}

// ResolveControls orchestrates control resolution for all imports in the profile,
// returning the list of catalog UUIDs and the fully processed controls.
func ResolveControls(profile *relational.Profile, db *gorm.DB) ([]uuid.UUID, []relational.Control, error) {
	var setParams map[string]relational.ParameterSetting
	var additions map[string][]relational.Addition
	if profile.Modify != nil {
		setParams = buildSetParams(profile.Modify.SetParameters)
		additions = buildAdditions(profile.Modify.Alters)
	}

	var allControls []relational.Control
	uuids := make([]uuid.UUID, len(profile.Imports))

	for i, imp := range profile.Imports {
		catalogID, processed, err := processImport(db, profile, imp, setParams, additions)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to process imports: %w", err)
		}
		allControls = append(allControls, processed...)
		uuids[i] = *catalogID
	}

	return uuids, allControls, nil
}

func BuildControlCatalogForProfile(profile *relational.Profile, db *gorm.DB) (*relational.Catalog, error) {
	_, allControls, err := ResolveControls(profile, db)
	if err != nil {
		return nil, err
	}

	return rollUpControlsToCatalog(db, allControls)
}

// FindOscalCatalogFromBackMatter searches the profile’s BackMatter for a resource matching the reference string
// and returns its catalog UUID if found.
func FindOscalCatalogFromBackMatter(profile *relational.Profile, ref string) (uuid.UUID, error) {
	id := strings.TrimPrefix(ref, "#")

	resources := profile.BackMatter.Resources
	for _, resource := range resources {
		if resource.ID.String() == id {
			for _, link := range resource.RLinks {
				if link.MediaType == "application/ccf+oscal+json" {
					hrefUUID := strings.TrimPrefix(link.Href, "#")
					return uuid.Parse(hrefUUID)
				}
			}
		}
	}
	return uuid.Nil, errors.New("no valid catalog uuid was found within the backmatter. ref: " + ref)
}

// GatherControlIds extracts unique control IDs from an Import’s IncludeControls, avoiding duplicates.
func GatherControlIds(imports relational.Import) []string {
	var controlIds []string
	seen := map[string]bool{}

	for _, includedControls := range imports.IncludeControls {
		for _, value := range includedControls.WithIds {
			if _, ok := seen[value]; !ok {
				seen[value] = true
				controlIds = append(controlIds, value)
			}
		}
	}
	return controlIds
}

// FindFullProfile loads a Profile by its UUID string from the database,
// preloading all related entities such as metadata, imports, merges, modifications, and back matter.
func FindFullProfile(db *gorm.DB, id uuid.UUID) (*relational.Profile, error) {
	var profile relational.Profile
	if err := db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Preload("Imports").
		Preload("Imports.IncludeControls").
		Preload("Imports.ExcludeControls").
		Preload("Merge").
		Preload("Modify").
		Preload("Modify.SetParameters").
		Preload("Modify.Alters").
		Preload("Modify.Alters.Adds").
		Preload("BackMatter").
		Preload("BackMatter.Resources").
		Preload("Controls").
		Preload("Controls.Controls").
		First(&profile, "id = ?", id).Error; err != nil {
		return nil, err
	}

	return &profile, nil
}

// Checks if an import with the given idFragment already exists in the profile's backmatter resources.
func importExistsInProfile(profile *relational.Profile, idFragment string) bool {
	for _, resource := range profile.BackMatter.Resources {
		for _, link := range resource.RLinks {
			if link.Href == idFragment && link.MediaType == "application/ccf+oscal+json" {
				return true
			}
		}
	}
	return false
}
