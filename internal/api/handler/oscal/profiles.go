package oscal

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	"github.com/defenseunicorns/go-oscal/src/pkg/versioning"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type ProfileHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
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
	api.GET("/:id", h.Get)
	api.GET("/:id/imports", h.ListImports)
	api.GET("/:id/modify", h.GetModify)
	api.GET("/:id/merge", h.GetMerge)
	api.GET("/:id/back-matter", h.GetBackmatter)
	api.POST("/:id/resolve", h.Resolve)
	api.GET("/:id/full", h.GetFull)
}

// List godoc
//
//	@Summary		List Profiles
//	@Description	Retrieves all OSCAL profiles
//	@Tags			Oscal, Profiles
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
			UUID:     *profile.UUIDModel.ID,
			Metadata: *profile.Metadata.MarshalOscal(),
		}
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[response]{Data: respProfiles})
}

// Get godoc
//
//	@Summary		Get Profile
//	@Description	Get an OSCAL profile with the uuid provided
//	@Tags			Oscal, Profiles
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
		h.sugar.Errorw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var profile relational.Profile
	if err := h.db.
		Preload("Metadata").
		Preload("Metadata.Revisions").
		Where("id = ?", id).
		First(&profile).Error; err != nil {
		h.sugar.Errorw("error getting profile", "id", idParam, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	responseProfile := response{
		UUID:     *profile.UUIDModel.ID,
		Metadata: *profile.Metadata.MarshalOscal(),
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[response]{Data: responseProfile})
}

// ListImports godoc
//
//	@Summary		List Imports
//	@Description	List imports for a specific profile
//	@Tags			Oscal, Profiles
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
		h.sugar.Errorw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var profile relational.Profile
	if err := h.db.
		Preload("Imports").Preload("Imports.IncludeControls").Preload("Imports.ExcludeControls").
		Where("id = ?", id).First(&profile).Error; err != nil {
		h.sugar.Errorw("error listing imports", "id", idParam, "error", err)
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

// GetBackmatter godoc
//
//	@Summary		Get Backmatter
//	@Description	Get the BackMatter for a specific profile
//	@Tags			Oscal, Profiles
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
		h.sugar.Errorw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var profile relational.Profile

	if err := h.db.Preload("BackMatter").Preload("BackMatter.Resources").Where("id = ?", id).First(&profile).Error; err != nil {
		h.sugar.Errorw("error getting profile", "id", idParam, "error", err)
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
//	@Tags			Oscal, Profiles
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
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
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

	catalogUUids, allControls := ResolveControls(profile, h.db, newID)

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

	catalog.Controls = append(catalog.Controls, *allControls...)

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
		ID: catalog.UUIDModel.ID.String(),
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[response]{Data: resp})
}

// Create godoc
//
//	@Summary		Create a new OSCAL Profile
//	@Description	Creates a new OSCAL Profile.
//	@Tags			Oscal, Profiles
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
		h.sugar.Errorw("error binding profile", "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	profileRel := &relational.Profile{}
	profileRel.UnmarshalOscal(oscalProfile)
	profileRel.Metadata.LastModified = &now
	profileRel.Metadata.OscalVersion = versioning.GetLatestSupportedVersion()
	if err := h.db.Create(profileRel).Error; err != nil {
		h.sugar.Errorw("error creating profile", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[oscalTypes_1_1_3.Profile]{Data: *profileRel.MarshalOscal()})
}

// GetFull godoc
//
//	@Summary		Get full Profile
//	@Description	Retrieves the full OSCAL Profile, including all nested content.
//	@Tags			Oscal, Profiles
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
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
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
//	@Tags			Oscal, Profiles
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
		h.sugar.Errorw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var profile relational.Profile
	if err := h.db.
		Preload("Modify").
		Preload("Modify.SetParameters").
		Preload("Modify.Alters").
		Preload("Modify.Alters.Adds").
		Where("id = ?", id).
		First(&profile).Error; err != nil {
		h.sugar.Errorw("error getting profile", "id", idParam, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Modify]{Data: *profile.Modify.MarshalOscal()})
}

// GetMerge godoc
//
//	@Summary		Get merge section
//	@Description	Retrieves the merge section for a specific profile.
//	@Tags			Oscal, Profiles
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
		h.sugar.Errorw("error parsing UUID", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	var profile relational.Profile
	if err := h.db.
		Preload("Merge").
		Where("id = ?", id).
		First(&profile).Error; err != nil {
		h.sugar.Errorw("error getting profile", "id", idParam, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Merge]{Data: *profile.Merge.MarshalOscal()})
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
			if addition.Position == "starting" || addition.Position == "ending" {
				applyAdditionsToControl(&ctrl, addition, addition.Position)
			} else if addition.Position == "before" || addition.Position == "after" {
				// TODO - inject the addition either before or after the current id
			}
		} else if part := findPartRecursive(ctrl.Parts, addition.ByID); part != nil {
			if addition.Position == "starting" || addition.Position == "ending" {
				applyAdditionsToPart(part, addition, addition.Position)
			} else if addition.Position == "before" || addition.Position == "after" {
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
		if position == "starting" {
			part.Props = append(addition.Props, part.Props...)
		} else if position == "ending" {
			part.Props = append(part.Props, addition.Props...)
		}
	}
	if addition.Links != nil {
		if position == "starting" {
			part.Links = append(addition.Links, part.Links...)
		} else if position == "ending" {
			part.Links = append(part.Links, addition.Links...)
		}
	}
	if addition.Parts != nil {
		if position == "starting" {
			part.Parts = append(addition.Parts, part.Parts...)
		} else if position == "ending" {
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
		if position == "starting" {
			ctrl.Props = append(addition.Props, ctrl.Props...)
		} else if position == "ending" {
			ctrl.Props = append(ctrl.Props, addition.Props...)
		}
	}
	if addition.Params != nil {
		if position == "starting" {
			ctrl.Params = append(addition.Params, ctrl.Params...)
		} else if position == "ending" {
			ctrl.Params = append(ctrl.Params, addition.Params...)
		}
	}
	if addition.Links != nil {
		if position == "starting" {
			ctrl.Links = append(addition.Links, ctrl.Links...)
		} else if position == "ending" {
			ctrl.Links = append(ctrl.Links, addition.Links...)
		}
	}
	if addition.Parts != nil {
		if position == "starting" {
			ctrl.Parts = append(addition.Parts, ctrl.Parts...)
		} else if position == "ending" {
			ctrl.Parts = append(ctrl.Parts, addition.Parts...)
		}
	}
}

// processImport loads controls of a given import from the database, applies parameter settings and additions,
// and returns the catalog UUID along with the modified controls.
func processImport(db *gorm.DB, profile *relational.Profile, imp relational.Import, setParams map[string]relational.ParameterSetting, additions map[string][]relational.Addition, newCatalogId uuid.UUID) (uuid.UUID, []relational.Control) {
	ids := GatherControlIds(imp)
	catalogID, err := FindOscalCatalogFromBackMatter(profile, imp.Href)
	if err != nil {
		panic(err)
	}

	var controls []relational.Control
	if err := db.Preload("Controls").Find(&controls, "catalog_id = ? AND id IN ?", catalogID, ids).Error; err != nil {
		panic(err)
	}

	newControls := make([]relational.Control, len(controls))

	for i := range controls {
		ctrl := relational.Control{}

		ctrl.UnmarshalOscal(*controls[i].MarshalOscal(), newCatalogId)

		ctrl = applySetParameters(ctrl, setParams)
		if list, ok := additions[controls[i].ID]; ok {
			ctrl = applyAdditions(ctrl, list)
		}
		newControls[i] = ctrl
	}
	return catalogID, newControls
}

// ResolveControls orchestrates control resolution for all imports in the profile,
// returning the list of catalog UUIDs and the fully processed controls.
func ResolveControls(profile *relational.Profile, db *gorm.DB, catalogId uuid.UUID) ([]uuid.UUID, *[]relational.Control) {
	setParams := buildSetParams(profile.Modify.SetParameters)
	additions := buildAdditions(profile.Modify.Alters)

	var allControls []relational.Control

	uuids := make([]uuid.UUID, len(profile.Imports))

	for i, imp := range profile.Imports {
		uuid, processed := processImport(db, profile, imp, setParams, additions, catalogId)
		allControls = append(allControls, processed...)
		uuids[i] = uuid
	}

	return uuids, &allControls
}

// FindOscalCatalogFromBackMatter searches the profile’s BackMatter for a resource matching the reference string
// and returns its catalog UUID if found.
func FindOscalCatalogFromBackMatter(profile *relational.Profile, ref string) (uuid.UUID, error) {
	id := strings.TrimPrefix(ref, "#")

	resources := profile.BackMatter.Resources
	for _, resource := range resources {
		if resource.UUIDModel.ID.String() == id {
			for _, link := range resource.RLinks {
				if link.MediaType == "application/ccf+oscal+json" {
					hrefUUID := strings.TrimPrefix(link.Href, "#")
					return uuid.Parse(hrefUUID)
				}
			}
		}
	}
	return uuid.Nil, errors.New("No valid catalog UUID was found within the backmatter. Ref: " + ref)
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
		Find(&profile, "id = ?", id).Error; err != nil {
		return nil, err
	}

	return &profile, nil
}
