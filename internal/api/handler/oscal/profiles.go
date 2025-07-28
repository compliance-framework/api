package oscal

import (
	"errors"
	"fmt"
	"net/http"
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
		UUID:     *profile.UUIDModel.ID,
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
	catalog, err := BuildControlCatalogForProfile(profile, h.db, newID)
	if err != nil {
		h.sugar.Errorw("error building control catalog", "id", id, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	catalog.ID = &newID
	catalog.Metadata = profile.Metadata
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[oscalTypes_1_1_3.Catalog]{Data: *catalog.MarshalOscal()})

	//if err := h.db.Save(&catalog).Error; err != nil {
	//	h.sugar.Errorw("error saving new catalog to database", "id", idParam, "error", err)
	//	return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	//}
	//
	//resp := response{
	//	ID: catalog.UUIDModel.ID.String(),
	//}
	//
	//return ctx.JSON(http.StatusCreated, handler.GenericDataResponse[response]{Data: resp})
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

	fmt.Printf("%+v\n", updateData)

	if updateData.Href != href {
		h.sugar.Warnw("href mismatch", "expected", href, "received", updateData.Href)
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("href in request body does not match URL parameter")))
	}

	updatedImport := relational.Import{}
	updatedImport.UnmarshalOscal(updateData)
	updatedImport.UUIDModel.ID = profileImport.UUIDModel.ID
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

	var payload oscalTypes_1_1_3.Merge
	if err := ctx.Bind(&payload); err != nil {
		h.sugar.Errorw("error binding request data", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	var relationalMerge relational.Merge
	if err := h.db.Where("profile_id = ?", id).First(&relationalMerge).Error; err != nil {
		h.sugar.Warnw("error finding merge", "id", idParam, "error", err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
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
	if err := db.Preload("Controls").Preload("Controls.Controls").Find(&controls, "catalog_id = ? AND id IN ?", catalogID, ids).Error; err != nil {
		panic(err)
	}

	newControls := make([]relational.Control, len(controls))

	for i := range controls {
		ctrl := relational.Control{}

		ctrl.UnmarshalOscal(*controls[i].MarshalOscal(), newCatalogId)
		ctrl.ParentID = controls[i].ParentID
		ctrl.ParentType = controls[i].ParentType

		ctrl = applySetParameters(ctrl, setParams)
		if list, ok := additions[controls[i].ID]; ok {
			ctrl = applyAdditions(ctrl, list)
		}
		newControls[i] = ctrl
	}
	return catalogID, newControls
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

// ResolveControls orchestrates control resolution for all imports in the profile,
// returning the list of catalog UUIDs and the fully processed controls.
func BuildControlCatalogForProfile(profile *relational.Profile, db *gorm.DB, catalogId uuid.UUID) (*relational.Catalog, error) {
	setParams := buildSetParams(profile.Modify.SetParameters)
	additions := buildAdditions(profile.Modify.Alters)

	var allControls []relational.Control

	for _, imp := range profile.Imports {
		_, processed := processImport(db, profile, imp, setParams, additions, catalogId)
		allControls = append(allControls, processed...)
	}

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
			return &relational.Catalog{}, err
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
				return &relational.Catalog{}, err
			}
			group.Controls = append(group.Controls, rootControl)
			rootGroup, err := rollUpToRootGroup(db, *group)
			if err != nil {
				return &relational.Catalog{}, err
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

	for _, control := range allControls {
		fmt.Println(control.ID)
		fmt.Println(control.Title)
		fmt.Println(*control.ParentType)
		fmt.Println(*control.ParentID)
	}

	return uuids, &allControls
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
