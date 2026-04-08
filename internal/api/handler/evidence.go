package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/compliance-framework/api/internal"
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/authcontext"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	svc "github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type EvidenceHandler struct {
	evidenceService *evidencesvc.EvidenceService
	pagination      *svc.PaginationConfig
	sugar           *zap.SugaredLogger
}

func NewEvidenceHandler(sugar *zap.SugaredLogger, evidenceService *evidencesvc.EvidenceService) *EvidenceHandler {
	return &EvidenceHandler{
		evidenceService: evidenceService,
		pagination:      svc.NewPaginationConfig(),
		sugar:           sugar,
	}
}

func (h *EvidenceHandler) Register(api *echo.Group) {
	api.POST("", h.Create)
	api.GET("/:id", h.Get)
	api.GET("/history/:id", h.History)
	api.GET("/latest/:id", h.Latest)
	api.POST("/search", h.Search)
	api.GET("/for-control/:id", h.ForControl)
	api.GET("/status-over-time/:id", h.StatusOverTimeByUUID)
	api.POST("/status-over-time", h.StatusOverTime)
	api.GET("/compliance-by-control/:id", h.ComplianceByControl)
	api.GET("/compliance-by-filter/:id", h.ComplianceByFilter)
}

func (h *EvidenceHandler) RegisterCreate(api *echo.Group, middlewares ...echo.MiddlewareFunc) {
	api.POST("", h.Create, middlewares...)
}

func (h *EvidenceHandler) RegisterReadRoutes(api *echo.Group) {
	api.GET("/:id", h.Get)
	api.GET("/history/:id", h.History)
	api.GET("/latest/:id", h.Latest)
	api.POST("/search", h.Search)
	api.GET("/for-control/:id", h.ForControl)
	api.GET("/status-over-time/:id", h.StatusOverTimeByUUID)
	api.POST("/status-over-time", h.StatusOverTime)
	api.GET("/compliance-by-control/:id", h.ComplianceByControl)
	api.GET("/compliance-by-filter/:id", h.ComplianceByFilter)
}

func (h *EvidenceHandler) RegisterSignatureRoutes(api *echo.Group) {
	api.GET("/:id/signature", h.GetSignature)
	api.POST("/:id/verify", h.VerifySignature)
}

type EvidenceActivityStep struct {
	UUID        uuid.UUID
	Title       string
	Description string
	Remarks     string
	Props       []oscalTypes_1_1_3.Property
	Links       []oscalTypes_1_1_3.Link
}

type EvidenceActivity struct {
	UUID        uuid.UUID
	Title       string
	Description string
	Remarks     string
	Props       []oscalTypes_1_1_3.Property
	Links       []oscalTypes_1_1_3.Link
	Steps       []EvidenceActivityStep
}

type EvidenceInventoryItem struct {
	// user/chris@linguine.tech
	// operating-system/ubuntu/22.4
	// web-server/ec2/i-12345
	Identifier string

	// "operating-system"	description="System software that manages computer hardware, software resources, and provides common services for computer programs."
	// "database"			description="An electronic collection of data, or information, that is specially organized for rapid search and retrieval."
	// "web-server"			description="A system that delivers content or services to end users over the Internet or an intranet."
	// "dns-server"			description="A system that resolves domain names to internet protocol (IP) addresses."
	// "email-server"		description="A computer system that sends and receives electronic mail messages."
	// "directory-server"	description="A system that stores, organizes and provides access to directory information in order to unify network resources."
	// "pbx"				description="A private branch exchange (PBX) provides a a private telephone switchboard."
	// "firewall"			description="A network security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules."
	// "router"				description="A physical or virtual networking device that forwards data packets between computer networks."
	// "switch"				description="A physical or virtual networking device that connects devices within a computer network by using packet switching to receive and forward data to the destination device."
	// "storage-array"		description="A consolidated, block-level data storage capability."
	// "appliance"			description="A physical or virtual machine that centralizes hardware, software, or services for a specific purpose."
	Type                  string
	Title                 string
	Description           string
	Remarks               string
	Props                 []oscalTypes_1_1_3.Property
	Links                 []oscalTypes_1_1_3.Link
	ImplementedComponents []struct {
		Identifier string
	}
}

type EvidenceComponent struct {
	// components/common/ssh
	// components/common/github-repository
	// components/common/github-organisation
	// components/common/ubuntu-22
	// components/internal/auth-policy
	Identifier string

	// Software
	// Service
	Type        string
	Title       string
	Description string
	Remarks     string
	Purpose     string
	Protocols   []oscalTypes_1_1_3.Protocol
	Props       []oscalTypes_1_1_3.Property
	Links       []oscalTypes_1_1_3.Link
}

type EvidenceSubject struct {
	Identifier string

	// InventoryItem
	// Component
	Type string

	Description string
	Remarks     string
	Props       []oscalTypes_1_1_3.Property
	Links       []oscalTypes_1_1_3.Link
}

type EvidenceCreateRequest struct {
	// UUID needs to remain consistent for a piece of evidence being collected periodically.
	// It represents the "stream" of the same observation being made over time.
	// For the same checks, performed on the same machine, the UUID for each check should remain the same.
	// For the same check, performed on two different machines, the UUID should differ.
	UUID        uuid.UUID
	Title       string
	Description string
	Remarks     *string

	// Assigning labels to Evidence makes it searchable and easily usable in the UI
	Labels map[string]string

	// When did we start collecting the evidence, and when did the process end, and how long is it valid for ?
	Start   time.Time
	End     time.Time
	Expires *time.Time

	Props      []oscalTypes_1_1_3.Property
	Links      []oscalTypes_1_1_3.Link
	BackMatter *oscalTypes_1_1_3.BackMatter `json:"back-matter,omitempty"`

	// Who or What is generating this evidence
	Origins []oscalTypes_1_1_3.Origin
	// What steps did we take to create this evidence
	Activities     []EvidenceActivity
	InventoryItems []EvidenceInventoryItem
	// Which components of the subject are being observed. A tool, user, policy etc.
	Components []EvidenceComponent
	// Who or What are we providing evidence for. What's under test.
	Subjects []EvidenceSubject
	// Did we satisfy what was being tested for, or did we fail ?
	Status oscalTypes_1_1_3.ObjectiveStatus
}

// Create godoc
//
//	@Summary		Create new Evidence
//	@Description	Creates a new Evidence record including activities, inventory items, components, and subjects.
//	@Tags			Evidence
//	@Accept			json
//	@Produce		json
//	@Param			evidence	body		EvidenceCreateRequest	true	"Evidence create request"
//	@Success		201			{object}	GenericDataResponse[CreatedEvidenceResponse]
//	@Failure		400			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/evidence [post]
func (h *EvidenceHandler) Create(ctx echo.Context) error {
	var input *EvidenceCreateRequest
	if err := ctx.Bind(&input); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	err := ctx.Validate(input)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.Validator(err))
	}

	now := time.Now().UTC()
	if input.Start.UTC().After(now) {
		return ctx.JSON(http.StatusBadRequest, api.InvalidFutureTime(input.Start))
	}
	if input.End.UTC().After(now) {
		return ctx.JSON(http.StatusBadRequest, api.InvalidFutureTime(input.End))
	}

	components := []relational.SystemComponent{}
	for _, i := range input.Components {
		id, err := internal.SeededUUID(map[string]string{
			"identifier": i.Identifier,
		})
		if err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
		model := relational.SystemComponent{
			UUIDModel: relational.UUIDModel{
				ID: &id,
			},
			Type:        i.Type,
			Title:       i.Title,
			Description: i.Description,
			Purpose:     i.Purpose,
			Remarks:     i.Remarks,
			Protocols: relational.ConvertList(&i.Protocols, func(op oscalTypes_1_1_3.Protocol) relational.Protocol {
				protocol := relational.Protocol{}
				protocol.UnmarshalOscal(op)
				return protocol
			}),
			Props: relational.ConvertOscalToProps(&input.Props),
			Links: relational.ConvertOscalToLinks(&input.Links),
		}
		components = append(components, model)
	}

	inventoryItems := []relational.InventoryItem{}
	for _, i := range input.InventoryItems {
		id, err := internal.SeededUUID(map[string]string{
			"identifier": i.Identifier,
		})
		if err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
		model := relational.InventoryItem{
			UUIDModel: relational.UUIDModel{
				ID: &id,
			},
			Description: i.Description,
			Props:       relational.ConvertOscalToProps(&input.Props),
			Links:       relational.ConvertOscalToLinks(&input.Links),
			Remarks:     i.Remarks,
		}
		for _, k := range i.ImplementedComponents {
			id, err := internal.SeededUUID(map[string]string{
				"identifier": k.Identifier,
			})
			if err != nil {
				return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
			}
			model.ImplementedComponents = append(model.ImplementedComponents, relational.ImplementedComponent{
				ComponentID: id,
			})
		}
		inventoryItems = append(inventoryItems, model)
	}

	activities := []relational.Activity{}
	for _, i := range input.Activities {
		model := relational.Activity{
			UUIDModel: relational.UUIDModel{
				ID: &i.UUID,
			},
			Title:       &i.Title,
			Description: i.Description,
			Remarks:     &i.Remarks,
			Props:       relational.ConvertOscalToProps(&input.Props),
			Links:       relational.ConvertOscalToLinks(&input.Links),
		}
		for _, k := range i.Steps {
			model.Steps = append(model.Steps, relational.Step{
				UUIDModel: relational.UUIDModel{
					ID: &k.UUID,
				},
				Title:       &k.Title,
				Description: k.Description,
				Remarks:     &k.Remarks,
				Props:       relational.ConvertOscalToProps(&input.Props),
				Links:       relational.ConvertOscalToLinks(&input.Links),
			})
		}
		activities = append(activities, model)
	}

	subjects := []relational.AssessmentSubject{}
	for _, i := range input.Subjects {
		id, err := internal.SeededUUID(map[string]string{
			"identifier": i.Identifier,
		})
		if err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
		model := relational.AssessmentSubject{
			Type: i.Type,
			IncludeSubjects: []relational.SelectSubjectById{
				{
					SubjectUUID: id,
				},
			},
			Description: &i.Description,
			Remarks:     &i.Remarks,
			Props:       relational.ConvertOscalToProps(&input.Props),
			Links:       relational.ConvertOscalToLinks(&input.Links),
		}
		subjects = append(subjects, model)
	}

	labels := []relational.Labels{}
	for name, value := range input.Labels {
		labels = append(labels, relational.Labels{
			Name:  name,
			Value: value,
		})
	}

	var backMatter *relational.BackMatter
	if input.BackMatter != nil {
		backMatter = &relational.BackMatter{}
		backMatter.UnmarshalOscal(*input.BackMatter)
	}

	evidence := relational.Evidence{
		UUIDModel: relational.UUIDModel{
			ID: internal.Pointer(uuid.New()),
		},
		UUID:        input.UUID,
		Title:       input.Title,
		Description: input.Description,
		Remarks:     input.Remarks,
		Start:       input.Start,
		End:         input.End,
		Expires:     input.Expires,
		Props:       relational.ConvertOscalToProps(&input.Props),
		Links:       relational.ConvertOscalToLinks(&input.Links),
		Origins: relational.ConvertList(&input.Origins, func(ol oscalTypes_1_1_3.Origin) relational.Origin {
			out := relational.Origin{}
			out.UnmarshalOscal(ol)
			return out
		}),
		BackMatter: backMatter,
		Status:     datatypes.NewJSONType(input.Status),
	}

	created, err := h.evidenceService.Create(ctx.Request().Context(), evidencesvc.CreateEvidenceParams{
		Evidence:       evidence,
		Components:     components,
		InventoryItems: inventoryItems,
		Activities:     activities,
		Subjects:       subjects,
		Labels:         labels,
		Signer:         authcontext.SignerContextFromEcho(ctx),
	})
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	output, err := newCreatedEvidenceResponse(created)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusCreated, GenericDataResponse[*CreatedEvidenceResponse]{Data: output})
}

// Search godoc
//
//	@Summary		Search Evidence
//	@Description	Searches Evidence records by label filters.
//	@Tags			Evidence
//	@Accept			json
//	@Produce		json
//	@Param			filter	body		labelfilter.Filter	true	"Label filter"
//	@Param			page	query		int					false	"Page number"
//	@Param			limit	query		int					false	"Page size"
//	@Success		200		{object}	svc.ListResponse[PublicEvidenceResponse]
//	@Failure		422		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/evidence/search [post]
func (h *EvidenceHandler) Search(ctx echo.Context) error {
	filter := &labelfilter.Filter{}
	req := filteredSearchRequest{}

	if err := req.bind(ctx, filter); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	pagination, err := h.pagination.ParseParams(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	results, total, err := h.evidenceService.SearchPaginated(*filter, pagination.Limit, pagination.Offset)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	output := make([]*PublicEvidenceResponse, 0, len(results))
	for _, evidence := range results {
		out, err := newPublicEvidenceResponse(&evidence)
		if err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
		output = append(output, out)
	}

	return ctx.JSON(http.StatusOK, svc.NewListResponse(output, total, pagination.Page, pagination.Limit))
}

type EvidenceFields struct {
	ID             *uuid.UUID                           `json:"id"`
	UUID           uuid.UUID                            `json:"uuid,omitempty"`
	Title          string                               `json:"title"`
	Description    string                               `json:"description"`
	Remarks        *string                              `json:"remarks,omitempty"`
	Labels         []relational.Labels                  `json:"labels"`
	Start          time.Time                            `json:"start"`
	End            time.Time                            `json:"end"`
	Expires        *time.Time                           `json:"expires,omitempty"`
	BackMatter     *oscalTypes_1_1_3.BackMatter         `json:"back-matter,omitempty"`
	Props          []oscalTypes_1_1_3.Property          `json:"props"`
	Links          []oscalTypes_1_1_3.Link              `json:"links"`
	Origins        []oscalTypes_1_1_3.Origin            `json:"origins,omitempty"`
	Activities     []oscalTypes_1_1_3.Activity          `json:"activities,omitempty"`
	InventoryItems []oscalTypes_1_1_3.InventoryItem     `json:"inventory-items,omitempty"`
	Components     []oscalTypes_1_1_3.SystemComponent   `json:"components,omitempty"`
	Subjects       []oscalTypes_1_1_3.AssessmentSubject `json:"subjects,omitempty"`
	Status         oscalTypes_1_1_3.ObjectiveStatus     `json:"status"`
}

type PublicEvidenceResponse struct {
	EvidenceFields
}

type CreatedEvidenceResponse struct {
	EvidenceFields
	Signature *relational.EvidenceSignature `json:"signature,omitempty"`
}

type EvidenceSignatureResponse = GenericDataResponse[*evidencesvc.SignatureDetail]

type EvidenceSignatureVerificationResponse = GenericDataResponse[*evidencesvc.VerificationResult]

func buildEvidenceFields(evidence *relational.Evidence) (*EvidenceFields, error) {
	out := &EvidenceFields{
		ID:          evidence.ID,
		UUID:        evidence.UUID,
		Title:       evidence.Title,
		Description: evidence.Description,
		Remarks:     evidence.Remarks,
		Labels:      evidence.Labels,
		Start:       evidence.Start,
		End:         evidence.End,
		Expires:     evidence.Expires,
		Props:       *relational.ConvertPropsToOscal(evidence.Props),
		Links:       *relational.ConvertLinksToOscal(evidence.Links),
	}
	out.Subjects = relational.ConvertList(&evidence.Subjects, func(in relational.AssessmentSubject) oscalTypes_1_1_3.AssessmentSubject {
		return *in.MarshalOscal()
	})
	out.Components = relational.ConvertList(&evidence.Components, func(in relational.SystemComponent) oscalTypes_1_1_3.SystemComponent {
		return *in.MarshalOscal()
	})
	out.Activities = relational.ConvertList(&evidence.Activities, func(in relational.Activity) oscalTypes_1_1_3.Activity {
		return *in.MarshalOscal()
	})
	out.InventoryItems = relational.ConvertList(&evidence.InventoryItems, func(in relational.InventoryItem) oscalTypes_1_1_3.InventoryItem {
		return in.MarshalOscal()
	})
	out.Origins = func() []oscalTypes_1_1_3.Origin {
		out := make([]oscalTypes_1_1_3.Origin, 0)
		for _, v := range evidence.Origins {
			out = append(out, oscalTypes_1_1_3.Origin(v))
		}
		return out
	}()
	out.BackMatter = &oscalTypes_1_1_3.BackMatter{}
	if evidence.BackMatter != nil {
		out.BackMatter = evidence.BackMatter.MarshalOscal()
	}
	out.Status = evidence.Status.Data()
	return out, nil
}

func newPublicEvidenceResponse(evidence *relational.Evidence) (*PublicEvidenceResponse, error) {
	fields, err := buildEvidenceFields(evidence)
	if err != nil {
		return nil, err
	}
	return &PublicEvidenceResponse{EvidenceFields: *fields}, nil
}

func newCreatedEvidenceResponse(evidence *relational.Evidence) (*CreatedEvidenceResponse, error) {
	fields, err := buildEvidenceFields(evidence)
	if err != nil {
		return nil, err
	}

	response := &CreatedEvidenceResponse{EvidenceFields: *fields}
	if evidence.Signature != nil {
		signature := evidence.Signature.Data()
		response.Signature = &signature
	}
	return response, nil
}

func parseEvidenceID(ctx echo.Context) (uuid.UUID, error) {
	return uuid.Parse(ctx.Param("id"))
}

// Get godoc
//
//	@Summary		Get Evidence by ID
//	@Description	Retrieves a single Evidence record by its unique ID, including associated activities, inventory items, components, subjects, and labels.
//	@Tags			Evidence
//	@Produce		json
//	@Param			id	path		string	true	"Evidence ID"
//	@Success		200	{object}	GenericDataResponse[PublicEvidenceResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/evidence/{id} [get]
func (h *EvidenceHandler) Get(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := parseEvidenceID(ctx)
	if err != nil {
		h.sugar.Warnw("Invalid evidence id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	evidence, err := h.evidenceService.GetByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load evidence", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	output, err := newPublicEvidenceResponse(evidence)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[*PublicEvidenceResponse]{Data: output})
}

// History godoc
//
//	@Summary		Get Evidence history by UUID
//	@Description	Retrieves a the history for a Evidence record by its UUID, including associated activities, inventory items, components, subjects, and labels.
//	@Tags			Evidence
//	@Produce		json
//	@Param			id		path		string	true	"Evidence UUID"
//	@Param			page	query		int		false	"Page number"
//	@Param			limit	query		int		false	"Page size"
//	@Success		200		{object}	svc.ListResponse[PublicEvidenceResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/evidence/history/{id} [get]
func (h *EvidenceHandler) History(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := parseEvidenceID(ctx)
	if err != nil {
		h.sugar.Warnw("Invalid evidence id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	pagination, err := h.pagination.ParseParams(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	evidences, total, err := h.evidenceService.GetHistoryPaginated(id, pagination.Limit, pagination.Offset)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load evidence", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	output := []*PublicEvidenceResponse{}
	for _, e := range evidences {
		out, convErr := newPublicEvidenceResponse(&e)
		if convErr != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(convErr))
		}
		output = append(output, out)
	}

	return ctx.JSON(http.StatusOK, svc.NewListResponse(output, total, pagination.Page, pagination.Limit))
}

// Latest godoc
//
//	@Summary		Get latest Evidence by UUID
//	@Description	Retrieves the most recent Evidence record for a given UUID stream, including associated activities, inventory items, components, subjects, and labels.
//	@Tags			Evidence
//	@Produce		json
//	@Param			id	path		string	true	"Evidence UUID"
//	@Success		200	{object}	GenericDataResponse[PublicEvidenceResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/evidence/latest/{id} [get]
func (h *EvidenceHandler) Latest(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := parseEvidenceID(ctx)
	if err != nil {
		h.sugar.Warnw("Invalid evidence uuid", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	evidence, err := h.evidenceService.GetLatestByUUID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load latest evidence", "uuid", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	output, err := newPublicEvidenceResponse(evidence)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[*PublicEvidenceResponse]{Data: output})
}

// GetSignature godoc
//
//	@Summary		Get Evidence signature by ID
//	@Description	Retrieves the stored signature envelope for a single Evidence record.
//	@Tags			Evidence
//	@Produce		json
//	@Param			id	path		string	true	"Evidence ID"
//	@Success		200	{object}	handler.EvidenceSignatureResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/evidence/{id}/signature [get]
func (h *EvidenceHandler) GetSignature(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := parseEvidenceID(ctx)
	if err != nil {
		h.sugar.Warnw("Invalid evidence id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	signature, err := h.evidenceService.GetSignatureByID(id)
	if err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		default:
			h.sugar.Warnw("Failed to load evidence signature", "id", idParam, "error", err)
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}

	return ctx.JSON(http.StatusOK, EvidenceSignatureResponse{Data: signature})
}

// VerifySignature godoc
//
//	@Summary		Verify Evidence signature by ID
//	@Description	Recomputes the current evidence content hash and verifies the stored signed payload.
//	@Tags			Evidence
//	@Produce		json
//	@Param			id	path		string	true	"Evidence ID"
//	@Success		200	{object}	handler.EvidenceSignatureVerificationResponse
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/evidence/{id}/verify [post]
func (h *EvidenceHandler) VerifySignature(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := parseEvidenceID(ctx)
	if err != nil {
		h.sugar.Warnw("Invalid evidence id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	result, err := h.evidenceService.VerifyByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to verify evidence signature", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, EvidenceSignatureVerificationResponse{Data: result})
}

// ForControl godoc
//
//	@Summary		List Evidence for a Control
//	@Description	Retrieves Evidence records associated with a specific Control ID, including related activities, inventory items, components, subjects, and labels.
//	@Tags			Evidence
//	@Produce		json
//	@Param			id	path		string	true	"Control ID"
//	@Success		200	{object}	handler.ForControl.EvidenceDataListResponse
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/evidence/for-control/{id} [get]
func (h *EvidenceHandler) ForControl(ctx echo.Context) error {
	type responseMetadata struct {
		Control *oscalTypes_1_1_3.Control `json:"control"`
	}
	type EvidenceDataListResponse struct {
		Metadata responseMetadata `json:"metadata"`
		// Items from the list response
		Data []PublicEvidenceResponse `json:"data" yaml:"data"`
	}

	id := ctx.Param("id")
	control, err := h.evidenceService.GetControlByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	response := EvidenceDataListResponse{
		Metadata: responseMetadata{
			Control: control.MarshalOscal(),
		},
	}

	filters := []labelfilter.Filter{}
	for _, filter := range control.Filters {
		filters = append(filters, filter.Filter.Data())
	}

	if len(filters) == 0 {
		return ctx.JSON(http.StatusOK, GenericDataListResponse[evidencesvc.StatusCount]{Data: []evidencesvc.StatusCount{}})
	}

	evidenceList, err := h.evidenceService.GetLatestForFilters(filters...)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	response.Data = []PublicEvidenceResponse{}
	for _, e := range evidenceList {
		out, convErr := newPublicEvidenceResponse(&e)
		if convErr != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(convErr))
		}
		response.Data = append(response.Data, *out)
	}

	return ctx.JSON(http.StatusOK, response)
}

type StatusInterval struct {
	Interval time.Time                 `json:"interval"`
	Statuses []evidencesvc.StatusCount `json:"statuses"`
}

// StatusOverTime godoc
//
//	@Summary		Evidence status metrics over intervals
//	@Description	Retrieves counts of evidence statuses at various time intervals based on a label filter.
//	@Tags			Evidence
//	@Accept			json
//	@Produce		json
//	@Param			filter		body		labelfilter.Filter	true	"Label filter"
//	@Param			intervals	query		string				false	"Comma-separated list of duration intervals (e.g., '10m,1h,24h')"
//	@Success		200			{object}	handler.GenericDataListResponse[StatusInterval]
//	@Failure		400			{object}	api.Error
//	@Failure		422			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/evidence/status-over-time [post]
func (h *EvidenceHandler) StatusOverTime(ctx echo.Context) error {
	filter := &labelfilter.Filter{}
	req := filteredSearchRequest{}

	if err := req.bind(ctx, filter); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	intervals, err := ParseIntervalListQueryParam(
		ctx.QueryParam("intervals"),
		[]time.Duration{0, 10 * time.Minute, 20 * time.Minute, 30 * time.Minute, 1 * time.Hour, 2 * time.Hour, 4 * time.Hour},
	)
	if err != nil {
		h.sugar.Warnw("Invalid evidence interval query", "query", ctx.QueryParam("intervals"), "error", err)
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	type result struct {
		idx      int
		interval time.Time
		data     []evidencesvc.StatusCount
		err      error
	}

	ch := make(chan result, len(intervals))
	now := time.Now()
	for i, d := range intervals {
		go func(i int, d time.Duration) {
			var endBefore *time.Time
			if d > 0 {
				t := now.Add(-d).UTC()
				endBefore = &t
			}
			rows, err := h.evidenceService.GetStatusCountsAtPoint(*filter, endBefore)
			if err != nil {
				ch <- result{idx: i, err: err}
				return
			}
			ch <- result{idx: i, interval: now.Add(-d), data: rows}
		}(i, d)
	}

	results := make([]StatusInterval, len(intervals))
	for range intervals {
		r := <-ch
		if r.err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(r.err))
		}
		results[r.idx] = StatusInterval{Interval: r.interval, Statuses: r.data}
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[StatusInterval]{Data: results})
}

// StatusOverTimeByUUID godoc
//
//	@Summary		Evidence status metrics over intervals by UUID
//	@Description	Retrieves counts of evidence statuses at various time intervals for a specific evidence stream identified by UUID.
//	@Tags			Evidence
//	@Produce		json
//	@Param			id			path		string	true	"Evidence UUID"
//	@Param			intervals	query		string	false	"Comma-separated list of duration intervals (e.g., '10m,1h,24h')"
//	@Success		200			{object}	handler.GenericDataListResponse[StatusInterval]
//	@Failure		400			{object}	api.Error
//	@Failure		422			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/evidence/status-over-time/{id} [get]
func (h *EvidenceHandler) StatusOverTimeByUUID(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid evidence id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	intervals, err := ParseIntervalListQueryParam(
		ctx.QueryParam("intervals"),
		[]time.Duration{0, 10 * time.Minute, 20 * time.Minute, 30 * time.Minute, 1 * time.Hour, 2 * time.Hour, 4 * time.Hour},
	)
	if err != nil {
		h.sugar.Warnw("Invalid evidence interval query", "query", ctx.QueryParam("intervals"), "error", err)
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	type result struct {
		idx      int
		interval time.Time
		data     []evidencesvc.StatusCount
		err      error
	}

	ch := make(chan result, len(intervals))
	now := time.Now()
	for i, d := range intervals {
		go func(i int, d time.Duration) {
			var endBefore *time.Time
			if d > 0 {
				t := now.Add(-d).UTC()
				endBefore = &t
			}
			rows, err := h.evidenceService.GetStatusCountsByUUIDAtPoint(id, endBefore)
			if err != nil {
				ch <- result{idx: i, err: err}
				return
			}
			ch <- result{idx: i, interval: now.Add(-d), data: rows}
		}(i, d)
	}

	results := make([]StatusInterval, len(intervals))
	for range intervals {
		r := <-ch
		if r.err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(r.err))
		}
		results[r.idx] = StatusInterval{Interval: r.interval, Statuses: r.data}
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[StatusInterval]{Data: results})
}

// ComplianceByControl godoc
//
//	@Summary		Get compliance counts by control
//	@Description	Retrieves the count of evidence statuses for filters associated with a specific Control ID.
//	@Tags			Evidence
//	@Produce		json
//	@Param			id	path		string	true	"Control ID"
//	@Success		200	{object}	GenericDataListResponse[evidence.StatusCount]
//	@Failure		500	{object}	api.Error
//	@Router			/evidence/compliance-by-control/{id} [get]
func (h *EvidenceHandler) ComplianceByControl(ctx echo.Context) error {
	id := ctx.Param("id")
	control, err := h.evidenceService.GetControlByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	filters := []labelfilter.Filter{}
	for _, filter := range control.Filters {
		filters = append(filters, filter.Filter.Data())
	}

	if len(filters) == 0 {
		return ctx.JSON(http.StatusOK, GenericDataListResponse[evidencesvc.StatusCount]{Data: []evidencesvc.StatusCount{}})
	}

	rows, err := h.evidenceService.GetStatusCountsByFilters(filters...)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[evidencesvc.StatusCount]{Data: rows})
}

// ComplianceByFilter godoc
//
//	@Summary		Get compliance status counts by filter/dashboard ID
//	@Description	Retrieves the count of evidence statuses for a specific filter/dashboard.
//	@Tags			Evidence
//	@Produce		json
//	@Param			id	path		string	true	"Filter/Dashboard ID (UUID)"
//	@Success		200	{object}	GenericDataListResponse[evidence.StatusCount]
//	@Failure		400	{object}	api.Error	"Invalid UUID"
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/evidence/compliance-by-filter/{id} [get]
func (h *EvidenceHandler) ComplianceByFilter(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	filter, err := h.evidenceService.GetFilterByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	rows, err := h.evidenceService.GetStatusCountsByFilters(filter.Filter.Data())
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[evidencesvc.StatusCount]{Data: rows})
}
