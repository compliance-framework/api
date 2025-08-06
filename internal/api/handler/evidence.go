package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/compliance-framework/api/internal"
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type EvidenceHandler struct {
	db    *gorm.DB
	sugar *zap.SugaredLogger
}

func NewEvidenceHandler(sugar *zap.SugaredLogger, db *gorm.DB) *EvidenceHandler {
	return &EvidenceHandler{
		sugar: sugar,
		db:    db,
	}
}

func (h *EvidenceHandler) Register(api *echo.Group) {
	api.POST("", h.Create)
	api.GET("/:id", h.Get)
	api.GET("/history/:id", h.History)
	api.POST("/search", h.Search)
	api.GET("/for-control/:id", h.ForControl)
	api.GET("/status-over-time/:id", h.StatusOverTimeByUUID)
	api.POST("/status-over-time", h.StatusOverTime)
	api.GET("/compliance-by-control/:id", h.ComplianceByControl)
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
	BackMatter *oscalTypes_1_1_3.BackMatter

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
//	@Success		201			{object}	GenericDataResponse[relational.Evidence]
//	@Failure		400			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/evidence [post]
func (h *EvidenceHandler) Create(ctx echo.Context) error {
	// Bind the incoming JSON payload into a slice of SDK findings.
	var input *EvidenceCreateRequest
	if err := ctx.Bind(&input); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	err := ctx.Validate(input)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.Validator(err))
	}

	components := []relational.SystemComponent{}
	// First, Inventory
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
		h.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&model)
	}

	inventoryItems := []relational.InventoryItem{}
	// First, Inventory
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
			id, err = internal.SeededUUID(map[string]string{
				"identifier": k.Identifier,
			})
			model.ImplementedComponents = append(model.ImplementedComponents, relational.ImplementedComponent{
				ComponentID: id,
			})
		}
		inventoryItems = append(inventoryItems, model)
		h.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&model)
	}

	activities := []relational.Activity{}
	// First, Inventory
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
		h.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&model)
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
		h.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&model)
	}

	labels := []relational.Labels{}
	for name, value := range input.Labels {
		model := relational.Labels{
			Name:  name,
			Value: value,
		}
		labels = append(labels, model)
		h.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&model)
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

	if err := h.db.Create(&evidence).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err = h.db.Model(&evidence).Association("Activities").Append(activities); err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err = h.db.Model(&evidence).Association("InventoryItems").Append(inventoryItems); err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err = h.db.Model(&evidence).Association("Components").Append(components); err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err = h.db.Model(&evidence).Association("Subjects").Append(subjects); err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	if err = h.db.Model(&evidence).Association("Labels").Append(labels); err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Return a 201 Created response with no content.
	return ctx.JSON(http.StatusCreated, GenericDataResponse[relational.Evidence]{Data: evidence})
}

// Search godoc
//
//	@Summary		Search Evidence
//	@Description	Searches Evidence records by label filters.
//	@Tags			Evidence
//	@Accept			json
//	@Produce		json
//	@Param			filter	body		labelfilter.Filter	true	"Label filter"
//	@Success		200		{object}	GenericDataListResponse[relational.Evidence]
//	@Failure		422		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Router			/evidence/search [post]
func (h *EvidenceHandler) Search(ctx echo.Context) error {
	var err error
	filter := &labelfilter.Filter{}
	req := filteredSearchRequest{}

	// Bind the incoming request to the filter.
	if err = req.bind(ctx, filter); err != nil {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}

	results := []relational.Evidence{}
	query := h.db.Session(&gorm.Session{})
	query, err = relational.GetEvidenceSearchByFilterQuery(relational.GetLatestEvidenceStreamsQuery(h.db), h.db, *filter)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if err = query.Preload("Labels").Find(&results).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[relational.Evidence]{results})
}

type OscalLikeEvidence struct {
	relational.Evidence
	Props          []oscalTypes_1_1_3.Property          `json:"props"`
	Links          []oscalTypes_1_1_3.Link              `json:"links"`
	Origins        []oscalTypes_1_1_3.Origin            `json:"origins,omitempty"`
	Activities     []oscalTypes_1_1_3.Activity          `json:"activities,omitempty"`
	InventoryItems []oscalTypes_1_1_3.InventoryItem     `json:"inventory-items,omitempty"`
	Components     []oscalTypes_1_1_3.SystemComponent   `json:"components,omitempty"`
	Subjects       []oscalTypes_1_1_3.AssessmentSubject `json:"subjects,omitempty"`
	Status         oscalTypes_1_1_3.ObjectiveStatus     `json:"status"`
}

func (o *OscalLikeEvidence) FromEvidence(evidence *relational.Evidence) error {
	o.ID = evidence.ID
	o.UUID = evidence.UUID
	o.Title = evidence.Title
	o.Description = evidence.Description
	o.Remarks = evidence.Remarks
	o.Start = evidence.Start
	o.End = evidence.End
	o.Expires = evidence.Expires
	o.Labels = evidence.Labels
	o.Props = *relational.ConvertPropsToOscal(evidence.Props)
	o.Links = *relational.ConvertLinksToOscal(evidence.Links)
	o.Subjects = relational.ConvertList(&evidence.Subjects, func(in relational.AssessmentSubject) oscalTypes_1_1_3.AssessmentSubject {
		return *in.MarshalOscal()
	})
	o.Components = relational.ConvertList(&evidence.Components, func(in relational.SystemComponent) oscalTypes_1_1_3.SystemComponent {
		return *in.MarshalOscal()
	})
	o.Activities = relational.ConvertList(&evidence.Activities, func(in relational.Activity) oscalTypes_1_1_3.Activity {
		return *in.MarshalOscal()
	})
	o.InventoryItems = relational.ConvertList(&evidence.InventoryItems, func(in relational.InventoryItem) oscalTypes_1_1_3.InventoryItem {
		return in.MarshalOscal()
	})
	o.Origins = func() []oscalTypes_1_1_3.Origin {
		out := make([]oscalTypes_1_1_3.Origin, 0)
		for _, v := range evidence.Origins {
			out = append(out, oscalTypes_1_1_3.Origin(v))
		}
		return out
	}()
	o.Status = evidence.Status.Data()
	return nil
}

// Get godoc
//
//	@Summary		Get Evidence by ID
//	@Description	Retrieves a single Evidence record by its unique ID, including associated activities, inventory items, components, subjects, and labels.
//	@Tags			Evidence
//	@Produce		json
//	@Param			id	path		string	true	"Evidence ID"
//	@Success		200	{object}	GenericDataResponse[OscalLikeEvidence]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/evidence/{id} [get]
func (h *EvidenceHandler) Get(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid evidence id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var evidence relational.Evidence
	if err := h.db.
		Preload("Labels").
		Preload("Activities").
		Preload("Activities.Steps").
		Preload("InventoryItems").
		Preload("Components").
		Preload("Subjects").
		First(&evidence, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load evidence", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	output := &OscalLikeEvidence{}
	err = output.FromEvidence(&evidence)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataResponse[*OscalLikeEvidence]{Data: output})
}

// History godoc
//
//	@Summary		Get Evidence history by UUID
//	@Description	Retrieves a the history for a Evidence record by its UUID, including associated activities, inventory items, components, subjects, and labels.
//	@Tags			Evidence
//	@Produce		json
//	@Param			id	path		string	true	"Evidence ID"
//	@Success		200	{object}	GenericDataListResponse[OscalLikeEvidence]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Router			/evidence/history/{id} [get]
func (h *EvidenceHandler) History(ctx echo.Context) error {
	idParam := ctx.Param("id")
	id, err := uuid.Parse(idParam)
	if err != nil {
		h.sugar.Warnw("Invalid evidence id", "id", idParam, "error", err)
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var evidences []relational.Evidence
	if err := h.db.
		Preload("Labels").
		Preload("Activities").
		Preload("Activities.Steps").
		Preload("InventoryItems").
		Preload("Components").
		Preload("Subjects").
		Order("evidences.end DESC").
		Find(&evidences, "uuid = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		h.sugar.Warnw("Failed to load evidence", "id", idParam, "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	output := []*OscalLikeEvidence{}

	for _, e := range evidences {
		out := &OscalLikeEvidence{}
		err = out.FromEvidence(&e)
		if err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
		output = append(output, out)
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[*OscalLikeEvidence]{Data: output})
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
		Data []OscalLikeEvidence `json:"data" yaml:"data"`
	}

	id := ctx.Param("id")
	control := &relational.Control{}
	if err := h.db.Preload("Filters").First(control, "id = ?", id).Error; err != nil {
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

	type StatusCount struct {
		Count  int64  `json:"count"`
		Status string `json:"status"`
	}

	if len(filters) == 0 {
		// If there are no filters assigned for the control, we should return nothing explicitly, otherwise we return everything implicitly
		return ctx.JSON(http.StatusOK, GenericDataListResponse[StatusCount]{Data: []StatusCount{}})
	}

	latestQuery := h.db.Session(&gorm.Session{})
	latestQuery = relational.GetLatestEvidenceStreamsQuery(latestQuery)
	q, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, h.db, filters...)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	evidence := []relational.Evidence{}
	if err := q.Model(&relational.Evidence{}).
		Scan(&evidence).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	response.Data = []OscalLikeEvidence{}
	for _, e := range evidence {
		out := &OscalLikeEvidence{}
		err = out.FromEvidence(&e)
		if err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
		response.Data = append(response.Data, *out)
	}

	return ctx.JSON(http.StatusOK, response)
}

type StatusCount struct {
	Count  int64  `json:"count"`
	Status string `json:"status"`
}

type StatusInterval struct {
	Interval time.Time     `json:"interval"`
	Statuses []StatusCount `json:"statuses"`
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
	var err error
	filter := &labelfilter.Filter{}
	req := filteredSearchRequest{}

	if err = req.bind(ctx, filter); err != nil {
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
		data     []StatusCount
		err      error
	}

	ch := make(chan result, len(intervals))
	now := time.Now()
	for i, d := range intervals {
		go func(i int, d time.Duration) {
			latestQuery := h.db.Session(&gorm.Session{})
			latestQuery = relational.GetLatestEvidenceStreamsQuery(latestQuery)
			if d > 0 {
				latestQuery = latestQuery.Where("evidences.end < ?", now.Add(-d).UTC())
			}
			q, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, h.db, *filter)
			if err != nil {
				ch <- result{idx: i, err: err}
				return
			}
			rows := []StatusCount{}
			if err := q.Model(&relational.Evidence{}).
				Select("count(*) as count, status->>'state' as status").
				Group("status->>'state'").
				Scan(&rows).Error; err != nil {
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
		data     []StatusCount
		err      error
	}

	ch := make(chan result, len(intervals))
	now := time.Now()
	for i, d := range intervals {
		go func(i int, d time.Duration) {
			latestQuery := h.db.Session(&gorm.Session{})
			latestQuery = relational.GetLatestEvidenceStreamsQuery(latestQuery)
			latestQuery = latestQuery.Where("uuid = ?", id.String())
			if d > 0 {
				latestQuery = latestQuery.Where("evidences.end < ?", now.Add(-d).UTC())
			}
			q, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, h.db, labelfilter.Filter{})
			if err != nil {
				ch <- result{idx: i, err: err}
				return
			}
			rows := []StatusCount{}
			if err := q.Model(&relational.Evidence{}).
				Select("count(*) as count, status->>'state' as status").
				Group("status->>'state'").
				Scan(&rows).Error; err != nil {
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
//	@Success		200	{object}	GenericDataListResponse[handler.ComplianceByControl.StatusCount]
//	@Failure		500	{object}	api.Error
//	@Router			/evidence/compliance-by-control/{id} [get]
func (h *EvidenceHandler) ComplianceByControl(ctx echo.Context) error {
	id := ctx.Param("id")
	control := &relational.Control{}
	if err := h.db.Preload("Filters").First(control, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.JSON(http.StatusNotFound, api.NewError(err))
		}
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	filters := []labelfilter.Filter{}
	for _, filter := range control.Filters {
		filters = append(filters, filter.Filter.Data())
	}

	type StatusCount struct {
		Count  int64  `json:"count"`
		Status string `json:"status"`
	}

	if len(filters) == 0 {
		// If there are no filters assigned for the control, we should return nothing explicitly, otherwise we return everything implicitly
		return ctx.JSON(http.StatusOK, GenericDataListResponse[StatusCount]{Data: []StatusCount{}})
	}

	latestQuery := h.db.Session(&gorm.Session{})
	latestQuery = relational.GetLatestEvidenceStreamsQuery(latestQuery)
	q, err := relational.GetEvidenceSearchByFilterQuery(latestQuery, h.db, filters...)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	rows := []StatusCount{}
	if err := q.Model(&relational.Evidence{}).
		Select("count(*) as count, status->>'state' as status").
		Group("status->>'state'").
		Scan(&rows).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, GenericDataListResponse[StatusCount]{Data: rows})
}
