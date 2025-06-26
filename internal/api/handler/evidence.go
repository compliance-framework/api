package handler

import (
	"github.com/compliance-framework/configuration-service/internal"
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	"github.com/compliance-framework/configuration-service/sdk"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"net/http"
	"time"
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
	//api.GET("/over-time", h.OverTime)
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
	Title       *string
	Description string
	Remarks     *string

	// Assigning labels to Evidence makes it searchable and easily usable in the UI
	Labels map[string]string

	// When did we start collecting the evidence, and when did the process end, and how long is it valid for ?
	Start   time.Time
	End     time.Time
	Expires *time.Time

	Props []oscalTypes_1_1_3.Property
	Links []oscalTypes_1_1_3.Link

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

// Create purposefully has no swagger doc to prevent it showing up in the swagger ui. This is for internal use only.
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
		id, err := sdk.SeededUUID(map[string]string{
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
		id, err := sdk.SeededUUID(map[string]string{
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
			id, err = sdk.SeededUUID(map[string]string{
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
		id, err := sdk.SeededUUID(map[string]string{
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
		Labels: func() []relational.Labels {
			result := make([]relational.Labels, 0)
			for key, value := range input.Labels {
				result = append(result, relational.Labels{
					Name:  key,
					Value: value,
				})
			}
			return result
		}(),
		Props: relational.ConvertOscalToProps(&input.Props),
		Links: relational.ConvertOscalToLinks(&input.Links),
		Origins: relational.ConvertList(&input.Origins, func(ol oscalTypes_1_1_3.Origin) relational.Origin {
			out := relational.Origin{}
			out.UnmarshalOscal(ol)
			return out
		}),
		Status: datatypes.NewJSONType(input.Status),
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

	// Return a 201 Created response with no content.
	return ctx.NoContent(http.StatusCreated)
}
