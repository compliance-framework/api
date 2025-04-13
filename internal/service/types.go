package service

import (
	"github.com/compliance-framework/configuration-service/internal/converters/labelfilter"
	"github.com/compliance-framework/configuration-service/sdk/types"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"time"
)

type Observation struct {
	// ID is the unique ID for this specific observation, and will be used as the primary key in the database.
	ID *uuid.UUID `json:"_id,omitempty" yaml:"_id,omitempty" bson:"_id,omitempty"`

	// UUID needs to remain consistent when automation runs again, but unique for each subject.
	// It represents the "stream" of the same observation being made over time.
	UUID        uuid.UUID `json:"uuid" yaml:"uuid"`
	Title       *string   `json:"title,omitempty" yaml:"title,omitempty"`
	Description string    `json:"description" yaml:"description"`
	Remarks     *string   `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	Collected time.Time         `json:"collected" yaml:"collected"`
	Expires   *time.Time        `json:"expires,omitempty" yaml:"expires,omitempty"`
	Methods   *[]string         `json:"methods" yaml:"methods"`
	Links     *[]types.Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props     *[]types.Property `json:"props,omitempty" yaml:"props,omitempty"`

	// Who is generating this finding
	Origins *[]types.Origin `json:"origins,omitempty" yaml:"origins,omitempty"`
	// What are we observing
	SubjectIDs *[]uuid.UUID `json:"subjects,omitempty" yaml:"subjects,omitempty"`
	// What steps did we take to make this observation
	Activities *[]types.Activity `json:"activities,omitempty" yaml:"activities,omitempty"`
	// Which components of the subject are being observed
	ComponentIDs *[]uuid.UUID `json:"components,omitempty" yaml:"components,omitempty"`
	// What exactly did we see
	RelevantEvidence *[]types.RelevantEvidence `json:"relevant-evidence,omitempty" yaml:"relevant-evidence,omitempty"`
}

type Finding struct {
	// ID is the unique ID for this specific observation, and will be used as the primary key in the database.
	ID *uuid.UUID `json:"_id,omitempty" yaml:"_id,omitempty" bson:"_id,omitempty"`

	// UUID needs to remain consistent when automation runs again, but unique for each subject.
	// It represents the "stream" of the same finding being made over time.
	UUID        uuid.UUID `json:"uuid" yaml:"uuid"`
	Title       string    `json:"title" yaml:"title"`
	Description string    `json:"description" yaml:"description"`
	Collected   time.Time `json:"collected" yaml:"collected"`
	Remarks     *string   `json:"remarks,omitempty" yaml:"remarks,omitempty"`

	// Labels represent the unique labels which can be used to filter for findings in the UI.
	Labels map[string]string `json:"labels" yaml:"labels"`

	// Who is generating this finding
	Origins *[]types.Origin `json:"origins,omitempty" yaml:"origins,omitempty"`
	// What are we making a judgement against
	SubjectIDs *[]uuid.UUID `json:"subjects,omitempty" yaml:"subjects,omitempty"`
	// Which components of the subject are being judged
	ComponentIDs *[]uuid.UUID `json:"components,omitempty" yaml:"components,omitempty"`
	// Which observations led to this judgment ?
	ObservationIDs *[]uuid.UUID `json:"observations,omitempty" yaml:"observations,omitempty"`
	// Which controls did we validate
	Controls *[]types.ControlReference `json:"controls,omitempty" yaml:"controls,omitempty"`
	// Which risks are associated with what we've tested
	Risks *[]types.RiskReference `json:"risks,omitempty" yaml:"risks,omitempty"`
	// What is our conclusion drawn for this finding. satisfied | not-satisfied
	Status types.FindingStatus `json:"status" yaml:"status"`

	Links *[]types.Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props *[]types.Property `json:"props,omitempty" yaml:"props,omitempty"`
}

type Subject struct {
	ID         *uuid.UUID        `json:"_id" yaml:"_id" bson:"_id"`
	Type       string            `json:"type" yaml:"type"`
	Title      string            `json:"title,omitempty" yaml:"title,omitempty"`
	Remarks    string            `json:"remarks,omitempty" yaml:"remarks,omitempty"`
	Attributes map[string]string `json:"attributes" yaml:"attributes"`
	Links      *[]types.Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props      *[]types.Property `json:"props,omitempty" yaml:"props,omitempty"`
}

type Component struct {
	ID *uuid.UUID `json:"_id" yaml:"_id" bson:"_id"`

	// A reference for this component. Example: `common-components/mongodb` or `internal-components/logging-system`
	Identifier string `json:"identifier" yaml:"identifier"`

	// Type represents the type of component.
	// "this-system"|"system"|"interconnection"|"software"|"hardware"|"service"|"policy"|"physical"|"process-procedure"|"plan"|"guidance"|"standard"|"validation"|"network"
	Type string `json:"type,omitempty" yaml:"type,omitempty"`

	Title       string `json:"title,omitempty" yaml:"title,omitempty"`
	Description string `json:"description" yaml:"description"`
	Remarks     string `json:"remarks" yaml:"remarks"`
	Purpose     string `json:"purpose" yaml:"purpose"`

	Links *[]types.Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props *[]types.Property `json:"props,omitempty" yaml:"props,omitempty"`

	// Status represents the current status of the component
	// "under-development"|"operational"|"disposition"|"other"
	// For the moment we are using the OSCAL types, as we don't know what to do with these yet.
	Status           *[]oscalTypes_1_1_3.SystemComponentStatus `json:"status,omitempty" yaml:"status,omitempty"`
	Protocols        *[]oscalTypes_1_1_3.Protocol              `json:"protocols,omitempty" yaml:"protocols,omitempty"`
	ResponsibleRoles *[]oscalTypes_1_1_3.ResponsibleRole       `json:"responsible-role,omitempty" yaml:"responsible-role,omitempty"`
}

type Dashboard struct {
	UUID   *uuid.UUID         `bson:"_id" json:"uuid" yaml:"uuid"`
	Name   string             `json:"name" yaml:"name" bson:"name"`
	Filter labelfilter.Filter `bson:"filter" json:"filter" yaml:"filter"`
}

type Catalog struct {
	UUID     *uuid.UUID                `bson:"_id" json:"uuid" yaml:"uuid"`
	Metadata oscalTypes_1_1_3.Metadata `json:"metadata" yaml:"metadata"`
}

type CatalogItemParentType string

const (
	CatalogItemParentTypeControl CatalogItemParentType = "control"
	CatalogItemParentTypeGroup   CatalogItemParentType = "group"
	CatalogItemParentTypeCatalog CatalogItemParentType = "catalog"
)

// CatalogItemParentIdentifier is used to identify the parent for groups and controls.
// A group or control can belong to either a catalog or a group. In that case:
// type=catalog|group
// id=<parent-id>
// class=<likely-parent-class> # Not sure about this, so for safety it's included.
//
// This allows us  a flat database hierarchy so we can easily search for singular controls.
type CatalogItemParentIdentifier struct {
	ID        string                `json:"id" yaml:"id"`
	Class     string                `json:"class" yaml:"class"`
	Type      CatalogItemParentType `json:"type" yaml:"type"`
	CatalogId uuid.UUID             `json:"catalog_id" yaml:"catalog_id"`
}

type CatalogGroup struct {
	// UUID as a primary key, although it likely won't be used.
	// The primary key for a group consists of a compound (class + id)
	UUID   *uuid.UUID                   `bson:"_id" json:"uuid" yaml:"uuid"`
	ID     string                       `json:"id,omitempty" yaml:"id,omitempty"`
	Title  string                       `json:"title" yaml:"title"`
	Class  string                       `json:"class,omitempty" yaml:"class,omitempty"`
	Parts  *[]oscalTypes_1_1_3.Part     `json:"parts,omitempty" yaml:"parts,omitempty"`
	Parent CatalogItemParentIdentifier  `json:"parent,omitempty" yaml:"parent,omitempty"`
	Links  *[]oscalTypes_1_1_3.Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props  *[]oscalTypes_1_1_3.Property `json:"props,omitempty" yaml:"props,omitempty"`
}

type CatalogControl struct {
	// UUID as a primary key, although it likely won't be used.
	// The primary key for a group consists of a compound (class + id)
	UUID   *uuid.UUID                   `bson:"_id" json:"uuid" yaml:"uuid"`
	ID     string                       `json:"id,omitempty" yaml:"id,omitempty"`
	Title  string                       `json:"title" yaml:"title"`
	Class  string                       `json:"class,omitempty" yaml:"class,omitempty"`
	Parts  *[]oscalTypes_1_1_3.Part     `json:"parts,omitempty" yaml:"parts,omitempty"`
	Parent CatalogItemParentIdentifier  `json:"parent,omitempty" yaml:"parent,omitempty"`
	Links  *[]oscalTypes_1_1_3.Link     `json:"links,omitempty" yaml:"links,omitempty"`
	Props  *[]oscalTypes_1_1_3.Property `json:"props,omitempty" yaml:"props,omitempty"`
}
