package v1_1

import (
	"encoding/json"

	"github.com/compliance-framework/configuration-service/internal/jsonschema"
	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

// Action An action applied by a role within a given party to the content.
type Action struct {

	// The date and time when the action occurred.
	Date               string              `json:"date,omitempty"`
	Links              []*Link             `json:"links,omitempty"`
	Props              []*Property         `json:"props,omitempty"`
	Remarks            string              `json:"remarks,omitempty"`
	ResponsibleParties []*ResponsibleParty `json:"responsible-parties,omitempty"`

	// Specifies the action type system used.
	System string `json:"system"`

	// The type of action documented by the assembly, such as an approval.
	Type string `json:"type"`

	// A unique identifier that can be used to reference this defined action elsewhere in an OSCAL document. A UUID should be consistently used for a given location across revisions of the document.
	Uuid string `json:"uuid"`
}

// AssessmentLog A log of all assessment-related actions taken.
type AssessmentLog struct {
	Entries []*AssessmentLogEntry `json:"entries"`
}

// AssessmentLogEntry Identifies the result of an action and/or task that occurred as part of executing an assessment plan or an assessment event that occurred in producing the assessment results.
type AssessmentLogEntry struct {

	// A human-readable description of this event.
	Description string `json:"description,omitempty"`

	// Identifies the end date and time of an event. If the event is a point in time, the start and end will be the same date and time.
	End          string               `json:"end,omitempty"`
	Links        []*Link              `json:"links,omitempty"`
	LoggedBy     []*LoggedBy          `json:"logged-by,omitempty"`
	Props        []*Property          `json:"props,omitempty"`
	RelatedTasks []*CommonRelatedTask `json:"related-tasks,omitempty"`
	Remarks      string               `json:"remarks,omitempty"`

	// Identifies the start date and time of an event.
	Start string `json:"start"`

	// The title for this event.
	Title string `json:"title,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference an assessment event in this or other OSCAL instances. The locally defined UUID of the assessment log entry can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// AssessmentSpecificControlObjective A local definition of a control objective for this assessment. Uses catalog syntax for control objective and assessment actions.
type AssessmentSpecificControlObjective struct {

	// A reference to a control with a corresponding id value. When referencing an externally defined control, the Control Identifier Reference must be used in the context of the external / imported OSCAL instance (e.g., uri-reference).
	ControlId string `json:"control-id"`

	// A human-readable description of this control objective.
	Description string      `json:"description,omitempty"`
	Links       []*Link     `json:"links,omitempty"`
	Parts       []*Part     `json:"parts"`
	Props       []*Property `json:"props,omitempty"`
	Remarks     string      `json:"remarks,omitempty"`
}

// AssociatedRisk Relates the finding to a set of referenced risks that were used to determine the finding.
type AssociatedRisk struct {

	// A machine-oriented identifier reference to a risk defined in the list of risks.
	RiskUuid string `json:"risk-uuid"`
}

// AttestationStatements A set of textual statements, typically written by the assessor.
type AttestationStatements struct {
	Parts              []*CommonAssessmentPart `json:"parts"`
	ResponsibleParties []*ResponsibleParty     `json:"responsible-parties,omitempty"`
}

// DocumentMetadata Provides information about the containing document, and defines concepts that are shared across the document.
type DocumentMetadata struct {
	Actions            []*Action               `json:"actions,omitempty"`
	DocumentIds        []*DocumentIdentifier   `json:"document-ids,omitempty"`
	LastModified       string                  `json:"last-modified"`
	Links              []*Link                 `json:"links,omitempty"`
	Locations          []*Location             `json:"locations,omitempty"`
	OscalVersion       string                  `json:"oscal-version"`
	Parties            []*Party                `json:"parties,omitempty"`
	Props              []*Property             `json:"props,omitempty"`
	Published          string                  `json:"published,omitempty"`
	Remarks            string                  `json:"remarks,omitempty"`
	ResponsibleParties []*ResponsibleParty     `json:"responsible-parties,omitempty"`
	Revisions          []*RevisionHistoryEntry `json:"revisions,omitempty"`
	Roles              []*Role                 `json:"roles,omitempty"`

	// A name given to the document, which may be used by a tool for display and navigation.
	Title   string `json:"title"`
	Version string `json:"version"`
}

// Facet An individual characteristic that is part of a larger set produced by the same actor.
type Facet struct {
	Links []*Link `json:"links,omitempty"`

	// The name of the risk metric within the specified system.
	Name    string      `json:"name"`
	Props   []*Property `json:"props,omitempty"`
	Remarks string      `json:"remarks,omitempty"`

	// Specifies the naming system under which this risk metric is organized, which allows for the same names to be used in different systems controlled by different parties. This avoids the potential of a name clash.
	System interface{} `json:"system"`

	// Indicates the value of the facet.
	Value string `json:"value"`
}

// Finding Describes an individual finding.
type Finding struct {

	// A human-readable description of this finding.
	Description string `json:"description"`

	// A machine-oriented identifier reference to the implementation statement in the SSP to which this finding is related.
	ImplementationStatementUuid string                `json:"implementation-statement-uuid,omitempty"`
	Links                       []*Link               `json:"links,omitempty"`
	Origins                     []*Origin             `json:"origins,omitempty"`
	Props                       []*Property           `json:"props,omitempty"`
	RelatedObservations         []*RelatedObservation `json:"related-observations,omitempty"`
	RelatedRisks                []*AssociatedRisk     `json:"related-risks,omitempty"`
	Remarks                     string                `json:"remarks,omitempty"`
	Target                      *Target               `json:"target"`

	// The title for this finding.
	Title string `json:"title"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this finding in this or other OSCAL instances. The locally defined UUID of the finding can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// IdentifiedRisk An identified risk.
type IdentifiedRisk struct {
	Characterizations []*Characterization `json:"characterizations,omitempty"`

	// The date/time by which the risk must be resolved.
	Deadline string `json:"deadline,omitempty"`

	// A human-readable summary of the identified risk, to include a statement of how the risk impacts the system.
	Description         string                `json:"description"`
	Links               []*Link               `json:"links,omitempty"`
	MitigatingFactors   []*MitigatingFactor   `json:"mitigating-factors,omitempty"`
	Origins             []*Origin             `json:"origins,omitempty"`
	Props               []*Property           `json:"props,omitempty"`
	RelatedObservations []*RelatedObservation `json:"related-observations,omitempty"`
	Remediations        []*CommonResponse     `json:"remediations,omitempty"`

	// A log of all risk-related tasks taken.
	RiskLog *RiskLog `json:"risk-log,omitempty"`

	// An summary of impact for how the risk affects the system.
	Statement string            `json:"statement"`
	Status    interface{}       `json:"status"`
	ThreatIds []*CommonThreatId `json:"threat-ids,omitempty"`

	// The title for this risk.
	Title string `json:"title"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this risk elsewhere in this or other OSCAL instances. The locally defined UUID of the risk can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// ImportAssessmentPlan Used by assessment-results to import information about the original plan for assessing the system.
type ImportAssessmentPlan struct {

	// A resolvable URL reference to the assessment plan governing the assessment activities.
	Href    string `json:"href"`
	Remarks string `json:"remarks,omitempty"`
}

// AssessmentResultLocalDefinitions Used to define data objects that are used in the assessment plan, that do not appear in the referenced SSP.
type AssessmentResultLocalDefinitions struct {
	Activities           []*CommonActivity                     `json:"activities,omitempty"`
	ObjectivesAndMethods []*AssessmentSpecificControlObjective `json:"objectives-and-methods,omitempty"`
	Remarks              string                                `json:"remarks,omitempty"`
}

// Location A physical point of presence, which may be associated with people, organizations, or other concepts within the current or linked OSCAL document.
type Location struct {
	Address          *Address           `json:"address,omitempty"`
	EmailAddresses   []interface{}      `json:"email-addresses,omitempty"`
	Links            []*Link            `json:"links,omitempty"`
	Props            []*Property        `json:"props,omitempty"`
	Remarks          string             `json:"remarks,omitempty"`
	TelephoneNumbers []*TelephoneNumber `json:"telephone-numbers,omitempty"`

	// A name given to the location, which may be used by a tool for display and navigation.
	Title string   `json:"title,omitempty"`
	Urls  []string `json:"urls,omitempty"`

	// A unique ID for the location, for reference.
	Uuid string `json:"uuid"`
}

// LoggedBy Used to indicate who created a log entry in what role.
type LoggedBy struct {

	// A machine-oriented identifier reference to the party who is making the log entry.
	PartyUuid string `json:"party-uuid"`

	// A point to the role-id of the role in which the party is making the log entry.
	RoleId string `json:"role-id,omitempty"`
}

// MitigatingFactor Describes an existing mitigating factor that may affect the overall determination of the risk, with an optional link to an implementation statement in the SSP.
type MitigatingFactor struct {

	// A human-readable description of this mitigating factor.
	Description string `json:"description"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this implementation statement elsewhere in this or other OSCAL instancess. The locally defined UUID of the implementation statement can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	ImplementationUuid string                  `json:"implementation-uuid,omitempty"`
	Links              []*Link                 `json:"links,omitempty"`
	Props              []*Property             `json:"props,omitempty"`
	Subjects           []*IdentifiesTheSubject `json:"subjects,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this mitigating factor elsewhere in this or other OSCAL instances. The locally defined UUID of the mitigating factor can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// ObjectiveStatus A determination of if the objective is satisfied or not within a given system.
type ObjectiveStatus struct {
	State interface{} `json:"state"`
}

// ObjectiveStatus A determination of if the objective is satisfied or not within a given system.
type Target struct {

	// The reason the objective was given it's status.
	Type     string           `json:"type,omitempty"`
	TargetId string           `json:"target-id,omitempty"`
	Status   *ObjectiveStatus `json:"status,omitempty"`
	Remarks  string           `json:"remarks,omitempty"`
}

// Origin Identifies the source of the finding, such as a tool, interviewed person, or activity.
type Origin struct {
	Actors       []*OriginActor   `json:"actors"`
	RelatedTasks []*TaskReference `json:"related-tasks,omitempty"`
}

// Result Used by the assessment results and POA&M. In the assessment results, this identifies all of the assessment observations and findings, initial and residual risks, deviations, and disposition. In the POA&M, this identifies initial and residual risks, deviations, and disposition.
type Result struct {

	// A log of all assessment-related actions taken.
	AssessmentLog *AssessmentLog           `json:"assessment-log,omitempty"`
	Attestations  []*AttestationStatements `json:"attestations,omitempty"`

	// A human-readable description of this set of test results.
	Description string `json:"description"`

	// Date/time stamp identifying the end of the evidence collection reflected in these results. In a continuous motoring scenario, this may contain the same value as start if appropriate.
	End      string     `json:"end,omitempty"`
	Findings []*Finding `json:"findings,omitempty"`
	Links    []*Link    `json:"links,omitempty"`

	// Used to define data objects that are used in the assessment plan, that do not appear in the referenced SSP.
	LocalDefinitions *LocalDefinitions                     `json:"local-definitions,omitempty"`
	Observations     []*Observation                        `json:"observations,omitempty"`
	Props            []*Property                           `json:"props,omitempty"`
	Remarks          string                                `json:"remarks,omitempty"`
	ReviewedControls *ReviewedControlsAndControlObjectives `json:"reviewed-controls"`
	Risks            []*IdentifiedRisk                     `json:"risks,omitempty"`

	// Date/time stamp identifying the start of the evidence collection reflected in these results.
	Start string `json:"start"`

	// The title for this set of results.
	Title string `json:"title"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this set of results in this or other OSCAL instances. The locally defined UUID of the assessment result can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// Characterization A collection of descriptive data about the containing object from a specific origin.
type Characterization struct {
	Facets []*Facet    `json:"facets"`
	Links  []*Link     `json:"links,omitempty"`
	Origin *Origin     `json:"origin"`
	Props  []*Property `json:"props,omitempty"`
}

// Observation Describes an individual observation.
type Observation struct {

	// Date/time stamp identifying when the finding information was collected.
	Collected string `json:"collected"`

	// A human-readable description of this assessment observation.
	Description string `json:"description"`

	// Date/time identifying when the finding information is out-of-date and no longer valid. Typically used with continuous assessment scenarios.
	Expires          string                  `json:"expires,omitempty"`
	Links            []*Link                 `json:"links,omitempty"`
	Methods          []interface{}           `json:"methods"`
	Origins          []*Origin               `json:"origins,omitempty"`
	Props            []*Property             `json:"props,omitempty"`
	RelevantEvidence []*RelevantEvidence     `json:"relevant-evidence,omitempty"`
	Remarks          string                  `json:"remarks,omitempty"`
	Subjects         []*IdentifiesTheSubject `json:"subjects,omitempty"`

	// The title for this observation.
	Title string        `json:"title,omitempty"`
	Types []interface{} `json:"types,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this observation elsewhere in this or other OSCAL instances. The locally defined UUID of the observation can be used to reference the data item locally or globally (e.g., in an imorted OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// OriginActor The actor that produces an observation, a finding, or a risk. One or more actor type can be used to specify a person that is using a tool.
type OriginActor struct {

	// A machine-oriented identifier reference to the tool or person based on the associated type.
	ActorUuid string      `json:"actor-uuid"`
	Links     []*Link     `json:"links,omitempty"`
	Props     []*Property `json:"props,omitempty"`

	// For a party, this can optionally be used to specify the role the actor was performing.
	RoleId string `json:"role-id,omitempty"`

	// The kind of actor.
	Type interface{} `json:"type"`
}

// CommonRelatedTask Identifies an individual task for which the containing object is a consequence of.
type CommonRelatedTask struct {

	// Used to detail assessment subjects that were identfied by this task.
	IdentifiedSubject  *IdentifiedSubject   `json:"identified-subject,omitempty"`
	Links              []*Link              `json:"links,omitempty"`
	Props              []*Property          `json:"props,omitempty"`
	Remarks            string               `json:"remarks,omitempty"`
	ResponsibleParties []*ResponsibleParty  `json:"responsible-parties,omitempty"`
	Subjects           []*AssessmentSubject `json:"subjects,omitempty"`

	// A machine-oriented identifier reference to a unique task.
	TaskUuid string `json:"task-uuid"`
}

// CommonResponse Describes either recommended or an actual plan for addressing the risk.
type CommonResponse struct {

	// A human-readable description of this response plan.
	Description string `json:"description"`

	// Identifies whether this is a recommendation, such as from an assessor or tool, or an actual plan accepted by the system owner.
	Lifecycle      interface{}      `json:"lifecycle"`
	Links          []*Link          `json:"links,omitempty"`
	Origins        []*Origin        `json:"origins,omitempty"`
	Props          []*Property      `json:"props,omitempty"`
	Remarks        string           `json:"remarks,omitempty"`
	RequiredAssets []*RequiredAsset `json:"required-assets,omitempty"`
	Tasks          []*Task          `json:"tasks,omitempty"`

	// The title for this response activity.
	Title string `json:"title"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this remediation elsewhere in this or other OSCAL instances. The locally defined UUID of the risk response can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// CommonThreatId A pointer, by ID, to an externally-defined threat.
type CommonThreatId struct {

	// An optional location for the threat data, from which this ID originates.
	Href string `json:"href,omitempty"`
	Id   string `json:"id"`

	// Specifies the source of the threat information.
	System interface{} `json:"system"`
}

// RelatedObservation Relates the finding to a set of referenced observations that were used to determine the finding.
type RelatedObservation struct {

	// A machine-oriented identifier reference to an observation defined in the list of observations.
	ObservationUuid string `json:"observation-uuid"`
}

// RelevantEvidence Links this observation to relevant evidence.
type RelevantEvidence struct {

	// A human-readable description of this evidence.
	Description string `json:"description"`

	// A resolvable URL reference to relevant evidence.
	Href    string      `json:"href,omitempty"`
	Links   []*Link     `json:"links,omitempty"`
	Props   []*Property `json:"props,omitempty"`
	Remarks string      `json:"remarks,omitempty"`
}

// RequiredAsset Identifies an asset required to achieve remediation.
type RequiredAsset struct {

	// A human-readable description of this required asset.
	Description string                  `json:"description"`
	Links       []*Link                 `json:"links,omitempty"`
	Props       []*Property             `json:"props,omitempty"`
	Remarks     string                  `json:"remarks,omitempty"`
	Subjects    []*IdentifiesTheSubject `json:"subjects,omitempty"`

	// The title for this required asset.
	Title string `json:"title,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this required asset elsewhere in this or other OSCAL instances. The locally defined UUID of the asset can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// RevisionHistoryEntry An entry in a sequential list of revisions to the containing document, expected to be in reverse chronological order (i.e. latest first).
type RevisionHistoryEntry struct {
	LastModified string      `json:"last-modified,omitempty"`
	Links        []*Link     `json:"links,omitempty"`
	OscalVersion string      `json:"oscal-version,omitempty"`
	Props        []*Property `json:"props,omitempty"`
	Published    string      `json:"published,omitempty"`
	Remarks      string      `json:"remarks,omitempty"`

	// A name given to the document revision, which may be used by a tool for display and navigation.
	Title   string `json:"title,omitempty"`
	Version string `json:"version"`
}

// RiskLog A log of all risk-related tasks taken.
type RiskLog struct {
	Entries []*RiskLogEntry `json:"entries"`
}

// RiskLogEntry Identifies an individual risk response that occurred as part of managing an identified risk.
type RiskLogEntry struct {

	// A human-readable description of what was done regarding the risk.
	Description string `json:"description,omitempty"`

	// Identifies the end date and time of the event. If the event is a point in time, the start and end will be the same date and time.
	End              string                   `json:"end,omitempty"`
	Links            []*Link                  `json:"links,omitempty"`
	LoggedBy         []*LoggedBy              `json:"logged-by,omitempty"`
	Props            []*Property              `json:"props,omitempty"`
	RelatedResponses []*RiskResponseReference `json:"related-responses,omitempty"`
	Remarks          string                   `json:"remarks,omitempty"`

	// Identifies the start date and time of the event.
	Start        string      `json:"start"`
	StatusChange interface{} `json:"status-change,omitempty"`

	// The title for this risk log entry.
	Title string `json:"title,omitempty"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this risk log entry elsewhere in this or other OSCAL instances. The locally defined UUID of the risk log entry can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// RiskResponseReference Identifies an individual risk response that this log entry is for.
type RiskResponseReference struct {
	Links        []*Link              `json:"links,omitempty"`
	Props        []*Property          `json:"props,omitempty"`
	RelatedTasks []*CommonRelatedTask `json:"related-tasks,omitempty"`
	Remarks      string               `json:"remarks,omitempty"`

	// A machine-oriented identifier reference to a unique risk response.
	ResponseUuid string `json:"response-uuid"`
}

// TaskReference Identifies an individual task for which the containing object is a consequence of.
type TaskReference struct {

	// Used to detail assessment subjects that were identfied by this task.
	IdentifiedSubject  *IdentifiedSubject   `json:"identified-subject,omitempty"`
	Links              []*Link              `json:"links,omitempty"`
	Props              []*Property          `json:"props,omitempty"`
	Remarks            string               `json:"remarks,omitempty"`
	ResponsibleParties []*ResponsibleParty  `json:"responsible-parties,omitempty"`
	Subjects           []*AssessmentSubject `json:"subjects,omitempty"`

	// A machine-oriented identifier reference to a unique task.
	TaskUuid string `json:"task-uuid"`
}

// AssessmentResult Security assessment results, such as those provided by a FedRAMP assessor in the FedRAMP Security Assessment Report.
type AssessmentResult struct {
	BackMatter *BackMatter           `json:"back-matter,omitempty"`
	ImportAp   *ImportAssessmentPlan `json:"import-ap"`

	// Used to define data objects that are used in the assessment plan, that do not appear in the referenced SSP.
	LocalDefinitions *AssessmentResultLocalDefinitions `json:"local-definitions,omitempty"`
	Metadata         *DocumentMetadata                 `json:"metadata"`
	Results          []*Result                         `json:"results"`

	// A machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this assessment results instance in this or other OSCAL instances. The locally defined UUID of the assessment result can be used to reference the data item locally or globally (e.g., in an imported OSCAL instance). This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// Automatic Register methods. add these for the schema to be fully CRUD-registered
func (c *AssessmentResult) FromJSON(b []byte) error {
	return json.Unmarshal(b, c)
}

func (c *AssessmentResult) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

func (c *AssessmentResult) DeepCopy() schema.BaseModel {
	d := &AssessmentResult{}
	p, err := c.ToJSON()
	if err != nil {
		panic(err)
	}
	err = d.FromJSON(p)
	if err != nil {
		panic(err)
	}
	return d
}

func (c *AssessmentResult) UUID() string {
	return c.Uuid
}

// TODO Add tests
func (c *AssessmentResult) Validate() error {

	sch, err := jsonschema.Compile("https://github.com/usnistgov/OSCAL/releases/download/v1.1.0/oscal_assessment-results_schema.json")
	if err != nil {
		return err
	}
	var p = map[string]interface{}{
		"assessment-results": c,
	}
	d, err := json.Marshal(p)
	if err != nil {
		return err
	}
	err = json.Unmarshal(d, &p)
	if err != nil {
		return err
	}
	return sch.Validate(p)
}
func (c *AssessmentResult) Type() string {
	return "assessment-result"
}

func init() {
	schema.MustRegister("assessment-result", &AssessmentResult{})
}
