package v1_1

import (
	"encoding/json"

	"github.com/compliance-framework/configuration-service/internal/jsonschema"
	"github.com/compliance-framework/configuration-service/internal/models/schema"
)

// Action represents an action applied by a role within a given party to the content
// in the context of the Open Security Controls Assessment Language (OSCAL) model.
// This could be an approval of a system security plan, a risk assessment, or any other action
// that's part of a compliance or security assessment process.
type Action struct {

	// Date represents the date and time when the action occurred.
	// It should be in a format that can be parsed by Go's time package, e.g., "2006-01-02T15:04:05Z07:00".
	Date string `json:"date,omitempty"`

	// Links are a collection of Link structures, representing hyperlinks related to the action.
	// For example, this could be a link to a document or resource relevant to the action.
	Links []*Link `json:"links,omitempty"`

	// Props are a collection of Property structures, representing additional properties or metadata about the action.
	// For example, this could include a description of the action, its status, or other relevant details.
	Props []*Property `json:"props,omitempty"`

	// Remarks is a string that can be used to provide additional comments or notes about the action.
	Remarks string `json:"remarks,omitempty"`

	// ResponsibleParties is a collection of ResponsibleParty structures,
	// representing the parties or roles responsible for the action.
	// For example, this could be the person or team who performed an assessment or approved a document.
	ResponsibleParties []*ResponsibleParty `json:"responsible-parties,omitempty"`

	// System specifies the action type system used. This could be a classification or categorization system
	// used by an organization to track or manage actions. For example, "ISO 27001" or "NIST 800-53".
	System string `json:"system"`

	// Type represents the type of action documented by the assembly, such as an approval, assessment, or review.
	// This should be a string that briefly and clearly describes the action.
	Type string `json:"type"`

	// Uuid is a unique identifier that can be used to reference this defined action elsewhere in an OSCAL document.
	// A UUID should be consistently used for a given location across revisions of the document.
	// For example, "123e4567-e89b-12d3-a456-426614174000".
	Uuid string `json:"uuid"`
}

// AssessmentLog represents a log of all assessment-related actions taken
// in the context of the Open Security Controls Assessment Language (OSCAL) model.
// An AssessmentLog is essentially a chronological record of all actions
// and decisions made during an assessment process.
type AssessmentLog struct {
	// Entries is a collection of AssessmentLogEntry structures, each representing a single action or event
	// that has occurred during the assessment. This could include actions like the approval of a security plan,
	// the completion of a risk assessment, or the decision to accept or mitigate a particular risk.
	// For example, an entry might record that a specific catalog was reviewed and approved at a particular time by a particular party.
	Entries []*AssessmentLogEntry `json:"entries"`
}

// AssessmentLogEntry identifies the result of an action and/or task that occurred
// as part of executing an assessment plan or an assessment event that occurred
// in producing the assessment results in the context of the Open Security Controls Assessment Language (OSCAL) model.
// An AssessmentLogEntry is essentially a record of a single event or action during an assessment process.
type AssessmentLogEntry struct {

	// Description is a human-readable explanation of this event.
	// It should provide enough information for someone unfamiliar with the specific event to understand what happened.
	// For example, "Review and approval of security catalog AC-1."
	Description string `json:"description,omitempty"`

	// End identifies the end date and time of an event.
	// It should be in a format that can be parsed by Go's time package, e.g., "2006-01-02T15:04:05Z07:00".
	// If the event is a point in time, the start and end will be the same date and time.
	End string `json:"end,omitempty"`

	// Links are a collection of Link structures, representing hyperlinks related to the event.
	// For example, this could be a link to a document or resource relevant to the event.
	Links []*Link `json:"links,omitempty"`

	// LoggedBy is a collection of LoggedBy structures, representing the parties or roles
	// responsible for logging the event. For example, this could be the person or team who performed an assessment.
	LoggedBy []*LoggedBy `json:"logged-by,omitempty"`

	// Props are a collection of Property structures, representing additional properties or metadata about the event.
	// For example, this could include a status of the event, its outcome, or other relevant details.
	Props []*Property `json:"props,omitempty"`

	// RelatedTasks is a collection of CommonRelatedTask structures, representing tasks related to the event.
	// For example, this could be tasks that were triggered by the event, or tasks that led up to the event.
	RelatedTasks []*CommonRelatedTask `json:"related-tasks,omitempty"`

	// Remarks is a string that can be used to provide additional comments or notes about the event.
	Remarks string `json:"remarks,omitempty"`

	// Start identifies the start date and time of an event.
	// It should be in a format that can be parsed by Go's time package, e.g., "2006-01-02T15:04:05Z07:00".
	Start string `json:"start"`

	// Title is a brief, human-readable label for this event,
	// such as "Security Control Review" or "Risk Assessment Completion".
	Title string `json:"title,omitempty"`

	// Uuid is a unique identifier that can be used to reference this event elsewhere in an OSCAL document.
	// A UUID should be consistently used for a given location across revisions of the document.
	// For example, "123e4567-e89b-12d3-a456-426614174000".
	Uuid string `json:"uuid"`
}

// AssessmentSpecificControlObjective represents a local definition of a catalog objective for this assessment.
// It uses catalog syntax for catalog objective and assessment actions within the Open Security Controls Assessment Language (OSCAL) model.
// An AssessmentSpecificControlObjective could be used to define a custom objective for a specific catalog in a specific assessment.
type AssessmentSpecificControlObjective struct {

	// ControlId is a reference to a catalog with a corresponding id value. When referencing an externally defined catalog,
	// the Control Identifier Reference must be used in the context of the external / imported OSCAL instance (e.g., uri-reference).
	// For example, this could be the ID of a catalog in the NIST 800-53 catalog, like "AC-2".
	ControlId string `json:"catalog-id"`

	// Description is a human-readable explanation of this catalog objective.
	// It should provide enough information for someone unfamiliar with the specific objective to understand its purpose.
	// For example, "Ensure that the system enforces approved authorizations for logical access to information and system functions in accordance with applicable policy."
	Description string `json:"description,omitempty"`

	// Links are a collection of Link structures, representing hyperlinks related to the catalog objective.
	// For example, this could be a link to a document or resource relevant to the objective.
	Links []*Link `json:"links,omitempty"`

	// Parts are a collection of Part structures, representing the component parts of the catalog objective.
	// This could include statements, guidelines, or other elements that together define the objective.
	Parts []*Part `json:"parts"`

	// Props are a collection of Property structures, representing additional properties or metadata about the catalog objective.
	// For example, this could include a status of the objective, its priority, or other relevant details.
	Props []*Property `json:"props,omitempty"`

	// Remarks is a string that can be used to provide additional comments or notes about the catalog objective.
	Remarks string `json:"remarks,omitempty"`
}

// AssociatedRisk represents a relationship between a finding and a set of referenced risks that were used to determine the finding
// within the Open Security Controls Assessment Language (OSCAL) model.
// An AssociatedRisk is used to link a specific finding or result to a specific risk that was considered during the assessment.
type AssociatedRisk struct {

	// RiskUuid is a machine-oriented identifier reference to a risk defined in the list of risks.
	// It should match the UUID of a risk defined elsewhere in the same OSCAL document.
	// For example, "123e4567-e89b-12d3-a456-426614174000".
	RiskUuid string `json:"risk-uuid"`
}

// AttestationStatements represents a set of textual statements, typically written by the assessor, within the Open Security Controls Assessment Language (OSCAL) model.
// An AttestationStatements could include conclusions, judgments, or recommendations based on the results of the assessment.
type AttestationStatements struct {
	// Parts are a collection of CommonAssessmentPart structures, representing the individual statements or assertions made by the assessor.
	// For example, this could include a statement that a particular catalog is effectively implemented, or a recommendation to improve a certain process.
	Parts []*CommonAssessmentPart `json:"parts"`

	// ResponsibleParties is a collection of ResponsibleParty structures, representing the parties or roles responsible for the attestation statements.
	// For example, this could be the person or team who performed the assessment and made the statements.
	ResponsibleParties []*ResponsibleParty `json:"responsible-parties,omitempty"`
}

// DocumentMetadata provides information about the containing document,
// and defines concepts that are shared across the document within the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes details like the document's title, version, and modification history, as well as references to the parties, roles, and actions defined in the document.
type DocumentMetadata struct {
	// Actions is a collection of Action structures, representing actions defined in the document.
	// These could be actions like approval, review, or assessment that are mentioned or referenced in the document.
	Actions []*Action `json:"actions,omitempty"`

	// DocumentIds is a collection of DocumentIdentifier structures, representing different identifiers assigned to the document.
	// For example, this could include an internal ID used by an organization, or a unique ID assigned by a regulatory body.
	DocumentIds []*DocumentIdentifier `json:"document-ids,omitempty"`

	// LastModified is the date and time when the document was last modified.
	// It should be in a format that can be parsed by Go's time package, e.g., "2006-01-02T15:04:05Z07:00".
	LastModified string `json:"last-modified"`

	// Links are a collection of Link structures, representing hyperlinks related to the document.
	// For example, this could include links to related documents or resources.
	Links []*Link `json:"links,omitempty"`

	// Locations is a collection of Location structures, representing physical or logical locations mentioned or referenced in the document.
	Locations []*Location `json:"locations,omitempty"`

	// OscalVersion is the version of the OSCAL model that the document conforms to.
	// For example, "1.0.0".
	OscalVersion string `json:"oscal-version"`

	// Parties is a collection of Party structures, representing the parties or roles mentioned or referenced in the document.
	// This could include individuals, teams, or organizations involved in the processes or activities described in the document.
	Parties []*Party `json:"parties,omitempty"`

	// Props are a collection of Property structures, representing additional properties or metadata about the document.
	// For example, this could include a status of the document, its classification, or other relevant details.
	Props []*Property `json:"props,omitempty"`

	// Published is the date and time when the document was published.
	// It should be in a format that can be parsed by Go's time package, e.g., "2006-01-02T15:04:05Z07:00".
	Published string `json:"published,omitempty"`

	// Remarks is a string that can be used to provide additional comments or notes about the document.
	Remarks string `json:"remarks,omitempty"`

	// ResponsibleParties is a collection of ResponsibleParty structures, representing the parties or roles responsible for the document.
	// For example, this could be the person or team who authored the document, or the party responsible for its maintenance.
	ResponsibleParties []*ResponsibleParty `json:"responsible-parties,omitempty"`

	// Revisions is a collection of RevisionHistoryEntry structures, representing the revision history of the document.
	// Each entry should include details about a specific revision, like the date, the person who made the change, and a description of the change.
	Revisions []*RevisionHistoryEntry `json:"revisions,omitempty"`

	// Roles is a collection of Role structures, representing the roles defined or mentioned in the document.
	// This could include roles like "assessor", "approver", or "system owner" that are part of the processes or
	// activities described in the document.
	Roles []*Role `json:"roles,omitempty"`

	// Title is a name given to the document, which may be used by a tool for display and navigation.
	// For example, "Security Assessment Report".
	Title string `json:"title"`

	// Version is the specific version of the document.
	// This could be a version number like "1.0", or a more descriptive version label like "Draft" or "Final".
	Version string `json:"version"`
}

// Facet represents an individual characteristic that is part of a larger set produced by the same actor in the context of the Open Security Controls Assessment Language (OSCAL) model.
// A Facet could represent a specific aspect or dimension of a risk, such as its likelihood or impact.
type Facet struct {
	// Links are a collection of Link structures, representing hyperlinks related to the facet.
	// For example, this could include links to resources providing more details about the facet.
	Links []*Link `json:"links,omitempty"`

	// Name is the name of the risk metric within the specified system.
	// For example, this could be "Likelihood" or "Impact".
	Name string `json:"name"`

	// Props are a collection of Property structures, representing additional properties or metadata about the facet.
	// For example, this could include a scale or range for the facet's values.
	Props []*Property `json:"props,omitempty"`

	// Remarks is a string that can be used to provide additional comments or notes about the facet.
	Remarks string `json:"remarks,omitempty"`

	// System specifies the naming system under which this risk metric is organized.
	// This allows for the same names to be used in different systems controlled by different parties and avoids the potential of a name clash.
	System interface{} `json:"system"`

	// Value indicates the value of the facet.
	// For example, this could be "High", "Medium", or "Low" for a likelihood facet.
	Value string `json:"value"`
}

// Finding represents a specific result or conclusion drawn during an assessment in the context of the Open Security Controls Assessment Language (OSCAL) model.
// A Finding could represent a weakness, vulnerability, or non-compliance identified during the assessment.
type Finding struct {

	// Description is a human-readable explanation of this finding.
	// It should provide enough information for someone unfamiliar with the specific finding to understand what was found and why it matters.
	Description string `json:"description"`

	// ImplementationStatementUuid is a machine-oriented identifier reference to the implementation statement in the System Security Plan (SSP) to which this finding is related.
	// For example, "123e4567-e89b-12d3-a456-426614174000".
	ImplementationStatementUuid string `json:"implementation-statement-uuid,omitempty"`

	// Links are a collection of Link structures, representing hyperlinks related to the finding.
	// For example, this could include links to resources providing more details about the finding.
	Links []*Link `json:"links,omitempty"`

	// Origins is a collection of Origin structures, representing the sources or causes of the finding.
	// For example, this could be a specific vulnerability that led to the finding, or a process failure that resulted in the issue.
	Origins []*Origin `json:"origins,omitempty"`

	// Props are a collection of Property structures, representing additional properties or metadata about the finding.
	// For example, this could include a severity of the finding, its status, or other relevant details.
	Props []*Property `json:"props,omitempty"`

	// RelatedObservations is a collection of RelatedObservation structures, representing observations related to the finding.
	// For example, this could be observations that were made during the assessment that led to the finding.
	RelatedObservations []*RelatedObservation `json:"related-observations,omitempty"`

	// RelatedRisks is a collection of AssociatedRisk structures, representing risks related to the finding.
	// For example, this could be risks that were considered during the assessment and are relevant to the finding.
	RelatedRisks []*AssociatedRisk `json:"related-risks,omitempty"`

	// Remarks is a string that
	// can be used to provide additional comments or notes about the finding.
	Remarks string `json:"remarks,omitempty"`

	// Target represents the specific system, component, or process that the finding is about.
	// For example, this could be a specific server, a software application, or a business process that was assessed and where the issue was found.
	Target *Target `json:"target"`

	// Title is the title for this finding.
	// For example, "Weak Password Policy" or "Unpatched Software Vulnerability".
	Title string `json:"title"`

	// Uuid is a machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this finding in this or other OSCAL instances.
	// This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	// For example, "123e4567-e89b-12d3-a456-426614174000".
	Uuid string `json:"uuid"`
}

// IdentifiedRisk represents a specific risk that has been identified during an assessment in the context of the Open Security Controls Assessment Language (OSCAL) model.
// An IdentifiedRisk includes details like the risk's description, impact, and status, as well as references to related observations and remediations.
type IdentifiedRisk struct {
	// Characterizations is a collection of Characterization structures, representing different aspects or dimensions of the identified risk.
	// This could include factors like the risk's likelihood and impact.
	Characterizations []*Characterization `json:"characterizations,omitempty"`

	// Deadline is the date/time by which the risk must be resolved.
	// It should be in a format that can be parsed by Go's time package, e.g., "2006-01-02T15:04:05Z07:00".
	Deadline string `json:"deadline,omitempty"`

	// Description is a human-readable explanation of the identified risk, including a statement of how the risk impacts the system.
	Description string `json:"description"`

	// Links are a collection of Link structures, representing hyperlinks related to the risk.
	// For example, this could include links to resources providing more details about the risk.
	Links []*Link `json:"links,omitempty"`

	// MitigatingFactors is a collection of MitigatingFactor structures, representing factors that reduce the risk's impact or likelihood.
	// For example, this could include controls or safeguards that are in place.
	MitigatingFactors []*MitigatingFactor `json:"mitigating-factors,omitempty"`

	// Origins is a collection of Origin structures, representing the sources or causes of the risk.
	// For example, this could be a specific vulnerability or threat that led to the risk.
	Origins []*Origin `json:"origins,omitempty"`

	// Props are a collection of Property structures, representing additional properties or metadata about the risk.
	// For example, this could include a category of the risk, its priority, or other relevant details.
	Props []*Property `json:"props,omitempty"`

	// RelatedObservations is a collection of RelatedObservation structures, representing observations related to the risk.
	// For example, this could be observations that were made during the assessment that led to the identification of the risk.
	RelatedObservations []*RelatedObservation `json:"related-observations,omitempty"`

	// Remediations is a collection of CommonResponse structures, representing potential responses or remedies for the risk.
	// For example, this could include actions like implementing a new catalog, improving a process, or accepting the risk.
	Remediations []*CommonResponse `json:"remediations,omitempty"`

	// RiskLog represents a log of all risk-related tasks taken.
	// This could include actions taken to mitigate the risk, to monitor it, or to decide about it.
	RiskLog *RiskLog `json:"risk-log,omitempty"`

	// Statement is a summary of impact for how the risk affects the system.
	// For example, "The risk could lead to unauthorized access to sensitive data, resulting in potential data breaches and compliance violations."
	Statement string `json:"statement"`

	// Status represents the current status of the risk.
	// This could be a simple string like "Open", "Mitigated", or "Accepted", or a more complex structure with additional details.
	Status interface{} `json:"status"`

	// ThreatIds is a collection of CommonThreatId structures, representing the threats associated with the risk.
	// For example, this could include threats like "External attackers", "Insider threats", or "Software vulnerabilities".
	ThreatIds []*CommonThreatId `json:"threat-ids,omitempty"`

	// Title is the title
	// for this risk.
	// For example, "Risk of Data Breach due to Inadequate Access Controls" or "Risk of Non-Compliance with GDPR due to Lack of Data Encryption".
	Title string `json:"title"`

	// Uuid is a machine-oriented, globally unique identifier with cross-instance scope that can be used to reference this risk elsewhere in this or other OSCAL instances.
	// This UUID should be assigned per-subject, which means it should be consistently used to identify the same subject across revisions of the document.
	// For example, "123e4567-e89b-12d3-a456-426614174000".
	Uuid string `json:"uuid"`
}

// ImportAssessmentPlan is used by assessment-results to import information about the original plan for assessing the system in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes a reference to the assessment plan document and optional remarks.
type ImportAssessmentPlan struct {

	// Href is a resolvable URL reference to the assessment plan governing the assessment activities.
	// For example, "https://example.com/assessment-plan.json".
	Href string `json:"href"`

	// Remarks is a string that can be used to provide additional comments or notes about the imported assessment plan.
	Remarks string `json:"remarks,omitempty"`
}

// AssessmentResultLocalDefinitions is used to define data objects that are used in the assessment plan, that do not appear in the referenced System Security Plan (SSP) in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes definitions of activities and objectives/methods, and optional remarks.
type AssessmentResultLocalDefinitions struct {
	// Activities is a collection of CommonActivity structures, representing specific tasks or actions that were planned or carried out during the assessment.
	// For example, this could include activities like "Review system configuration" or "Interview system owner".
	Activities []*CommonActivity `json:"activities,omitempty"`

	// ObjectivesAndMethods is a collection of AssessmentSpecificControlObjective structures, representing specific objectives and methods used during the assessment.
	// For example, this could include objectives like "Verify that access controls are properly configured" and methods like "Review system configuration and interview system owner".
	ObjectivesAndMethods []*AssessmentSpecificControlObjective `json:"objectives-and-methods,omitempty"`

	// Remarks is a string that can be used to provide additional comments or notes about the local definitions.
	Remarks string `json:"remarks,omitempty"`
}

// Location represents a physical point of presence, which may be associated with people, organizations, or other concepts within the current or linked Open Security Controls Assessment Language (OSCAL) document.
// It includes details like the location's address, contact details, and optional remarks.
type Location struct {
	// Address represents the physical address of the location.
	// For example, this could be the address of a data center where a system is hosted.
	Address *Address `json:"address,omitempty"`

	// EmailAddresses is a list of email addresses associated with the location.
	// For example, these could be the email addresses of the location's manager or contact person.
	EmailAddresses []interface{} `json:"email-addresses,omitempty"`

	// Links are a collection of Link structures, representing hyperlinks related to the location.
	// For example, this could include links to resources providing more details about the location.
	Links []*Link `json:"links,omitempty"`

	// Props are a collection of Property structures, representing additional properties or metadata about the location.
	// For example, this could include a location code, a region, or other relevant details.
	Props []*Property `json:"props,omitempty"`

	// Remarks is a string that can be used to provide additional comments or notes about the location.
	Remarks string `json:"remarks,omitempty"`

	// TelephoneNumbers is a collection of TelephoneNumber structures, representing phone numbers associated with the location.
	// For example, this could be the phone number of the location's manager or help desk.
	TelephoneNumbers []*TelephoneNumber `json:"telephone-numbers,omitempty"`

	// Title is a name given to the location, which may be used by a tool for display and navigation.
	// For example, "Data Center A" or "Office B".
	Title string `json:"title,omitempty"`

	// Urls is a list of URLs associated with the location.
	// For example, this could be the website of the location or a link to a map showing the location.
	Urls []string `json:"urls,omitempty"`

	// Uuid is a machine-oriented, globally unique identifier that can be used to reference this location in this or other OSCAL instances.
	// For example, "123e4567-e89b-12d3-a456-426614174000".
	Uuid string `json:"uuid"`
}

// LoggedBy is used to indicate who created a log entry and in what role, in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes references to the party and their role.
type LoggedBy struct {

	// PartyUuid is a machine-oriented identifier reference to the party who is making the log entry.
	// This should match the UUID of a Party structure elsewhere in the OSCAL document.
	// For example, "123e4567-e89b-12d3-a456-426614174000".
	PartyUuid string `json:"party-uuid"`

	// RoleId is a reference to the role-id of the role in which the party is making the log entry.
	// This should match the id of a Role structure elsewhere in the OSCAL document.
	// For example, "assessor" or "system-owner".
	RoleId string `json:"role-id,omitempty"`
}

// MitigatingFactor describes an existing factor that reduces the severity or impact of a risk, potentially affecting the overall determination of the risk.
// It includes an optional link to an implementation statement in the System Security Plan (SSP) of the Open Security Controls Assessment Language (OSCAL) model.
type MitigatingFactor struct {

	// Description is a human-readable explanation of the mitigating factor.
	// This could detail how the factor reduces the severity or impact of the risk.
	// For example, "Firewalls are in place to protect against unauthorized access".
	Description string `json:"description"`

	// ImplementationUuid is a machine-oriented, globally unique identifier that can be used to reference the related implementation statement elsewhere in this or other OSCAL instances.
	// This UUID should be consistently used to identify the same subject across revisions of the document.
	// For example, "123e4567-e89b-12d3-a456-426614174000".
	ImplementationUuid string `json:"implementation-uuid,omitempty"`

	// Links are a collection of Link structures, representing hyperlinks related to the mitigating factor.
	// For example, this could include links to resources providing more details about the factor or its implementation.
	Links []*Link `json:"links,omitempty"`

	// Props are a collection of Property structures, representing additional properties or metadata about the mitigating factor.
	// For example, this could include a property indicating the effectiveness of the factor.
	Props []*Property `json:"props,omitempty"`

	// Subjects is a collection of IdentifiesTheSubject structures, representing the subjects (e.g., system components, individuals, or organizations) to which this mitigating factor applies.
	Subjects []*IdentifiesTheSubject `json:"subjects,omitempty"`

	// Uuid is a machine-oriented, globally unique identifier that can be used to reference this mitigating factor elsewhere in this or other OSCAL instances.
	// This UUID should be consistently used to identify the same subject across revisions of the document.
	// For example, "123e4567-e89b-12d3-a456-426614174000".
	Uuid string `json:"uuid"`
}

// ObjectiveStatus represents a determination of whether a particular objective is satisfied or not within a given system in the context of the Open Security Controls Assessment Language (OSCAL) model.
type ObjectiveStatus struct {

	// State represents the current status of the objective in the system.
	// The data type of State is interface{}, meaning it can hold values of any type.
	// The actual value could be a boolean, string, or custom type indicating whether the objective is satisfied.
	// For example, it could be a boolean value (true if the objective is satisfied, false otherwise),
	// or it could be a string value ("satisfied", "not satisfied", "pending", etc.).
	State interface{} `json:"state"`
}

// Target represents a specific objective within a system in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes details about the status of the objective and optional remarks.
type Target struct {

	// Type is an optional field that may be used to categorize or classify the objective.
	// For example, the type could be "security", "performance", "availability", etc.
	Type string `json:"type,omitempty"`

	// TargetId is an optional field that represents a unique identifier for the objective.
	// This could be a simple string or a more complex identifier, depending on your requirements.
	TargetId string `json:"target-id,omitempty"`

	// Status represents the current status of the objective within the system.
	// It is an instance of the ObjectiveStatus struct, which includes a State field that indicates whether the objective is satisfied or not.
	Status *ObjectiveStatus `json:"status,omitempty"`

	// Remarks is an optional field that can be used to provide additional comments or notes about the objective or its status.
	// For example, this could include explanations for why the objective is not satisfied, plans for satisfying it in the future, etc.
	Remarks string `json:"remarks,omitempty"`
}

// Origin identifies the source of a finding in the context of the Open Security Controls Assessment Language (OSCAL) model.
// The source could be a tool, interviewed person, or activity. It includes references to the actors involved and any related tasks.
type Origin struct {

	// Actors is a collection of OriginActor structures, representing the entities involved in the origin of the finding.
	// This could include individuals, teams, or software tools.
	// For example, an actor could be a security analyst who discovered a vulnerability, or a scanning tool that detected a security issue.
	Actors []*OriginActor `json:"actors"`

	// RelatedTasks is an optional collection of TaskReference structures, representing tasks related to the origin of the finding.
	// This could include tasks that led to the discovery of the finding, tasks that are affected by the finding, or tasks that need to be completed to address the finding.
	// For example, a related task could be a security audit that needs to be performed, or a patch that needs to be applied to fix a security issue.
	RelatedTasks []*TaskReference `json:"related-tasks,omitempty"`
}

// Result represents the outcome of an assessment or Plan of Actions and Milestones (POA&M) in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes details about the assessment observations, findings, risks, deviations, and disposition.
type Result struct {

	// AssessmentLog is an optional field that represents a log of all actions taken during the assessment.
	AssessmentLog *AssessmentLog `json:"assessment-log,omitempty"`

	// Attestations is an optional collection of AttestationStatements structures, representing confirmations or affirmations related to the assessment.
	Attestations []*AttestationStatements `json:"attestations,omitempty"`

	// Description is a human-readable explanation of the set of test results.
	// This could detail the context, methodology, or key findings of the assessment.
	Description string `json:"description"`

	// End is an optional field that represents the date/time when the evidence collection reflected in these results ended.
	// In a continuous monitoring scenario, this may contain the same value as Start.
	End string `json:"end,omitempty"`

	// Findings is an optional collection of Finding structures, representing specific discoveries or determinations made during the assessment.
	Findings []*Finding `json:"findings,omitempty"`

	// Links are a collection of Link structures, representing hyperlinks related to the result.
	Links []*Link `json:"links,omitempty"`

	// LocalDefinitions is an optional field that can be used to define data objects used in the assessment plan that do not appear in the referenced System Security Plan (SSP).
	LocalDefinitions *LocalDefinitions `json:"local-definitions,omitempty"`

	// Observations is an optional collection of Observation structures, representing specific observations made during the assessment.
	Observations []*Observation `json:"observations,omitempty"`

	// Props are a collection of Property structures, representing additional properties or metadata about the result.
	Props []*Property `json:"props,omitempty"`

	// Remarks is an optional field that can be used to provide additional comments or notes about the result.
	Remarks string `json:"remarks,omitempty"`

	// ReviewedControls is a reference to the controls and catalog objectives that were reviewed during the assessment.
	ReviewedControls *ReviewedControlsAndControlObjectives `json:"reviewed-controls"`

	// Risks is an optional collection of IdentifiedRisk structures, representing the risks identified during the assessment.
	Risks []*IdentifiedRisk `json:"risks,omitempty"`

	// Start is the date/time when the evidence collection reflected in these results started.
	Start string `json:"start"`

	// Title is the title for this set of results.
	// This could be a brief, descriptive name for the assessment or its key findings.
	Title string `json:"title"`

	// Uuid is a machine-oriented, globally unique identifier that can be used to reference this set of results in this or other OSCAL instances.
	// This UUID should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// Characterization represents a collection of descriptive data about a particular object in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes facets that describe the object, links to related information, and the origin of the characterization.
type Characterization struct {

	// Facets is a collection of Facet structures, representing specific aspects or dimensions that describe the object.
	// Each facet could detail a particular characteristic of the object.
	// For example, facets could include the object's type, size, color, function, etc.
	Facets []*Facet `json:"facets"`

	// Links is an optional collection of Link structures, representing hyperlinks related to the characterization.
	// For example, this could include links to resources providing more details about the object or its facets.
	Links []*Link `json:"links,omitempty"`

	// Origin represents the source of the characterization.
	// This could be a tool, person, or activity that provided the information used to describe the object.
	Origin *Origin `json:"origin"`

	// Props is an optional collection of Property structures, representing additional properties or metadata about the characterization.
	// For example, this could include a property indicating when the characterization was last updated.
	Props []*Property `json:"props,omitempty"`
}

// Observation describes an individual observation in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes details about when the observation was made, its description, links, methods, origins, properties, relevant evidence, remarks, subjects, types, and a unique identifier.
type Observation struct {

	// Collected is the date/time stamp identifying when the observation information was collected.
	Collected string `json:"collected"`

	// Description is a human-readable explanation of the observation.
	// This could detail the context, methodology, or key findings of the observation.
	Description string `json:"description"`

	// Expires is an optional field that represents the date/time when the observation information will be considered out-of-date and no longer valid.
	// This is typically used in continuous assessment scenarios.
	Expires string `json:"expires,omitempty"`

	// Links is an optional collection of Link structures, representing hyperlinks related to the observation.
	Links []*Link `json:"links,omitempty"`

	// Methods represents the techniques or procedures used to make the observation.
	// The data type of Methods is interface{}, meaning it can hold values of any type.
	Methods []interface{} `json:"methods"`

	// Origins is an optional collection of Origin structures, representing the sources of the observation.
	// This could include individuals, teams, or software tools that contributed to the observation.
	Origins []*Origin `json:"origins,omitempty"`

	// Props is an optional collection of Property structures, representing additional properties or metadata about the observation.
	Props []*Property `json:"props,omitempty"`

	// RelevantEvidence is an optional collection of RelevantEvidence structures, representing evidence that supports or relates to the observation.
	RelevantEvidence []*RelevantEvidence `json:"relevant-evidence,omitempty"`

	// Remarks is an optional field that can be used to provide additional comments or notes about the observation.
	Remarks string `json:"remarks,omitempty"`

	// Subjects is an optional collection of IdentifiesTheSubject structures, representing the subjects of the observation.
	// This could include the systems, components, or processes that the observation pertains to.
	Subjects []*IdentifiesTheSubject `json:"subjects,omitempty"`

	// Title is an optional field that represents the title for this observation.
	// This could be a brief, descriptive name for the observation or its key findings.
	Title string `json:"title,omitempty"`

	// Types represents the nature or category of the observation.
	// The data type of Types is interface{}, meaning it can hold values of any type.
	Types []interface{} `json:"types,omitempty"`

	// Uuid is a machine-oriented, globally unique identifier that can be used to reference this observation in this or other OSCAL instances.
	// This UUID should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// OriginActor represents the entity that produces an observation, finding, or risk in the context of the Open Security Controls Assessment Language (OSCAL) model.
// This could be a person, a software tool, or a team. One or more actor types can be used to specify a person that is using a tool.
type OriginActor struct {

	// ActorUuid is a machine-oriented identifier reference to the actor based on the associated type.
	// This could be a unique identifier for a person, tool, or team that is responsible for the observation, finding, or risk.
	ActorUuid string `json:"actor-uuid"`

	// Links is an optional collection of Link structures, representing hyperlinks related to the actor.
	// For example, this could include a link to a profile or website for the actor.
	Links []*Link `json:"links,omitempty"`

	// Props is an optional collection of Property structures, representing additional properties or metadata about the actor.
	// For example, this could include a property indicating when the actor was last active.
	Props []*Property `json:"props,omitempty"`

	// RoleId is an optional field that can be used to specify the role the actor was performing when they produced the observation, finding, or risk.
	// For a party, this could include roles such as "security analyst", "auditor", "tool", etc.
	RoleId string `json:"role-id,omitempty"`

	// Type represents the kind of actor.
	// The data type of Type is interface{}, meaning it can hold values of any type.
	// This could specify whether the actor is a person, tool, team, etc.
	Type interface{} `json:"type"`
}

// CommonRelatedTask represents an individual task that the containing object is a consequence of, in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes details about the subject identified by the task, links, properties, remarks, responsible parties, subjects, and a unique task identifier.
type CommonRelatedTask struct {

	// IdentifiedSubject is an optional field used to detail the assessment subject that was identified by this task.
	// This could be a system, component, or process that was assessed or affected by the task.
	IdentifiedSubject *IdentifiedSubject `json:"identified-subject,omitempty"`

	// Links is an optional collection of Link structures, representing hyperlinks related to the task.
	// For example, this could include a link to a task description or instructions.
	Links []*Link `json:"links,omitempty"`

	// Props is an optional collection of Property structures, representing additional properties or metadata about the task.
	// For example, this could include a property indicating the priority or status of the task.
	Props []*Property `json:"props,omitempty"`

	// Remarks is an optional field that can be used to provide additional comments or notes about the task.
	Remarks string `json:"remarks,omitempty"`

	// ResponsibleParties is an optional collection of ResponsibleParty structures, representing the entities responsible for the task.
	// This could include individuals, teams, or organizations that are tasked with performing or overseeing the task.
	ResponsibleParties []*ResponsibleParty `json:"responsible-parties,omitempty"`

	// Subjects is an optional collection of AssessmentSubject structures, representing the subjects of the task.
	// This could include the systems, components, or processes that the task pertains to.
	Subjects []*AssessmentSubject `json:"subjects,omitempty"`

	// TaskUuid is a machine-oriented identifier reference to a unique task.
	// This unique identifier can be used to reference this task in this or other OSCAL instances.
	TaskUuid string `json:"task-uuid"`
}

// CommonResponse describes either a recommended or an actual plan for addressing a risk in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes details about the description, lifecycle, links, origins, properties, remarks, required assets, tasks, title, and a unique identifier.
type CommonResponse struct {

	// Description is a human-readable explanation of this response plan.
	// This could detail the actions to be taken, resources required, and expected outcomes of the plan.
	Description string `json:"description"`

	// Lifecycle identifies whether this response plan is a recommendation, such as from an assessor or tool, or an actual plan accepted by the system owner.
	// The data type of Lifecycle is interface{}, meaning it can hold values of any type.
	Lifecycle interface{} `json:"lifecycle"`

	// Links is an optional collection of Link structures, representing hyperlinks related to the response plan.
	Links []*Link `json:"links,omitempty"`

	// Origins is an optional collection of Origin structures, representing the sources of the response plan.
	// This could include individuals, teams, or software tools that contributed to the plan.
	Origins []*Origin `json:"origins,omitempty"`

	// Props is an optional collection of Property structures, representing additional properties or metadata about the response plan.
	Props []*Property `json:"props,omitempty"`

	// Remarks is an optional field that can be used to provide additional comments or notes about the response plan.
	Remarks string `json:"remarks,omitempty"`

	// RequiredAssets is an optional collection of RequiredAsset structures, representing the assets required to implement the response plan.
	// This could include tools, systems, personnel, or other resources.
	RequiredAssets []*RequiredAsset `json:"required-assets,omitempty"`

	// Tasks is an optional collection of Task structures, representing the tasks to be performed as part of the response plan.
	Tasks []*Task `json:"tasks,omitempty"`

	// Title represents the title for this response activity.
	// This could be a brief, descriptive name for the plan or its key actions.
	Title string `json:"title"`

	// Uuid is a machine-oriented, globally unique identifier that can be used to reference this response plan in this or other OSCAL instances.
	// This UUID should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// CommonThreatId represents a pointer, by ID, to an externally-defined threat in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes details about the location of the threat data, the ID, and the source of the threat information.
type CommonThreatId struct {

	// Href is an optional field that provides a location for the threat data, from which this ID originates.
	// This could be a URL or URI where the threat information can be accessed.
	Href string `json:"href,omitempty"`

	// Id is the identifier of the threat. This is used to uniquely identify the threat in the context of the system.
	Id string `json:"id"`

	// System specifies the source of the threat information. This could be a database, a threat intelligence feed,
	// or any other system that provides information about threats.
	// The data type of System is interface{}, meaning it can hold values of any type.
	System interface{} `json:"system"`
}

// RelatedObservation Relates the finding to a set of referenced observations that were used to determine the finding.
type RelatedObservation struct {

	// A machine-oriented identifier reference to an observation defined in the list of observations.
	ObservationUuid string `json:"observation-uuid"`
}

// RelevantEvidence links an observation to relevant evidence in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes details about the description of the evidence, a resolvable URL reference to the evidence, links, properties, and remarks.
type RelevantEvidence struct {

	// Description provides a human-readable explanation of the evidence.
	// This could detail the nature of the evidence, how it was collected, and its relevance to the observation.
	Description string `json:"description"`

	// Href is an optional field that provides a resolvable URL reference to the relevant evidence.
	// This could be a URL where the evidence can be accessed or downloaded.
	Href string `json:"href,omitempty"`

	// Links is an optional collection of Link structures, representing hyperlinks related to the evidence.
	// This could include links to additional details, context, or analysis related to the evidence.
	Links []*Link `json:"links,omitempty"`

	// Props is an optional collection of Property structures, representing additional properties or metadata about the evidence.
	// This could include properties such as the date of collection, source, or integrity of the evidence.
	Props []*Property `json:"props,omitempty"`

	// Remarks is an optional field that can be used to provide additional comments or notes about the evidence.
	Remarks string `json:"remarks,omitempty"`
}

// RequiredAsset identifies an asset required to achieve remediation in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes details about the description, links, properties, remarks, subjects, title, and a unique identifier of the required asset.
type RequiredAsset struct {

	// Description provides a human-readable explanation of the required asset.
	// This could detail the nature of the asset, its use, and its importance for the remediation.
	Description string `json:"description"`

	// Links is an optional collection of Link structures, representing hyperlinks related to the required asset.
	// This could include links to additional details, context, or sources for the asset.
	Links []*Link `json:"links,omitempty"`

	// Props is an optional collection of Property structures, representing additional properties or metadata about the required asset.
	// This could include properties such as the type, location, or ownership of the asset.
	Props []*Property `json:"props,omitempty"`

	// Remarks is an optional field that can be used to provide additional comments or notes about the required asset.
	Remarks string `json:"remarks,omitempty"`

	// Subjects is an optional collection of IdentifiesTheSubject structures, representing the subjects related to the required asset.
	// This could include individuals, systems, or processes that are associated with the asset.
	Subjects []*IdentifiesTheSubject `json:"subjects,omitempty"`

	// Title represents the title for this required asset.
	// This could be a brief, descriptive name for the asset.
	Title string `json:"title,omitempty"`

	// Uuid is a machine-oriented, globally unique identifier that can be used to reference this required asset in this or other OSCAL instances.
	// This UUID should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// RevisionHistoryEntry represents an entry in a sequential list of revisions to the containing document, expected to be in reverse chronological order (i.e. latest first) in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes details about the last modification date, links, OSCAL version, properties, publication date, remarks, title, and version of the revision.
type RevisionHistoryEntry struct {

	// LastModified provides the date and time when the revision was last modified.
	LastModified string `json:"last-modified,omitempty"`

	// Links is an optional collection of Link structures, representing hyperlinks related to the revision.
	Links []*Link `json:"links,omitempty"`

	// OscalVersion provides the version of OSCAL used for the revision.
	OscalVersion string `json:"oscal-version,omitempty"`

	// Props is an optional collection of Property structures, representing additional properties or metadata about the revision.
	Props []*Property `json:"props,omitempty"`

	// Published provides the date and time when the revision was published.
	Published string `json:"published,omitempty"`

	// Remarks is an optional field that can be used to provide additional comments or notes about the revision.
	Remarks string `json:"remarks,omitempty"`

	// Title represents a name given to the document revision, which may be used by a tool for display and navigation.
	Title string `json:"title,omitempty"`

	// Version provides the version number of the revision.
	Version string `json:"version"`
}

// RiskLog represents a log of all risk-related tasks taken in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes a collection of RiskLogEntry structures that detail each entry in the risk log.
type RiskLog struct {

	// Entries is a collection of RiskLogEntry structures, each representing a single entry in the risk log.
	// Each entry includes details about the risk-related task undertaken.
	Entries []*RiskLogEntry `json:"entries"`
}

// RiskLogEntry identifies an individual risk response that occurred as part of managing an identified risk in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes details about the description, end date/time, links, logged by, properties, related responses, remarks, start date/time, status change, title, and a unique identifier of the risk log entry.
type RiskLogEntry struct {

	// Description provides a human-readable explanation of what was done regarding the risk.
	// This could detail the actions taken, the results, and the rationale for the response.
	Description string `json:"description,omitempty"`

	// End identifies the end date and time of the event.
	// If the event is a point in time, the start and end will be the same date and time.
	End string `json:"end,omitempty"`

	// Links is an optional collection of Link structures, representing hyperlinks related to the risk response.
	Links []*Link `json:"links,omitempty"`

	// LoggedBy is an optional collection of LoggedBy structures, representing the entities that logged the risk response.
	LoggedBy []*LoggedBy `json:"logged-by,omitempty"`

	// Props is an optional collection of Property structures, representing additional properties or metadata about the risk response.
	Props []*Property `json:"props,omitempty"`

	// RelatedResponses is an optional collection of RiskResponseReference structures, representing the related risk responses.
	RelatedResponses []*RiskResponseReference `json:"related-responses,omitempty"`

	// Remarks is an optional field that can be used to provide additional comments or notes about the risk response.
	Remarks string `json:"remarks,omitempty"`

	// Start identifies the start date and time of the event.
	Start string `json:"start"`

	// StatusChange represents any changes to the status of the risk that occurred as a result of the response.
	StatusChange interface{} `json:"status-change,omitempty"`

	// Title represents the title for this risk log entry.
	// This could be a brief, descriptive name for the risk response.
	Title string `json:"title,omitempty"`

	// Uuid is a machine-oriented, globally unique identifier that can be used to reference this risk log entry in this or other OSCAL instances.
	// This UUID should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// RiskResponseReference identifies an individual risk response that this log entry is for in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes details about the links, properties, related tasks, remarks, and a unique identifier of the risk response.
type RiskResponseReference struct {

	// Links is an optional collection of Link structures, representing hyperlinks related to the risk response.
	Links []*Link `json:"links,omitempty"`

	// Props is an optional collection of Property structures, representing additional properties or metadata about the risk response.
	Props []*Property `json:"props,omitempty"`

	// RelatedTasks is an optional collection of CommonRelatedTask structures, representing the tasks related to the risk response.
	RelatedTasks []*CommonRelatedTask `json:"related-tasks,omitempty"`

	// Remarks is an optional field that can be used to provide additional comments or notes about the risk response.
	Remarks string `json:"remarks,omitempty"`

	// ResponseUuid is a machine-oriented identifier that can be used to reference the unique risk response in this or other OSCAL instances.
	ResponseUuid string `json:"response-uuid"`
}

// TaskReference identifies an individual task for which the containing object is a consequence of in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes details about the identified subject, links, properties, remarks, responsible parties, subjects, and a unique identifier of the task.
type TaskReference struct {

	// IdentifiedSubject is an optional field that details the assessment subjects that were identified by this task.
	IdentifiedSubject *IdentifiedSubject `json:"identified-subject,omitempty"`

	// Links is an optional collection of Link structures, representing hyperlinks related to the task.
	Links []*Link `json:"links,omitempty"`

	// Props is an optional collection of Property structures, representing additional properties or metadata about the task.
	Props []*Property `json:"props,omitempty"`

	// Remarks is an optional field that can be used to provide additional comments or notes about the task.
	Remarks string `json:"remarks,omitempty"`

	// ResponsibleParties is an optional collection of ResponsibleParty structures, representing the parties responsible for the task.
	ResponsibleParties []*ResponsibleParty `json:"responsible-parties,omitempty"`

	// Subjects is an optional collection of AssessmentSubject structures, representing the subjects related to the task.
	Subjects []*AssessmentSubject `json:"subjects,omitempty"`

	// TaskUuid is a machine-oriented identifier that can be used to reference the unique task in this or other OSCAL instances.
	TaskUuid string `json:"task-uuid"`
}

// AssessmentResult represents security assessment results, such as those provided by a FedRAMP assessor in the FedRAMP Security Assessment Report in the context of the Open Security Controls Assessment Language (OSCAL) model.
// It includes details about the back matter, imported assessment plan, local definitions, metadata, results, and a unique identifier of the assessment result.
type AssessmentResult struct {

	// BackMatter is an optional field that contains references and other content included in the back matter section of the document.
	BackMatter *BackMatter `json:"back-matter,omitempty"`

	// ImportAp represents the imported assessment plan used for this assessment result.
	ImportAp *ImportAssessmentPlan `json:"import-ap"`

	// LocalDefinitions is an optional field used to define data objects that are used in the assessment plan, that do not appear in the referenced System Security Plan (SSP).
	LocalDefinitions *AssessmentResultLocalDefinitions `json:"local-definitions,omitempty"`

	// Metadata provides the metadata for the document. This includes details such as the title, published date, last modified date, version, OSCAL version, and revision history.
	Metadata *DocumentMetadata `json:"metadata"`

	// Results is a collection of Result structures, each representing an individual result from the assessment.
	Results []*Result `json:"results"`

	// Uuid is a machine-oriented, globally unique identifier that can be used to reference this assessment results instance in this or other OSCAL instances.
	// This UUID should be consistently used to identify the same subject across revisions of the document.
	Uuid string `json:"uuid"`
}

// FromJSON Automatic Register methods. add these for the schema to be fully CRUD-registered
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
