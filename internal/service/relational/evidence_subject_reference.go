package relational

import (
	"sort"

	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// Where an evidence subject came from (ccf:subject-source).
const (
	// EvidenceSubjectSourceTemplate is a subject derived from a plugin's component subject
	// template matching the evidence labels.
	EvidenceSubjectSourceTemplate = "template"
	// EvidenceSubjectSourceDeclared is a subject named explicitly by manual or workflow evidence.
	EvidenceSubjectSourceDeclared = "declared"
	// EvidenceSubjectSourceLegacy is an identifier subject sent by a plugin. It doesn't count
	// towards the evidence being attributed.
	EvidenceSubjectSourceLegacy = "legacy"
)

// Prop names (in CCFOSCALNamespace) on an evidence subject reference.
const (
	EvidenceSubjectPropSource          = "subject-source"
	EvidenceSubjectPropTemplate        = "subject-template"
	EvidenceSubjectPropDisplayPriority = "display-priority"
)

// EvidenceSubjectReference is one subject of a piece of evidence: the resource the evidence
// is about. Each row maps 1:1 to an OSCAL observation subject-reference.
type EvidenceSubjectReference struct {
	UUIDModel
	// EvidenceID is indexed on its own so an evidence's subjects load without the
	// (subject_uuid, evidence_id) index, which serves lookups by subject.
	EvidenceID  uuid.UUID `json:"evidenceId" gorm:"type:uuid;not null;index;index:idx_evidence_subject_references_subject,priority:2"`
	SubjectUUID uuid.UUID `json:"subjectUuid" gorm:"type:uuid;not null;index:idx_evidence_subject_references_subject,priority:1"`
	// Type is the OSCAL subject type, e.g. component.
	Type  string `json:"type" gorm:"type:text;not null"`
	Title string `json:"title" gorm:"type:text"`
	// Source is one of the EvidenceSubjectSource* values.
	Source string `json:"source" gorm:"type:text;not null"`
	// TemplateID is the subject template a template-derived subject came from.
	TemplateID *uuid.UUID `json:"templateId,omitempty" gorm:"type:uuid"`
	// Priority is the template's display priority: higher subjects are shown first.
	Priority int     `json:"priority" gorm:"not null;default:0"`
	Group    *string `json:"group,omitempty" gorm:"column:group;type:text"`

	Props   datatypes.JSONSlice[Prop] `json:"props"`
	Links   datatypes.JSONSlice[Link] `json:"links"`
	Remarks *string                   `json:"remarks,omitempty"`
}

func (r EvidenceSubjectReference) MarshalOscal() oscalTypes_1_1_3.SubjectReference {
	ref := oscalTypes_1_1_3.SubjectReference{
		SubjectUuid: r.SubjectUUID.String(),
		Type:        r.Type,
		Title:       r.Title,
	}
	if len(r.Props) > 0 {
		ref.Props = ConvertPropsToOscal(r.Props)
	}
	if len(r.Links) > 0 {
		ref.Links = ConvertLinksToOscal(r.Links)
	}
	if r.Remarks != nil {
		ref.Remarks = *r.Remarks
	}
	return ref
}

// templateName is the name of the subject template a template-derived subject came from, as
// recorded on it (ccf:subject-template), or "" for other subjects.
func (r EvidenceSubjectReference) templateName() string {
	for _, prop := range r.Props {
		if prop.Ns == CCFOSCALNamespace && prop.Name == EvidenceSubjectPropTemplate {
			return prop.Value
		}
	}
	return ""
}

// SortEvidenceSubjectReferencesForDisplay returns the subjects in display order: higher
// display priority first, then alphabetically by template name. Subjects without a template
// follow, and title then UUID break any remaining ties so the order is stable. The order is
// only for rendering; it never changes which subjects are attached.
func SortEvidenceSubjectReferencesForDisplay(refs []EvidenceSubjectReference) []EvidenceSubjectReference {
	sorted := append([]EvidenceSubjectReference(nil), refs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		aName, bName := a.templateName(), b.templateName()
		if aName != bName {
			if aName == "" || bName == "" {
				return bName == ""
			}
			return aName < bName
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		return a.SubjectUUID.String() < b.SubjectUUID.String()
	})
	return sorted
}
