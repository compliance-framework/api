package relational

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func templateRef(title, template string, priority int) EvidenceSubjectReference {
	return EvidenceSubjectReference{
		SubjectUUID: uuid.New(),
		Title:       title,
		Source:      EvidenceSubjectSourceTemplate,
		Priority:    priority,
		Props:       []Prop{{Ns: CCFOSCALNamespace, Name: EvidenceSubjectPropTemplate, Value: template}},
	}
}

func TestSortEvidenceSubjectReferencesForDisplay(t *testing.T) {
	legacy := EvidenceSubjectReference{SubjectUUID: uuid.New(), Source: EvidenceSubjectSourceLegacy}
	refs := []EvidenceSubjectReference{
		legacy,
		templateRef("Org acme", "organization", 0),
		templateRef("Branch main", "branch", 0),
		templateRef("Repo api", "repository", 10),
	}

	sorted := SortEvidenceSubjectReferencesForDisplay(refs)

	titles := make([]string, 0, len(sorted))
	for _, ref := range sorted {
		titles = append(titles, ref.Title)
	}
	require.Equal(t, []string{"Repo api", "Branch main", "Org acme", ""}, titles,
		"higher priority first, then template name, then subjects without a template")
	require.Equal(t, legacy.SubjectUUID, refs[0].SubjectUUID, "the input is not reordered")
}
