package suggestions

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

var defaultGeneralizableKeys = []string{"provider", "region", "account", "repository", "environment", "host"}

func TestDetectGeneralizationsDropsProviderForSharedControl(t *testing.T) {
	catalog := uuid.New().String()
	shared := ControlRef{CatalogID: catalog, ControlID: "AC-1"}
	github := FilterWithControls{
		ID:       uuid.New(),
		Name:     "GitHub repos",
		Labels:   map[string]string{"provider": "github", "type": "repository", "_policy": "scan"},
		Controls: []ControlRef{shared},
	}
	gitlab := FilterWithControls{
		ID:       uuid.New(),
		Name:     "GitLab repos",
		Labels:   map[string]string{"provider": "gitlab", "type": "repository", "_policy": "scan"},
		Controls: []ControlRef{shared},
	}

	candidates := DetectGeneralizations([]FilterWithControls{github, gitlab}, defaultGeneralizableKeys, 1)
	require.Len(t, candidates, 1)
	candidate := candidates[0]
	require.Equal(t, "provider", candidate.DroppedKey)
	require.Equal(t, map[string]string{"type": "repository", "_policy": "scan"}, candidate.GeneralizedLabels)
	require.ElementsMatch(t, []uuid.UUID{github.ID, gitlab.ID}, candidate.SourceFilterIDs)
	require.Len(t, candidate.Controls, 1)
}

func TestDetectGeneralizationsNeverDropsPolicyOrType(t *testing.T) {
	catalog := uuid.New().String()
	shared := ControlRef{CatalogID: catalog, ControlID: "AC-1"}
	// Two filters differing only by _policy must never generalize.
	a := FilterWithControls{ID: uuid.New(), Labels: map[string]string{"provider": "github", "_policy": "x"}, Controls: []ControlRef{shared}}
	b := FilterWithControls{ID: uuid.New(), Labels: map[string]string{"provider": "github", "_policy": "y"}, Controls: []ControlRef{shared}}
	// type is also meaning-bearing.
	c := FilterWithControls{ID: uuid.New(), Labels: map[string]string{"provider": "github", "type": "repository"}, Controls: []ControlRef{shared}}
	d := FilterWithControls{ID: uuid.New(), Labels: map[string]string{"provider": "github", "type": "branch"}, Controls: []ControlRef{shared}}

	candidates := DetectGeneralizations([]FilterWithControls{a, b, c, d}, defaultGeneralizableKeys, 1)
	require.Empty(t, candidates)
}

func TestDetectGeneralizationsRequiresSharedControl(t *testing.T) {
	catalog := uuid.New().String()
	github := FilterWithControls{
		ID:       uuid.New(),
		Labels:   map[string]string{"provider": "github", "type": "repository"},
		Controls: []ControlRef{{CatalogID: catalog, ControlID: "AC-1"}},
	}
	gitlab := FilterWithControls{
		ID:       uuid.New(),
		Labels:   map[string]string{"provider": "gitlab", "type": "repository"},
		Controls: []ControlRef{{CatalogID: catalog, ControlID: "AC-2"}},
	}

	// No shared control → no candidate at the default threshold of 1.
	require.Empty(t, DetectGeneralizations([]FilterWithControls{github, gitlab}, defaultGeneralizableKeys, 1))
}

func TestDetectGeneralizationsUnionOfControls(t *testing.T) {
	catalog := uuid.New().String()
	shared := ControlRef{CatalogID: catalog, ControlID: "AC-1"}
	onlyGithub := ControlRef{CatalogID: catalog, ControlID: "AC-2"}
	onlyGitlab := ControlRef{CatalogID: catalog, ControlID: "AC-3"}
	github := FilterWithControls{ID: uuid.New(), Labels: map[string]string{"provider": "github", "type": "repository"}, Controls: []ControlRef{shared, onlyGithub}}
	gitlab := FilterWithControls{ID: uuid.New(), Labels: map[string]string{"provider": "gitlab", "type": "repository"}, Controls: []ControlRef{shared, onlyGitlab}}

	candidates := DetectGeneralizations([]FilterWithControls{github, gitlab}, defaultGeneralizableKeys, 1)
	require.Len(t, candidates, 1)
	require.Len(t, candidates[0].Controls, 3)
}

func TestDetectGeneralizationsNeverEmptyGeneralizedLabels(t *testing.T) {
	catalog := uuid.New().String()
	shared := ControlRef{CatalogID: catalog, ControlID: "AC-1"}
	// Dropping provider would leave an empty label set → never merge into match-all.
	a := FilterWithControls{ID: uuid.New(), Labels: map[string]string{"provider": "github"}, Controls: []ControlRef{shared}}
	b := FilterWithControls{ID: uuid.New(), Labels: map[string]string{"provider": "gitlab"}, Controls: []ControlRef{shared}}
	require.Empty(t, DetectGeneralizations([]FilterWithControls{a, b}, defaultGeneralizableKeys, 1))
}

func TestDetectGeneralizationsOmittedKeyJoinsGroup(t *testing.T) {
	catalog := uuid.New().String()
	shared := ControlRef{CatalogID: catalog, ControlID: "AC-1"}
	// One filter already equals the generalized form (omits provider).
	general := FilterWithControls{ID: uuid.New(), Labels: map[string]string{"type": "repository", "_policy": "scan"}, Controls: []ControlRef{shared}}
	github := FilterWithControls{ID: uuid.New(), Labels: map[string]string{"provider": "github", "type": "repository", "_policy": "scan"}, Controls: []ControlRef{shared}}

	candidates := DetectGeneralizations([]FilterWithControls{general, github}, defaultGeneralizableKeys, 1)
	require.Len(t, candidates, 1)
	require.Equal(t, "provider", candidates[0].DroppedKey)
	require.ElementsMatch(t, []uuid.UUID{general.ID, github.ID}, candidates[0].SourceFilterIDs)
}
