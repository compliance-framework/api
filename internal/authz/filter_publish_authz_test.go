package authz

import (
	"slices"
	"testing"
)

func TestManifestDeclaresFilterPublish(t *testing.T) {
	m, err := DefaultManifest()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(m.Resources[ResourceFilter].Actions, ActionPublish) {
		t.Fatalf("filter resource missing %q (have %v)", ActionPublish, m.Resources[ResourceFilter].Actions)
	}
}

// Under Cedar only admin ("*": ["*"]) holds filter:publish; contributors, who may update
// filters, may not publish them, and neither may agents or anonymous callers.
func TestCedarFilterPublishMatrix(t *testing.T) {
	c := mustCedar(t, &RoleAssignments{
		Users: map[string]string{
			"admin@x":       "admin",
			"viewer@x":      "viewer",
			"auditor@x":     "auditor",
			"contributor@x": "contributor",
		},
	})
	user := func(id string) Subject { return Subject{Type: "user", ID: id} }
	cases := []struct {
		subj Subject
		want bool
	}{
		{user("admin@x"), true},
		{user("viewer@x"), false},
		{user("auditor@x"), false},
		{user("contributor@x"), false},
		{Subject{Type: "agent", ID: "agent-1"}, false},
		{Subject{Type: "anonymous"}, false},
	}
	for _, tc := range cases {
		if got := allows(t, c, tc.subj, ActionPublish, ResourceFilter); got != tc.want {
			t.Errorf("%s %s: filter:publish allow = %v, want %v", tc.subj.Type, tc.subj.ID, got, tc.want)
		}
	}
	if !allows(t, c, user("contributor@x"), ActionUpdate, ResourceFilter) {
		t.Error("contributor: filter:update should stay allowed")
	}
}
