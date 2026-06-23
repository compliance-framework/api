//go:build integration

package authz

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func addSSOMapping(t *testing.T, db *gorm.DB, provider, externalGroup, groupName string) {
	t.Helper()
	group := relational.UserGroup{Name: groupName}
	require.NoError(t, db.Where("name = ?", groupName).FirstOrCreate(&group).Error)
	require.NoError(t, db.Create(&relational.SSOGroupMapping{
		Provider:      provider,
		ExternalGroup: externalGroup,
		GroupID:       group.ID.String(),
	}).Error)
}

// TestDBGroupResolverUnionsNativeAndSSO proves subject.groups is the union of native CCF
// memberships and SSO IdP groups, de-duplicated case-insensitively and sorted.
func TestDBGroupResolverUnionsNativeAndSSO(t *testing.T) {
	db := setupAuthzDB(t)
	user := createUser(t, db, "user@example.com", "sso")
	createSSOLink(t, db, user, "test", []string{"Auditors", "shared"})
	addNativeGroup(t, db, user, "engineers")
	addNativeGroup(t, db, user, "Shared") // collides case-insensitively with the SSO "shared"

	r := NewDBGroupResolver(db, zap.NewNop().Sugar())
	groups, err := r.ResolveGroups(context.Background(),
		Subject{Type: "user", ID: "user@example.com", Props: map[string]any{"user_uuid": user.ID.String()}})
	require.NoError(t, err)
	// "Shared"/"shared" collapse to a single entry (the native spelling, resolved first,
	// wins); the result is sorted case-sensitively (ASCII: uppercase before lowercase).
	require.Equal(t, []string{"Auditors", "Shared", "engineers"}, groups)
}

// TestDBGroupResolverMapsSSOGroupToNativeName proves an SSO group is translated to the mapped
// native group name so a synced IdP group and a native group unify rather than collide.
func TestDBGroupResolverMapsSSOGroupToNativeName(t *testing.T) {
	db := setupAuthzDB(t)
	user := createUser(t, db, "user@example.com", "sso")
	createSSOLink(t, db, user, "okta", []string{"okta-admins", "unmapped"})
	addSSOMapping(t, db, "okta", "okta-admins", "ccf-admins")

	r := NewDBGroupResolver(db, zap.NewNop().Sugar())
	groups, err := r.ResolveGroups(context.Background(),
		Subject{Type: "user", ID: "user@example.com", Props: map[string]any{"user_uuid": user.ID.String()}})
	require.NoError(t, err)
	// okta-admins -> ccf-admins (mapped); unmapped passes through under its raw name.
	require.Equal(t, []string{"ccf-admins", "unmapped"}, groups)
}

// TestDBGroupResolverResolvesByEmailFallback proves a subject without the user_uuid claim
// (an older token) still resolves via email.
func TestDBGroupResolverResolvesByEmailFallback(t *testing.T) {
	db := setupAuthzDB(t)
	user := createUser(t, db, "user@example.com", "password")
	addNativeGroup(t, db, user, "engineers")

	r := NewDBGroupResolver(db, zap.NewNop().Sugar())
	groups, err := r.ResolveGroups(context.Background(), Subject{Type: "user", ID: "user@example.com"})
	require.NoError(t, err)
	require.Equal(t, []string{"engineers"}, groups)
}

// TestDBGroupResolverNonUserAndUnknown returns no groups for non-user subjects and unknown
// users rather than erroring.
func TestDBGroupResolverNonUserAndUnknown(t *testing.T) {
	db := setupAuthzDB(t)
	r := NewDBGroupResolver(db, zap.NewNop().Sugar())

	agentGroups, err := r.ResolveGroups(context.Background(), Subject{Type: "agent", ID: "client-1"})
	require.NoError(t, err)
	require.Empty(t, agentGroups)

	ghostGroups, err := r.ResolveGroups(context.Background(), Subject{Type: "user", ID: "ghost@example.com"})
	require.NoError(t, err)
	require.Empty(t, ghostGroups)
}

// TestResolvingPDPPopulatesSubjectGroups proves the decorator attaches resolved groups to
// the subject before the inner PDP sees it, and leaves a non-user subject untouched.
func TestResolvingPDPPopulatesSubjectGroups(t *testing.T) {
	db := setupAuthzDB(t)
	user := createUser(t, db, "user@example.com", "password")
	addNativeGroup(t, db, user, "engineers")

	var seen Subject
	spy := pdpFunc(func(_ context.Context, s Subject, _ string, _ Resource, _ map[string]any) (Decision, error) {
		seen = s
		return Decision{Allow: true}, nil
	})

	pdp := newResolvingPDP(spy, NewDBGroupResolver(db, zap.NewNop().Sugar()), zap.NewNop().Sugar())
	_, err := pdp.Evaluate(context.Background(),
		Subject{Type: "user", ID: "user@example.com", Props: map[string]any{"user_uuid": user.ID.String()}},
		ActionManage, Resource{Type: ResourceAdmin}, nil)
	require.NoError(t, err)

	groups, ok := seen.Props[SubjectGroupsAttr].([]string)
	require.True(t, ok, "inner PDP should see the groups attribute")
	require.Equal(t, []string{"engineers"}, groups)
}

// TestResolvingPDPDoesNotMutateCallerSubject proves the decorator copies Props instead of
// mutating the subject the caller passed in.
func TestResolvingPDPDoesNotMutateCallerSubject(t *testing.T) {
	db := setupAuthzDB(t)
	user := createUser(t, db, "user@example.com", "password")
	addNativeGroup(t, db, user, "engineers")

	spy := pdpFunc(func(context.Context, Subject, string, Resource, map[string]any) (Decision, error) {
		return Decision{Allow: true}, nil
	})
	pdp := newResolvingPDP(spy, NewDBGroupResolver(db, zap.NewNop().Sugar()), zap.NewNop().Sugar())

	caller := Subject{Type: "user", ID: "user@example.com", Props: map[string]any{"user_uuid": user.ID.String()}}
	_, err := pdp.Evaluate(context.Background(), caller, ActionManage, Resource{Type: ResourceAdmin}, nil)
	require.NoError(t, err)
	_, leaked := caller.Props[SubjectGroupsAttr]
	require.False(t, leaked, "resolver must not mutate the caller's Props map")
}

// pdpFunc adapts a function to the PDP interface for tests; Evaluations delegates to Evaluate.
type pdpFunc func(ctx context.Context, s Subject, action string, r Resource, reqCtx map[string]any) (Decision, error)

func (f pdpFunc) Evaluate(ctx context.Context, s Subject, action string, r Resource, reqCtx map[string]any) (Decision, error) {
	return f(ctx, s, action, r, reqCtx)
}

func (f pdpFunc) Evaluations(ctx context.Context, reqs []EvalRequest) ([]Decision, error) {
	out := make([]Decision, len(reqs))
	for i, req := range reqs {
		d, err := f(ctx, req.Subject, req.Action, req.Resource, req.Context)
		if err != nil {
			return nil, err
		}
		out[i] = d
	}
	return out, nil
}
