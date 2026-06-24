//go:build integration

package authz

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestDBGroupResolverNativeOnly proves subject.groups is derived purely from native CCF
// memberships (ccf_user_groups), sorted and case-insensitively de-duplicated. Raw IdP groups on
// the user's SSO link never reach authz on their own — only what login materialized as native
// memberships does (BCH-1331).
func TestDBGroupResolverNativeOnly(t *testing.T) {
	db := setupAuthzDB(t)
	user := createUser(t, db, "user@example.com", "sso")
	// The SSO link still carries raw IdP groups, but they are not an authz surface.
	createSSOLink(t, db, user, "test", []string{"Auditors", "raw-idp-group"})
	addNativeGroup(t, db, user, "engineers")
	addNativeGroup(t, db, user, "Shared")

	r := NewDBGroupResolver(db, zap.NewNop().Sugar())
	groups, err := r.ResolveGroups(context.Background(),
		Subject{Type: "user", ID: "user@example.com", Props: map[string]any{"user_uuid": user.ID.String()}})
	require.NoError(t, err)
	// Only the native memberships appear; the link's "Auditors"/"raw-idp-group" do not.
	require.Equal(t, []string{"Shared", "engineers"}, groups)
}

// TestDBGroupResolverIgnoresUnmappedIdPGroups proves that even when an SSO link carries IdP groups
// AND a matching mapping exists, none reach subject.groups unless materialized as native
// memberships — the resolver no longer reads the link or its mappings at decision time (BCH-1331).
// The user is given a native membership so the result is asserted to be *exactly* that group: the
// absence of the IdP-derived groups is then a meaningful negative, not a vacuously empty slice.
func TestDBGroupResolverIgnoresUnmappedIdPGroups(t *testing.T) {
	db := setupAuthzDB(t)
	user := createUser(t, db, "user@example.com", "sso")
	createSSOLink(t, db, user, "okta", []string{"okta-admins", "unmapped"})
	// A mapping exists in the table, but the resolver must not consult it — only memberships count.
	group := relational.UserGroup{Name: "ccf-admins"}
	require.NoError(t, db.Where("name = ?", "ccf-admins").FirstOrCreate(&group).Error)
	require.NoError(t, db.Create(&relational.SSOGroupMapping{
		Provider: "okta", ExternalGroup: "okta-admins", GroupID: group.ID.String(),
	}).Error)
	// A real native membership the resolver MUST return, proving resolution itself works.
	addNativeGroup(t, db, user, "engineers")

	r := NewDBGroupResolver(db, zap.NewNop().Sugar())
	groups, err := r.ResolveGroups(context.Background(),
		Subject{Type: "user", ID: "user@example.com", Props: map[string]any{"user_uuid": user.ID.String()}})
	require.NoError(t, err)
	// Exactly the native group — "okta-admins"/"ccf-admins"/"unmapped" are all absent.
	require.Equal(t, []string{"engineers"}, groups)
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
