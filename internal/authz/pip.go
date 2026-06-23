package authz

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/sso"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// SubjectGroupsAttr is the subject-attribute key under which resolved group memberships are
// exported into the evaluation tuple (Subject.Props). The value is source-agnostic: native
// CCF groups unioned with the IdP groups synced via SSO (BCH-1319 §7, BCH-1328).
const SubjectGroupsAttr = "groups"

// GroupResolver is the in-process Policy Information Point (PIP) for the subject.groups
// attribute. It is OSS and reads CCF's database directly — an external PDP cannot, so it only
// ever receives already-resolved values (BCH-1319 §8, §11.5). Implementations must be safe
// for concurrent use.
type GroupResolver interface {
	// ResolveGroups returns the group names the subject belongs to: native CCF group
	// memberships unioned with the subject's SSO IdP groups (translated to native group names
	// where an SSOGroupMapping exists). Non-user subjects resolve to no groups.
	ResolveGroups(ctx context.Context, s Subject) ([]string, error)
}

// dbGroupResolver resolves subject.groups from CCF's database: native memberships
// (ccf_user_groups) unioned with the user's latest SSO link groups, the latter translated
// through ccf_sso_group_mappings so a synced IdP group and a native group unify rather than
// collide. It is the single resolver the design mandates (BCH-1319 §8).
type dbGroupResolver struct {
	db     *gorm.DB
	logger *zap.SugaredLogger
}

// NewDBGroupResolver constructs the DB-backed group PIP. A nil db disables resolution
// (ResolveGroups returns no groups); a nil logger becomes a no-op.
func NewDBGroupResolver(db *gorm.DB, logger *zap.SugaredLogger) GroupResolver {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &dbGroupResolver{db: db, logger: logger}
}

// ResolveGroups implements GroupResolver.
func (r *dbGroupResolver) ResolveGroups(ctx context.Context, s Subject) ([]string, error) {
	if r.db == nil || s.Type != "user" || s.ID == "" {
		return nil, nil
	}

	// Resolve the user row by uuid (the C0 claim) when present, else by email. The uuid keys
	// both native memberships and the SSO link; email is the fallback for tokens issued
	// before the user_uuid claim landed.
	var user relational.User
	q := r.db.WithContext(ctx)
	if uuidVal, _ := s.Props["user_uuid"].(string); strings.TrimSpace(uuidVal) != "" {
		q = q.Where("id = ?", strings.TrimSpace(uuidVal))
	} else {
		q = q.Where("email = ?", s.ID)
	}
	if err := q.First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if user.ID == nil {
		return nil, nil
	}
	userID := user.ID.String()

	// case-insensitive dedup: lower(name) -> first canonical spelling seen.
	set := map[string]string{}

	native, err := relational.GroupNamesForUser(r.db.WithContext(ctx), userID)
	if err != nil {
		return nil, err
	}
	for _, g := range native {
		addGroup(set, g)
	}

	ssoGroups, err := r.ssoGroupNames(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, g := range ssoGroups {
		addGroup(set, g)
	}

	out := make([]string, 0, len(set))
	for _, canonical := range set {
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out, nil
}

// ssoGroupNames loads the user's most recent SSO link and returns its groups, translating
// each through the provider's ccf_sso_group_mappings to the mapped native group name where
// one exists; unmapped groups pass through under their raw name. A user with no SSO link
// resolves to no SSO groups.
func (r *dbGroupResolver) ssoGroupNames(ctx context.Context, userID string) ([]string, error) {
	var link relational.SSOUserLink
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND deleted_at IS NULL", userID).
		Order("last_sync DESC").
		First(&link).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}

	raw := sso.DeserializeStringArray(link.Groups)
	if len(raw) == 0 {
		return nil, nil
	}

	var mappings []relational.SSOGroupMapping
	if err := r.db.WithContext(ctx).
		Where("provider = ?", link.Provider).
		Preload("Group").
		Find(&mappings).Error; err != nil {
		return nil, err
	}
	mapByExternal := make(map[string]string, len(mappings)) // lower(externalGroup) -> native name
	for _, m := range mappings {
		if name := strings.TrimSpace(m.Group.Name); name != "" {
			mapByExternal[strings.ToLower(strings.TrimSpace(m.ExternalGroup))] = name
		}
	}

	out := make([]string, 0, len(raw))
	for _, g := range raw {
		key := strings.ToLower(strings.TrimSpace(g))
		if key == "" {
			continue
		}
		if native, ok := mapByExternal[key]; ok {
			out = append(out, native)
		} else {
			out = append(out, strings.TrimSpace(g))
		}
	}
	return out, nil
}

// addGroup inserts a trimmed group name into the case-insensitive set, keeping the first
// spelling seen for a given lowercase key.
func addGroup(set map[string]string, name string) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return
	}
	key := strings.ToLower(trimmed)
	if _, exists := set[key]; !exists {
		set[key] = trimmed
	}
}

// resolvingPDP populates the subject.groups attribute (via the GroupResolver) before
// delegating to the inner PDP, so every engine sees a consistent, source-agnostic group set
// without each call site resolving it. It runs per request — groups are not baked into the
// ~24h JWT, keeping revocation timely — and sits OUTSIDE the decision cache, so a membership
// change yields a different subject, hence a different cache key, hence a fresh decision
// (BCH-1319 §7, BCH-1328). A resolver error is logged and the request proceeds with no
// groups attribute: the PEP supplies facts only, and a deny-by-default policy fails safe.
type resolvingPDP struct {
	inner    PDP
	resolver GroupResolver
	logger   *zap.SugaredLogger
}

// newResolvingPDP wraps inner so user subjects are decorated with their resolved groups.
func newResolvingPDP(inner PDP, resolver GroupResolver, logger *zap.SugaredLogger) PDP {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &resolvingPDP{inner: inner, resolver: resolver, logger: logger}
}

// withGroups returns s with subject.groups populated. It leaves a subject untouched when it
// is not a user, when groups were already attached upstream, or when resolution yields none.
func (p *resolvingPDP) withGroups(ctx context.Context, s Subject) Subject {
	if s.Type != "user" {
		return s
	}
	if _, already := s.Props[SubjectGroupsAttr]; already {
		return s
	}
	groups, err := p.resolver.ResolveGroups(ctx, s)
	if err != nil {
		p.logger.Warnw("authz group resolution failed; proceeding without groups",
			"subjectID", s.ID, "error", err)
		return s
	}
	if len(groups) == 0 {
		return s
	}
	// Copy Props so the caller's map is never mutated.
	props := make(map[string]any, len(s.Props)+1)
	for k, v := range s.Props {
		props[k] = v
	}
	props[SubjectGroupsAttr] = groups
	s.Props = props
	return s
}

// Evaluate implements PDP.
func (p *resolvingPDP) Evaluate(ctx context.Context, s Subject, action string, r Resource, reqCtx map[string]any) (Decision, error) {
	return p.inner.Evaluate(ctx, p.withGroups(ctx, s), action, r, reqCtx)
}

// Evaluations implements PDP. Each distinct subject is resolved once for the batch (the same
// subject recurs across the resource×action matrix that /me/permissions enumerates).
func (p *resolvingPDP) Evaluations(ctx context.Context, reqs []EvalRequest) ([]Decision, error) {
	if len(reqs) == 0 {
		return p.inner.Evaluations(ctx, reqs)
	}
	resolved := make(map[string]Subject, len(reqs))
	out := make([]EvalRequest, len(reqs))
	for i, req := range reqs {
		key := req.Subject.Type + "\x00" + req.Subject.ID
		s, ok := resolved[key]
		if !ok {
			s = p.withGroups(ctx, req.Subject)
			resolved[key] = s
		}
		req.Subject = s
		out[i] = req
	}
	return p.inner.Evaluations(ctx, out)
}

// Health forwards to the inner PDP when it supports it, so wrapping doesn't hide a remote
// PDP's health from the readiness check.
func (p *resolvingPDP) Health(ctx context.Context) error {
	if h, ok := p.inner.(Healther); ok {
		return h.Health(ctx)
	}
	return nil
}
