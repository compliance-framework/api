package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/sso"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func init() {
	Register(DriverBuiltin, func(_ Options, deps Deps) (PDP, error) {
		return NewBuiltin(deps.DB, deps.Config, deps.Logger), nil
	})
}

// Builtin is the default, in-process PDP. It reproduces CCF's pre-authz access rules with
// zero behavior change: admin resources require SSO admin-group membership (password
// users are treated as super admins), and every other resource is allowed once the
// request is authenticated — the authn middleware having already enforced authentication
// and any public-endpoint policy before the PEP runs.
//
// In Phase 1 the builtin driver resolves SSO facts itself (it holds db + config), acting
// as its own PIP, so behavior matches the previous RequireAdminGroups middleware exactly.
// The "PEP supplies all facts" model the design describes is for the remote drivers and
// the manifest attribute surface designed in BCH-1319. Because it runs in-process it
// never returns ErrUnavailable, so the configured fail mode never changes its behavior.
type Builtin struct {
	db     *gorm.DB
	cfg    *config.Config
	logger *zap.SugaredLogger
}

// NewBuiltin constructs the builtin PDP. A nil logger is replaced with a no-op logger.
func NewBuiltin(db *gorm.DB, cfg *config.Config, logger *zap.SugaredLogger) *Builtin {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &Builtin{db: db, cfg: cfg, logger: logger}
}

// Evaluate implements PDP.
func (b *Builtin) Evaluate(ctx context.Context, s Subject, _ string, r Resource, _ map[string]any) (Decision, error) {
	switch r.Type {
	case ResourceAdmin:
		return b.evaluateAdmin(ctx, s)
	default:
		// Phase 1: authenticated = allowed. The authn middleware already enforced
		// authentication (and any public-endpoint policy) before the PEP runs, so any
		// request that reaches a decision is permitted. Resource-attribute policies
		// (e.g. evidence labels/owner) arrive with the manifest attribute surface
		// (BCH-1319) and the later remote/cedar drivers.
		return Decision{Allow: true, Reason: "builtin: authenticated request allowed"}, nil
	}
}

// Evaluations implements PDP by evaluating each request independently, in order. Admin
// decisions are memoized per subject for the batch: evaluateAdmin ignores the action and
// keys only on the subject, so a batch enumerating several admin.* actions (e.g.
// /me/permissions) would otherwise repeat the same user + SSO-link DB lookups once per
// action. The memo keeps the facts inside the builtin driver and preserves both ordering
// and the error path.
func (b *Builtin) Evaluations(ctx context.Context, reqs []EvalRequest) ([]Decision, error) {
	type adminKey struct{ subjectType, subjectID string }
	adminMemo := map[adminKey]Decision{}

	out := make([]Decision, len(reqs))
	for i, req := range reqs {
		if req.Resource.Type == ResourceAdmin {
			key := adminKey{req.Subject.Type, req.Subject.ID}
			if d, ok := adminMemo[key]; ok {
				out[i] = d
				continue
			}
			d, err := b.Evaluate(ctx, req.Subject, req.Action, req.Resource, req.Context)
			if err != nil {
				return nil, err
			}
			adminMemo[key] = d
			out[i] = d
			continue
		}
		d, err := b.Evaluate(ctx, req.Subject, req.Action, req.Resource, req.Context)
		if err != nil {
			return nil, err
		}
		out[i] = d
	}
	return out, nil
}

// evaluateAdmin reproduces the previous RequireAdminGroups logic. SSO users must belong
// to the provider's configured admin groups; password (non-SSO) users are super admins;
// and when SSO is disabled or no admin groups are configured, access is allowed. A
// genuine DB failure loading the user is returned as an error (the PEP maps it to 500,
// preserving the prior behavior); every other denial is a clean deny (mapped to 403).
func (b *Builtin) evaluateAdmin(ctx context.Context, s Subject) (Decision, error) {
	if s.Type != "user" || s.ID == "" {
		return Decision{Allow: false, Reason: "missing authentication claims"}, nil
	}

	var user relational.User
	if err := b.db.WithContext(ctx).Where("email = ?", s.ID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Decision{Allow: false, Reason: "user not found"}, nil
		}
		b.logger.Errorw("Failed to load user for admin enforcement", "email", s.ID, "error", err)
		return Decision{}, fmt.Errorf("failed to load user: %w", err)
	}

	if strings.ToLower(user.AuthMethod) != "sso" {
		// Password (or other non-SSO) users bypass group enforcement.
		return Decision{Allow: true, Reason: "non-sso super admin"}, nil
	}
	if b.cfg == nil || b.cfg.SSO == nil || !b.cfg.SSO.Enabled {
		// Without SSO config we cannot enforce provider-based admin groups; allow request.
		return Decision{Allow: true, Reason: "sso enforcement disabled"}, nil
	}

	var link relational.SSOUserLink
	if err := b.db.WithContext(ctx).
		Where("user_id = ? AND deleted_at IS NULL", user.ID.String()).
		Order("last_sync DESC").
		First(&link).Error; err != nil {
		b.logger.Warnw("Missing SSO link for admin enforcement", "userID", user.ID.String(), "error", err)
		return Decision{Allow: false, Reason: "missing SSO link for user"}, nil
	}

	providerConfig := b.cfg.SSO.GetProvider(link.Provider)
	if providerConfig == nil {
		b.logger.Warnw("Provider config not found for admin enforcement", "provider", link.Provider)
		// SSO IS enabled and this provider is unknown - we should fail.
		return Decision{Allow: false, Reason: "provider configuration not found"}, nil
	}

	if len(providerConfig.RequiredAdminGroups) == 0 {
		return Decision{Allow: true, Reason: "no required admin groups configured"}, nil
	}

	groupSet := make(map[string]struct{})
	for _, g := range sso.DeserializeStringArray(link.Groups) {
		if normalized := normalizeGroup(g); normalized != "" {
			groupSet[normalized] = struct{}{}
		}
	}

	// Happy path: the SSO link groups alone satisfy the requirement. Resolved without the
	// native-group query so the common admin allow keeps its prior two-query cost.
	if missingRequiredGroup(providerConfig.RequiredAdminGroups, groupSet) == "" {
		return Decision{Allow: true}, nil
	}

	// Fallback: a native CCF group can also satisfy an admin requirement, so group-based
	// admin works for users whose IdP groups don't include it (BCH-1328). Queried only when
	// the SSO groups are insufficient; a failure degrades to "no native groups" (a clean
	// deny) rather than a 500, since the supplementary lookup must not break the admin check.
	native, err := relational.GroupNamesForUser(b.db.WithContext(ctx), user.ID.String())
	if err != nil {
		b.logger.Warnw("Failed to load native groups for admin enforcement",
			"userID", user.ID.String(), "error", err)
	}
	for _, g := range native {
		if normalized := normalizeGroup(g); normalized != "" {
			groupSet[normalized] = struct{}{}
		}
	}

	if missing := missingRequiredGroup(providerConfig.RequiredAdminGroups, groupSet); missing != "" {
		b.logger.Warnw("User missing required admin group",
			"userID", user.ID.String(),
			"requiredGroup", missing,
			"provider", link.Provider,
		)
		return Decision{Allow: false, Reason: "missing required admin groups"}, nil
	}

	return Decision{Allow: true}, nil
}

// normalizeGroup folds a group name to the trimmed, lower-cased form used for membership
// comparison, so IdP, native and required-group spellings match case-insensitively.
func normalizeGroup(g string) string {
	return strings.TrimSpace(strings.ToLower(g))
}

// missingRequiredGroup returns the first required group (original spelling) absent from have,
// or "" when every required group is present.
func missingRequiredGroup(required []string, have map[string]struct{}) string {
	for _, r := range required {
		if _, ok := have[normalizeGroup(r)]; !ok {
			return r
		}
	}
	return ""
}
