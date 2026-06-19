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
func (b *Builtin) Evaluate(_ context.Context, s Subject, _ string, r Resource, _ map[string]any) (Decision, error) {
	switch r.Type {
	case ResourceAdmin:
		return b.evaluateAdmin(s)
	default:
		// Phase 1: authenticated = allowed. The authn middleware already enforced
		// authentication (and any public-endpoint policy) before the PEP runs, so any
		// request that reaches a decision is permitted. Resource-attribute policies
		// (e.g. evidence labels/owner) arrive with the manifest attribute surface
		// (BCH-1319) and the later remote/cedar drivers.
		return Decision{Allow: true, Reason: "builtin: authenticated request allowed"}, nil
	}
}

// Evaluations implements PDP by evaluating each request independently, in order.
func (b *Builtin) Evaluations(ctx context.Context, reqs []EvalRequest) ([]Decision, error) {
	out := make([]Decision, len(reqs))
	for i, req := range reqs {
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
func (b *Builtin) evaluateAdmin(s Subject) (Decision, error) {
	if s.Type != "user" || s.ID == "" {
		return Decision{Allow: false, Reason: "missing authentication claims"}, nil
	}

	var user relational.User
	if err := b.db.Where("email = ?", s.ID).First(&user).Error; err != nil {
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
	if err := b.db.
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
		normalized := strings.TrimSpace(strings.ToLower(g))
		if normalized != "" {
			groupSet[normalized] = struct{}{}
		}
	}

	for _, required := range providerConfig.RequiredAdminGroups {
		normalized := strings.TrimSpace(strings.ToLower(required))
		if _, ok := groupSet[normalized]; !ok {
			b.logger.Warnw("User missing required admin group",
				"userID", user.ID.String(),
				"requiredGroup", required,
				"provider", link.Provider,
			)
			return Decision{Allow: false, Reason: "missing required admin groups"}, nil
		}
	}

	return Decision{Allow: true}, nil
}
