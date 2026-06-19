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

// DriverBuiltin is the name of the default, in-process driver.
const DriverBuiltin = "builtin"

func init() {
	Register(DriverBuiltin, newBuiltin)
}

// builtinPDP reproduces CCF's pre-authz access rules with zero behavior change:
//   - admin resources require the SSO admin groups previously enforced by
//     middleware.RequireAdminGroups;
//   - every other resource is allowed for any authenticated subject (and for
//     anonymous requests only where the route explicitly permits public access,
//     e.g. agent ingest with public endpoints enabled).
//
// As the in-process default it self-fetches the facts the admin check needs
// (user record, SSO link, provider config) via the DB and config it is built
// with. Exporting those facts into the evaluation tuple for remote drivers is a
// later-phase concern tracked under BCH-1319.
type builtinPDP struct {
	db     *gorm.DB
	cfg    *config.Config
	logger *zap.SugaredLogger
}

func newBuiltin(opts Options) (PDP, error) {
	if opts.DB == nil {
		return nil, errors.New("authz: builtin driver requires a database handle")
	}
	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &builtinPDP{db: opts.DB, cfg: opts.Config, logger: logger}, nil
}

// ResourceAdmin is the resource type whose actions require SSO admin groups.
const ResourceAdmin = "admin"

// ctxKeyAllowPublic, when set true in the request context, lets an anonymous
// subject through (mirroring routes that opt into public access).
const ctxKeyAllowPublic = "allow_public"

func (p *builtinPDP) Evaluate(ctx context.Context, s Subject, action string, r Resource, reqCtx map[string]any) (Decision, error) {
	if r.Type == ResourceAdmin {
		return p.evaluateAdmin(s)
	}

	// Default rule: authenticated subjects are allowed.
	if isAuthenticated(s) {
		return Decision{Allow: true, Reason: "authenticated subject"}, nil
	}
	// Anonymous requests are allowed only where the route opts into public
	// access (e.g. public agent ingest).
	if allowPublic, _ := reqCtx[ctxKeyAllowPublic].(bool); allowPublic {
		return Decision{Allow: true, Reason: "public access permitted for route"}, nil
	}
	return Decision{Allow: false, Reason: "subject is not authenticated"}, nil
}

func (p *builtinPDP) Evaluations(ctx context.Context, reqs []EvalRequest) ([]Decision, error) {
	decisions := make([]Decision, len(reqs))
	for i, req := range reqs {
		d, err := p.Evaluate(ctx, req.Subject, req.Action, req.Resource, req.Context)
		if err != nil {
			return nil, err
		}
		decisions[i] = d
	}
	return decisions, nil
}

// evaluateAdmin mirrors middleware.RequireAdminGroups exactly so admin routes
// keep their existing allow/deny outcomes. A returned error signals an internal
// failure (e.g. DB read error) which the PEP surfaces as 500 — matching the
// prior behavior where loading the user could fail with 500. Every explicit
// deny is returned as Decision{Allow:false} (mapped to 403 by the PEP).
func (p *builtinPDP) evaluateAdmin(s Subject) (Decision, error) {
	email := subjectEmail(s)
	if email == "" {
		// Unreachable in practice: admin routes run JWT authn first, which
		// rejects unauthenticated requests with 401 before the PEP is reached.
		return Decision{Allow: false, Reason: "missing authentication claims"}, nil
	}

	var user relational.User
	if err := p.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Decision{Allow: false, Reason: "user not found"}, nil
		}
		p.logger.Errorw("Failed to load user for admin enforcement", "email", email, "error", err)
		return Decision{}, fmt.Errorf("load user for admin enforcement: %w", err)
	}

	if strings.ToLower(user.AuthMethod) != "sso" {
		// Password (or other non-SSO) users bypass group enforcement.
		return Decision{Allow: true, Reason: "non-sso user bypasses admin groups"}, nil
	}
	if p.cfg == nil || p.cfg.SSO == nil || !p.cfg.SSO.Enabled {
		// Without SSO config we cannot enforce provider-based admin groups.
		return Decision{Allow: true, Reason: "sso disabled"}, nil
	}

	var link relational.SSOUserLink
	if err := p.db.
		Where("user_id = ? AND deleted_at IS NULL", user.ID.String()).
		Order("last_sync DESC").
		First(&link).Error; err != nil {
		p.logger.Warnw("Missing SSO link for admin enforcement", "userID", user.ID.String(), "error", err)
		return Decision{Allow: false, Reason: "missing SSO link for user"}, nil
	}

	providerConfig := p.cfg.SSO.GetProvider(link.Provider)
	if providerConfig == nil {
		p.logger.Warnw("Provider config not found for admin enforcement", "provider", link.Provider)
		return Decision{Allow: false, Reason: "provider configuration not found"}, nil
	}

	if len(providerConfig.RequiredAdminGroups) == 0 {
		return Decision{Allow: true, Reason: "provider requires no admin groups"}, nil
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
			p.logger.Warnw("User missing required admin group",
				"userID", user.ID.String(),
				"requiredGroup", required,
				"provider", link.Provider,
			)
			return Decision{Allow: false, Reason: "missing required admin groups"}, nil
		}
	}

	return Decision{Allow: true, Reason: "admin groups satisfied"}, nil
}

func isAuthenticated(s Subject) bool {
	return s.Type == SubjectUser || s.Type == SubjectAgent
}

// subjectEmail returns the user email for a user subject, preferring the
// explicit email prop and falling back to the subject ID.
func subjectEmail(s Subject) string {
	if s.Type != SubjectUser {
		return ""
	}
	if email, ok := s.Props["email"].(string); ok && email != "" {
		return email
	}
	return s.ID
}
