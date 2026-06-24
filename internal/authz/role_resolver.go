package authz

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// DefaultRoleCacheTTL is the lifetime of a cached role resolution. It is short so a grant or
// revocation takes effect within a few seconds across the fleet, mirroring the timeliness the
// group resolver buys by not baking groups into the JWT (BCH-1333, BCH-1319 §7).
const DefaultRoleCacheTTL = 10 * time.Second

// maxRoleCacheEntries caps the role cache, mirroring the decision cache. Eviction is
// opportunistic (sweep expired on insert at the cap), enough for the bounded subject set.
const maxRoleCacheEntries = 4096

// RoleResolver resolves a subject to its effective manifest roles. It is the engine-neutral
// seam the PDP reads roles through, so the source can be the persisted ccf_role_assignments
// table (the BCH-1333 source of truth) without the engine knowing. Implementations must be
// safe for concurrent use.
type RoleResolver interface {
	// RolesFor returns the subject's effective roles: the union of its direct grant and a grant
	// for each group it belongs to (plus the agent/anonymous defaults for non-user subjects).
	// The result is sorted and de-duplicated; an empty result is deny-by-default. An error means
	// the source could not be read — the caller (PDP) surfaces it so the PEP fail mode decides.
	RolesFor(ctx context.Context, s Subject) ([]string, error)
}

// RolesFor lets the in-memory RoleAssignments satisfy RoleResolver, so a deployment with no DB
// (some test suites, the pure-file fallback) keeps working unchanged. It never errors.
func (ra *RoleAssignments) RolesFor(_ context.Context, s Subject) ([]string, error) {
	return ra.rolesFor(s), nil
}

// dbRoleResolver resolves a user's roles from the persisted ccf_role_assignments table — the
// source of truth (BCH-1333) — and falls back to the static config for the agent/anonymous
// defaults the table does not hold. It mirrors the group resolver (pip.go): a per-subject
// lookup, behind a short-TTL cache so hot routes don't pay a DB read per request while a grant
// change still lands within the TTL.
type dbRoleResolver struct {
	db       *gorm.DB
	defaults *RoleAssignments // agent/anonymous defaults (and the user/group seed until BCH-1334)
	ttl      time.Duration
	logger   *zap.SugaredLogger

	mu      sync.Mutex
	entries map[string]roleCacheEntry
}

type roleCacheEntry struct {
	roles   []string
	expires time.Time
}

// NewDBRoleResolver constructs the DB-backed role resolver. defaults supplies the
// agent/anonymous roles (the table holds only user/group grants); a nil defaults becomes the
// agent service role only. A nil db returns the static defaults directly (no DB to read), so
// callers can wire it unconditionally. A ttl <= 0 disables caching (every lookup hits the DB).
func NewDBRoleResolver(db *gorm.DB, defaults *RoleAssignments, ttl time.Duration, logger *zap.SugaredLogger) RoleResolver {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	if defaults == nil {
		defaults = &RoleAssignments{Agents: DefaultAgentRole}
	}
	if db == nil {
		return defaults
	}
	return &dbRoleResolver{db: db, defaults: defaults, ttl: ttl, logger: logger, entries: map[string]roleCacheEntry{}}
}

// RolesFor implements RoleResolver.
func (r *dbRoleResolver) RolesFor(ctx context.Context, s Subject) ([]string, error) {
	if s.Type != "user" {
		// Agent and anonymous defaults still come from config: the table holds only user/group
		// grants, and BCH-1334 reconciles the file's user/group rows into it — not the defaults.
		return r.defaults.rolesFor(s), nil
	}
	if strings.TrimSpace(s.ID) == "" {
		return nil, nil
	}

	// subjectGroups already trims+lowercases; sort so the cache key is order-independent and the
	// IN clause is deterministic. Group grants are stored lower-cased, so these match directly.
	groups := subjectGroups(s)
	sort.Strings(groups)

	key := relational.NormalizeAssigneeID(s.ID) + "\x00" + strings.Join(groups, ",")
	if roles, ok := r.cacheGet(key); ok {
		return roles, nil
	}
	roles, err := r.query(ctx, s.ID, groups)
	if err != nil {
		return nil, err
	}
	r.cachePut(key, roles)
	return roles, nil
}

// query reads the user's direct grant and its group grants from the table and unions them,
// sorted and de-duplicated — the same shape RoleAssignments.rolesFor produced from the file.
func (r *dbRoleResolver) query(ctx context.Context, email string, groups []string) ([]string, error) {
	db := r.db.WithContext(ctx)
	set := map[string]struct{}{}

	var direct []string
	if err := db.Model(&relational.CCFRoleAssignment{}).
		Where("assignee_type = ? AND assignee_id = ?", relational.RoleAssigneeTypeUser, relational.NormalizeAssigneeID(email)).
		Pluck("role_name", &direct).Error; err != nil {
		return nil, err
	}
	for _, role := range direct {
		if role != "" {
			set[role] = struct{}{}
		}
	}

	if len(groups) > 0 {
		var grp []string
		if err := db.Model(&relational.CCFRoleAssignment{}).
			Where("assignee_type = ? AND assignee_id IN ?", relational.RoleAssigneeTypeGroup, groups).
			Pluck("role_name", &grp).Error; err != nil {
			return nil, err
		}
		for _, role := range grp {
			if role != "" {
				set[role] = struct{}{}
			}
		}
	}

	if len(set) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(set))
	for role := range set {
		out = append(out, role)
	}
	sort.Strings(out)
	return out, nil
}

func (r *dbRoleResolver) cacheGet(key string) ([]string, bool) {
	if r.ttl <= 0 {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expires) {
		delete(r.entries, key)
		return nil, false
	}
	return e.roles, true
}

func (r *dbRoleResolver) cachePut(key string, roles []string) {
	if r.ttl <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) >= maxRoleCacheEntries {
		now := time.Now()
		for k, e := range r.entries {
			if now.After(e.expires) {
				delete(r.entries, k)
			}
		}
	}
	r.entries[key] = roleCacheEntry{roles: roles, expires: time.Now().Add(r.ttl)}
}
