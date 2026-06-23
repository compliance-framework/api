package authz

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// DriverBuiltin is the name of the default, in-process driver.
const DriverBuiltin = "builtin"

// Deps are the runtime dependencies handed to a driver factory. The builtin driver uses
// all three; remote drivers (later phases) may ignore the DB.
type Deps struct {
	DB     *gorm.DB
	Config *config.Config
	Logger *zap.SugaredLogger
}

// Options selects and configures the driver to open. Endpoint is the remote PDP URL used
// by HTTP drivers (authzen); CacheTTL, when > 0, wraps the constructed PDP in a short-TTL
// decision cache to absorb the network hop. Both are ignored by the in-process builtin.
type Options struct {
	Driver   string
	Endpoint string
	CacheTTL time.Duration
}

// Factory constructs a PDP for a registered driver.
type Factory func(opts Options, deps Deps) (PDP, error)

var (
	driversMu sync.RWMutex
	drivers   = map[string]Factory{}
)

// Register makes an authz driver available by name. It mirrors database/sql's driver
// registration: drivers self-register from an init function, and Register panics on a
// nil factory or a duplicate name.
func Register(name string, factory Factory) {
	driversMu.Lock()
	defer driversMu.Unlock()
	if factory == nil {
		panic("authz: Register factory is nil")
	}
	if _, dup := drivers[name]; dup {
		panic("authz: Register called twice for driver " + name)
	}
	drivers[name] = factory
}

// Drivers returns the registered driver names, sorted.
func Drivers() []string {
	driversMu.RLock()
	defer driversMu.RUnlock()
	names := make([]string, 0, len(drivers))
	for n := range drivers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Open constructs the configured PDP. An empty driver name selects the builtin driver.
// It also parses the embedded manifest so a broken vocabulary fails fast at startup
// rather than per request.
func Open(opts Options, deps Deps) (PDP, error) {
	name := opts.Driver
	if name == "" {
		name = DriverBuiltin
	}
	driversMu.RLock()
	factory, ok := drivers[name]
	driversMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("authz: unknown driver %q (forgotten import?)", name)
	}
	if _, err := DefaultManifest(); err != nil {
		return nil, fmt.Errorf("authz: load manifest: %w", err)
	}
	pdp, err := factory(opts, deps)
	if err != nil {
		return nil, err
	}
	// Optional short-TTL decision cache. Off by default; the in-process builtin gains
	// nothing from it, but operators may enable it for remote PDPs to absorb the hop.
	if opts.CacheTTL > 0 {
		pdp = newCachingPDP(pdp, opts.CacheTTL, deps.Logger)
	}
	// Populate subject.groups uniformly for engines that consume it (Cedar/AuthZen, which
	// expect it pre-resolved — BCH-1328). The PIP sits OUTSIDE the cache so a membership
	// change invalidates cached decisions. The builtin driver is skipped: it resolves groups
	// itself, lazily, only on the admin path, so it never pays a per-request membership read
	// on hot non-admin routes (e.g. evidence ingest). Needs DB locality, so a nil DB skips it.
	if deps.DB != nil && name != DriverBuiltin {
		pdp = newResolvingPDP(pdp, NewDBGroupResolver(deps.DB, deps.Logger), deps.Logger)
	}
	return pdp, nil
}
