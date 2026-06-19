package authz

import (
	"fmt"
	"sort"
	"sync"

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

// Options selects and configures the driver to open. Driver-specific settings (endpoint,
// cache TTL, ...) are added here as later-phase drivers land.
type Options struct {
	Driver string
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
	return factory(opts, deps)
}
