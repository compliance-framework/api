package authz

import (
	"fmt"
	"sort"
	"sync"

	"github.com/compliance-framework/api/internal/config"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// FailMode controls what the PEP does when a PDP cannot return a decision
// (error or timeout). It defaults to closed.
type FailMode string

const (
	// FailClosed denies the request when the evaluator cannot decide.
	FailClosed FailMode = "closed"
	// FailOpen allows the request when the evaluator cannot decide.
	FailOpen FailMode = "open"
)

// ParseFailMode maps a config string to a FailMode, defaulting to FailClosed
// for empty or unrecognized values.
func ParseFailMode(s string) FailMode {
	if FailMode(s) == FailOpen {
		return FailOpen
	}
	return FailClosed
}

// Options carries everything a driver factory might need. In-process drivers
// (like builtin) use DB/Config; remote drivers use Settings (driver-specific
// values from config such as endpoint or cache_ttl). Manifest is the loaded
// authorization vocabulary. Drivers take only what they need, much like a
// database driver parses only the parts of a DSN it understands.
type Options struct {
	DB       *gorm.DB
	Config   *config.Config
	Logger   *zap.SugaredLogger
	Manifest *Manifest
	Settings map[string]any
}

// Factory builds a PDP from Options.
type Factory func(Options) (PDP, error)

var (
	driversMu sync.RWMutex
	drivers   = map[string]Factory{}
)

// Register makes an authorization driver available by name. It mirrors
// database/sql's driver registration and is intended to be called from a
// driver's init(). It panics on a duplicate or nil registration.
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

// Drivers returns the names of the registered drivers, sorted.
func Drivers() []string {
	driversMu.RLock()
	defer driversMu.RUnlock()
	names := make([]string, 0, len(drivers))
	for name := range drivers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Open constructs the PDP registered under name using opts. It returns an error
// (rather than falling back) so a misconfigured authz.driver fails fast at
// startup instead of silently changing the enforcement engine.
func Open(name string, opts Options) (PDP, error) {
	driversMu.RLock()
	factory, ok := drivers[name]
	driversMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("authz: unknown driver %q (registered: %v)", name, Drivers())
	}
	return factory(opts)
}
