package config

import "github.com/spf13/viper"

// Authorization driver and fail-mode defaults. The defaults reproduce CCF's
// existing behavior: the in-process builtin engine, failing closed.
const (
	AuthZDriverBuiltin = "builtin"
	AuthZFailClosed    = "closed"
	AuthZFailOpen      = "open"
)

// AuthZConfig holds the operator-facing authorization settings. The decision
// engine itself is selected by Driver (see internal/authz drivers); FailMode
// controls what the enforcement point does when the engine cannot decide.
//
// Configured via the flat Viper keys used elsewhere in this package:
//
//	authz_driver     (env CCF_AUTHZ_DRIVER)     default "builtin"
//	authz_fail_mode  (env CCF_AUTHZ_FAIL_MODE)  default "closed"
type AuthZConfig struct {
	Driver   string
	FailMode string
}

func loadAuthZConfig() *AuthZConfig {
	driver := viper.GetString("authz_driver")
	if driver == "" {
		driver = AuthZDriverBuiltin
	}
	failMode := viper.GetString("authz_fail_mode")
	if failMode != AuthZFailOpen {
		// Anything other than an explicit "open" fails closed.
		failMode = AuthZFailClosed
	}
	return &AuthZConfig{Driver: driver, FailMode: failMode}
}
