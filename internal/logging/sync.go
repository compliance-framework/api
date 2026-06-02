package logging

import (
	"errors"
	"syscall"
)

// IgnoreSyncError filters the known benign sync errors returned when zap flushes
// stdout/stderr-backed loggers on some platforms and runtimes.
func IgnoreSyncError(err error) bool {
	return err == nil ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOTTY)
}
