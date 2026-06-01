package logging

import (
	"errors"
	"syscall"
	"testing"
)

// Test the catching of sync errors
func TestIgnoreSyncError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: true},
		{name: "EINVAL", err: syscall.EINVAL, want: true},
		{name: "wrapped EINVAL", err: errors.New("sync: " + syscall.EINVAL.Error()), want: false},
		{name: "ENOTTY", err: syscall.ENOTTY, want: true},
		{name: "other", err: syscall.EBADF, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IgnoreSyncError(tt.err); got != tt.want {
				t.Fatalf("IgnoreSyncError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
