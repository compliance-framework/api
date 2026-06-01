package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultWorkerConfig_UsePollingDisabledByDefault(t *testing.T) {
	cfg := DefaultWorkerConfig()

	assert.False(t, cfg.UsePolling)
}
