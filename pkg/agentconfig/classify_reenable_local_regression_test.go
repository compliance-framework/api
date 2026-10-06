package agentconfig

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression (review #471, fp 2db275ed2d26): re-enabling a plugin the base disables must
// classify its local source like a new plugin's, so allow_local_sources cannot be bypassed.
func TestClassifyReenabledPluginLocalSource(t *testing.T) {
	disabled := false
	base := Config{Plugins: map[string]*Plugin{
		"x": {Enabled: &disabled, Source: "./bin/local-plugin"},
	}}
	overlay := json.RawMessage(`{"plugins":{"x":{"enabled":true}}}`)

	t.Run("apply_all without allow_local_sources is forbidden", func(t *testing.T) {
		rc := RemoteConfig{Mode: ModeApplyAll}.Normalize(true)
		changes, err := Classify(base, overlay, rc)
		require.NoError(t, err)
		assert.Contains(t, changes, Change{Path: "/plugins/x/source", Safety: Forbidden, Reason: ChangeReasonLocalSourceNotAllowed, Value: "./bin/local-plugin"})
		apply, reason := WillApply(rc, changes)
		assert.False(t, apply)
		assert.Equal(t, ReasonForbiddenChanges, reason)
	})

	t.Run("apply_all with allow_local_sources is unsafe and applies", func(t *testing.T) {
		rc := RemoteConfig{Mode: ModeApplyAll, AllowLocalSources: true}.Normalize(true)
		changes, err := Classify(base, overlay, rc)
		require.NoError(t, err)
		assert.Contains(t, changes, Change{Path: "/plugins/x/source", Safety: Unsafe, Reason: ChangeReasonNewLocalSource, Value: "./bin/local-plugin"})
		apply, _ := WillApply(rc, changes)
		assert.True(t, apply)
	})

	t.Run("apply_safe is refused", func(t *testing.T) {
		rc := RemoteConfig{Mode: ModeApplySafe}.Normalize(true)
		changes, err := Classify(base, overlay, rc)
		require.NoError(t, err)
		apply, reason := WillApply(rc, changes)
		assert.False(t, apply)
		assert.Equal(t, ReasonForbiddenChanges, reason)
	})
}
