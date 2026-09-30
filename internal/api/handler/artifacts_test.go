package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/artifact"
	"github.com/compliance-framework/api/internal/config"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newTestArtifactHandler(maxConcurrent int, wait time.Duration) *ArtifactHandler {
	h := NewArtifactHandler(zap.NewNop().Sugar(), nil, &config.ArtifactConfig{MaxBytes: 1 << 20, MaxConcurrent: maxConcurrent})
	h.slotWait = wait
	return h
}

func TestArtifactHandlerSlots(t *testing.T) {
	t.Run("bounds concurrent uploads", func(t *testing.T) {
		h := newTestArtifactHandler(2, 20*time.Millisecond)
		first, ok := h.acquireSlot(context.Background())
		require.True(t, ok)
		second, ok := h.acquireSlot(context.Background())
		require.True(t, ok)

		_, ok = h.acquireSlot(context.Background())
		assert.False(t, ok, "a third upload must not get a slot while two are in progress")

		first()
		third, ok := h.acquireSlot(context.Background())
		assert.True(t, ok, "a released slot is reused")
		second()
		third()
	})

	t.Run("waits for a slot to free up", func(t *testing.T) {
		h := newTestArtifactHandler(1, 5*time.Second)
		held, ok := h.acquireSlot(context.Background())
		require.True(t, ok)
		go func() {
			time.Sleep(20 * time.Millisecond)
			held()
		}()

		started := time.Now()
		release, ok := h.acquireSlot(context.Background())
		require.True(t, ok)
		release()
		assert.Less(t, time.Since(started), time.Second, "the waiter proceeds as soon as the slot is released")
	})

	t.Run("gives up when the request ends", func(t *testing.T) {
		h := newTestArtifactHandler(1, 5*time.Second)
		held, ok := h.acquireSlot(context.Background())
		require.True(t, ok)
		defer held()

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, ok = h.acquireSlot(ctx)
		assert.False(t, ok)
	})

	t.Run("a non-positive limit falls back to the default", func(t *testing.T) {
		h := newTestArtifactHandler(0, time.Millisecond)
		assert.Equal(t, config.DefaultArtifactConfig().MaxConcurrent, cap(h.slots))
	})
}

func TestArtifactUploadReturns429WhenBusy(t *testing.T) {
	h := newTestArtifactHandler(1, 10*time.Millisecond)
	held, ok := h.acquireSlot(context.Background())
	require.True(t, ok)
	defer held()

	req := httptest.NewRequest(http.MethodPost, "/api/agent/artifacts", strings.NewReader(`{"a":1}`))
	req.Header.Set(echo.HeaderContentType, artifact.MediaTypeJSON)
	rec := httptest.NewRecorder()
	require.NoError(t, h.Upload(echo.New().NewContext(req, rec)))
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Contains(t, rec.Body.String(), "too many artifact uploads")
}
