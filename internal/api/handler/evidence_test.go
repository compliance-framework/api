package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestEvidenceHandler_Create_WithFutureDate_ReturnsError(t *testing.T) {
	// Setup
	e := echo.New()
	createRequest := &EvidenceCreateRequest{
		Start: time.Now().UTC().AddDate(0, -1, 0), // One month in the past
		End:   time.Now().UTC().AddDate(0, 1, 0),  // One month in the future
	}

	b, _ := json.Marshal(createRequest)
	req := httptest.NewRequest(http.MethodPost, "/evidence", bytes.NewReader(b))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	h := NewEvidenceHandler(nil, nil, nil)

	// Assertions
	if assert.NoError(t, h.Create(ctx)) {
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	}
}

func TestImplementedComponentLinkID_UnambiguousPairs(t *testing.T) {
	// These pairs produce the same SeededUUID seed string under a naive
	// two-key map, so they must still get distinct link IDs.
	a, err := implementedComponentLinkID("c", "a-inventory-item=b")
	assert.NoError(t, err)
	b, err := implementedComponentLinkID("b-inventory-item=c", "a")
	assert.NoError(t, err)
	assert.NotEqual(t, a, b)

	again, err := implementedComponentLinkID("c", "a-inventory-item=b")
	assert.NoError(t, err)
	assert.Equal(t, a, again, "link IDs must be deterministic")
}
