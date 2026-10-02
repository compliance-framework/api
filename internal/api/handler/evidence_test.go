package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
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

func TestSubjectReferencesForResponses(t *testing.T) {
	ns := relational.CCFOSCALNamespace
	template := relational.EvidenceSubjectReference{
		SubjectUUID: uuid.New(),
		Type:        "component",
		Title:       "GitHub Organization: acme",
		Source:      relational.EvidenceSubjectSourceTemplate,
		Priority:    1,
		Props:       []relational.Prop{{Ns: ns, Name: relational.EvidenceSubjectPropSource, Value: relational.EvidenceSubjectSourceTemplate}},
		Links:       []relational.Link{{Href: "https://github.com/acme", Rel: "canonical"}},
	}
	legacy := relational.EvidenceSubjectReference{
		SubjectUUID: uuid.New(),
		Type:        "Component",
		Source:      relational.EvidenceSubjectSourceLegacy,
		Props:       []relational.Prop{{Ns: ns, Name: relational.EvidenceSubjectPropSource, Value: relational.EvidenceSubjectSourceLegacy}},
	}
	refs := []relational.EvidenceSubjectReference{legacy, template}

	full := *fullSubjectReferences(refs)
	assert.Len(t, full, 2)
	assert.Equal(t, template.SubjectUUID.String(), full[0].SubjectUuid, "display order: higher priority first")
	assert.NotNil(t, full[0].Props)
	assert.NotNil(t, full[0].Links)
	assert.Equal(t, legacy.SubjectUUID.String(), full[1].SubjectUuid)

	compact := *compactSubjectReferences(refs)
	assert.Equal(t, []oscalTypes_1_1_3.SubjectReference{{
		SubjectUuid: template.SubjectUUID.String(),
		Type:        "component",
		Title:       "GitHub Organization: acme",
	}}, compact, "only uuid, type and title, without legacy subjects")

	assert.NotNil(t, compactSubjectReferences(nil), "no subjects is an empty list, not an absent one")
	assert.Empty(t, *compactSubjectReferences([]relational.EvidenceSubjectReference{legacy}))
}
