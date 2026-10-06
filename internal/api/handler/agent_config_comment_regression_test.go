package handler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression (review #481, fp a042387242aa): a NUL character cannot be stored in the
// comment column, so it is a 400, not a 500 from the insert.
func TestNormalizeCommentRejectsNUL(t *testing.T) {
	c := "a\x00b"
	_, err := normalizeComment(&c)
	assert.Error(t, err)

	ok := "  fine  "
	got, err := normalizeComment(&ok)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "fine", *got)
}
