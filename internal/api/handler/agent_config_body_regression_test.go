package handler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression (review #481, fp 8ef552cfc250): decodeStrict must reject any data after the
// JSON object, including a stray closing brace or bracket.
func TestDecodeStrictRejectsTrailingData(t *testing.T) {
	for _, body := range []string{
		`{"overlay":{}}}`,
		`{"overlay":{}}]`,
		`{"overlay":{}} x`,
		`{"overlay":{}} {}`,
	} {
		var req agentConfigPutRequest
		assert.Error(t, decodeStrict([]byte(body), &req), body)
	}
	var req agentConfigPutRequest
	require.NoError(t, decodeStrict([]byte(" {\"overlay\":{}} \n"), &req), "trailing whitespace is fine")
}
