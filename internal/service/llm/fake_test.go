package llm

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFakeClientReturnsConfiguredResponse(t *testing.T) {
	fake := &FakeClient{
		Raw:          json.RawMessage(`{"ok":true}`),
		Model:        "fake-model",
		InputTokens:  3,
		OutputTokens: 5,
	}

	resp, err := fake.CompleteStructured(context.Background(), StructuredRequest{Prompt: "prompt"})

	require.NoError(t, err)
	require.Equal(t, json.RawMessage(`{"ok":true}`), resp.Raw)
	require.Equal(t, "fake-model", resp.Model)
	require.Equal(t, 3, resp.InputTokens)
	require.Equal(t, 5, resp.OutputTokens)
	require.Len(t, fake.Requests, 1)
	require.Equal(t, "prompt", fake.Requests[0].Prompt)
}
