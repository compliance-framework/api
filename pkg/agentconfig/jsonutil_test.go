package agentconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeAnyWithDecoder is the reference decodeAny must match: a json.Decoder with UseNumber.
func decodeAnyWithDecoder(data []byte) (any, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after the JSON value")
	}
	return v, nil
}

func TestDecodeAnyMatchesDecoder(t *testing.T) {
	deep := strings.Repeat("[", numberValueMaxDepth+1) + "1" + strings.Repeat("]", numberValueMaxDepth+1)
	atLimit := strings.Repeat(`{"a":`, numberValueMaxDepth) + "1.50" + strings.Repeat("}", numberValueMaxDepth)
	for _, in := range []string{
		`{"a":1,"b":-0.5e+10,"c":12345678901234567890123,"d":1.0,"e":[1,2.50,[]],"f":{}}`,
		`{"s":"x\"}]{[\\","u":"é😀","n":null,"t":true,"f":false}`,
		` [ {"a" : [ ] } , "x" , 0 ] `,
		`{"dup":1,"dup":2}`,
		"\"\xff\xfe invalid utf-8\"",
		`"plain"`, `12`, `-0`, `true`, `null`,
		deep, atLimit,
		`{"a":1} x`, `{"a":1}}`, `{"a":1} {}`, `{"a":}`, `[1,]`, `{"a" 1}`, `01`, `{`,
	} {
		want, wantErr := decodeAnyWithDecoder([]byte(in))
		got, err := decodeAny([]byte(in))
		if wantErr != nil {
			require.Error(t, err, in)
			assert.Equal(t, wantErr.Error(), err.Error(), in)
			continue
		}
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
}

func TestNestedWithin(t *testing.T) {
	assert.True(t, nestedWithin([]byte(`{"a":[{"b":1}]}`), 3))
	assert.False(t, nestedWithin([]byte(`{"a":[{"b":1}]}`), 2))
	assert.True(t, nestedWithin([]byte(`{"a":"[[[[\"[[["}`), 1), "brackets in strings do not count")
	assert.True(t, nestedWithin([]byte(`["\\",[1]]`), 2), "an escaped backslash ends the escape")
}

// DecodeConfig keeps the exact number literals of policy_data, as a UseNumber Decoder does,
// and decodes everything else as before.
func TestDecodeConfigPolicyDataNumbers(t *testing.T) {
	raw := []byte(`{"daemon":true,"verbosity":2,"Verbosity":1,"plugins":{
		"p":{"source":"s","protocol_version":2,"policy_data":{"big":12345678901234567890123,"f":1.50,"nested":{"l":[1,{"x":2.0}]}},"Policy_Data":{"x":1}},
		"q":{"source":"s"}}}`)
	got, err := DecodeConfig(raw)
	require.NoError(t, err)

	var want Config
	obj, err := decodeAnyWithDecoder(raw)
	require.NoError(t, err)
	dropMiscasedKeys(obj.(map[string]any))
	canonical, err := encodeCanonical(obj)
	require.NoError(t, err)
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.UseNumber()
	require.NoError(t, dec.Decode(&want))

	assert.Equal(t, want, got)
	assert.Equal(t, json.Number("12345678901234567890123"), got.Plugins["p"].PolicyData["big"])
	assert.Equal(t, json.Number("1.50"), got.Plugins["p"].PolicyData["f"])
	assert.Nil(t, got.Plugins["q"].PolicyData)

	// A document Unmarshal rejects keeps the Decoder's error.
	_, err = DecodeConfig([]byte(`{"plugins":{"p":{"policy_data":[1]}}}`))
	require.Error(t, err)
	var typeErr *json.UnmarshalTypeError
	assert.ErrorAs(t, err, &typeErr)
}
