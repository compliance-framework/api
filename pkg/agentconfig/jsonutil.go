package agentconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// decodeAny decodes a single JSON value with UseNumber, so integers round-trip exactly.
// Empty or whitespace-only input decodes to nil (JSON null). Trailing data is an error.
//
// A document nested at most numberValueMaxDepth deep is decoded in place with json.Unmarshal
// (see numberValue): a json.Decoder copies its input through a buffer it grows by doubling,
// several times the size of a large document. Deeper documents, and input Unmarshal
// rejects, go through the Decoder, so the errors stay the Decoder's.
func decodeAny(data []byte) (any, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	if nestedWithin(data, numberValueMaxDepth) {
		var nv numberValue
		if err := json.Unmarshal(data, &nv); err == nil {
			return nv.v, nil
		}
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

// numberValueMaxDepth bounds the nesting numberValue decodes. json.Unmarshal re-scans an
// Unmarshaler's value at every level, so numberValue costs about twice the document size
// per level of nesting.
const numberValueMaxDepth = 12

// numberValue decodes a JSON value exactly as a json.Decoder with UseNumber decodes it into
// an any (objects as map[string]any, arrays as []any, numbers as json.Number), but with
// json.Unmarshal, which reads the input in place.
type numberValue struct{ v any }

// nestedWithin reports whether the objects and arrays of data (assumed to be JSON) nest at
// most limit deep. It skips string contents, so brackets inside strings do not count.
func nestedWithin(data []byte, limit int) bool {
	depth := 0
	inString, escaped := false, false
	for _, c := range data {
		switch {
		case inString:
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			if depth++; depth > limit {
				return false
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return true
}

func (n *numberValue) UnmarshalJSON(b []byte) error {
	switch b[0] {
	case '{':
		var m map[string]numberValue
		if err := json.Unmarshal(b, &m); err != nil {
			return err
		}
		out := make(map[string]any, len(m))
		for k, e := range m {
			out[k] = e.v
		}
		n.v = out
	case '[':
		var s []numberValue
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		out := make([]any, len(s))
		for i, e := range s {
			out[i] = e.v
		}
		n.v = out
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		n.v = json.Number(b)
	default: // string, true, false, null
		return json.Unmarshal(b, &n.v)
	}
	return nil
}

// encodeCanonical encodes v without HTML escaping and without a trailing newline. Map keys
// are sorted by encoding/json, so the output is canonical for decoded (map/slice/Number)
// values.
func encodeCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// CanonicalJSON returns the canonical encoding of v: json.Marshal, decode to any with
// UseNumber, re-encode with SetEscapeHTML(false) and no trailing newline. Object keys are
// sorted. It is the encoding Digest hashes.
//
// It intentionally duplicates the API's internal/artifact.CanonicalJSON: artifact forms are
// pinned by golden tests, and this public package must not import internal/.
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	decoded, err := decodeAny(raw)
	if err != nil {
		return nil, err
	}
	return encodeCanonical(decoded)
}

// decodeConfig decodes a JSON document into a Config non-strictly (unknown fields are
// ignored) with UseNumber for the free-form maps.
func decodeConfig(data []byte) (Config, error) {
	var c Config
	if len(bytes.TrimSpace(data)) == 0 || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return c, nil
	}
	v, err := decodeAny(data)
	if err != nil {
		return Config{}, err
	}
	if obj, ok := v.(map[string]any); ok {
		dropMiscasedKeys(obj)
		if data, err = encodeCanonical(obj); err != nil {
			return Config{}, err
		}
		// json.Unmarshal reads data in place, where a Decoder copies it through a growing
		// buffer. It decodes like a UseNumber Decoder except for the numbers of policy_data,
		// the one free-form field, which usePolicyDataNumbers takes from obj. Input it
		// rejects goes through the Decoder below, so the errors stay the Decoder's.
		if err := json.Unmarshal(data, &c); err == nil {
			usePolicyDataNumbers(&c, obj)
			return c, nil
		}
		c = Config{}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// usePolicyDataNumbers replaces each decoded plugin's policy_data with its value in obj, the
// UseNumber decoding of the same document, so its numbers are json.Number as a UseNumber
// Decoder leaves them (json.Unmarshal makes them float64).
func usePolicyDataNumbers(c *Config, obj map[string]any) {
	plugins, _ := obj["plugins"].(map[string]any)
	for name, p := range c.Plugins {
		if p == nil || p.PolicyData == nil {
			continue
		}
		raw, _ := plugins[name].(map[string]any)
		if pd, ok := raw["policy_data"].(map[string]any); ok {
			p.PolicyData = pd
		}
	}
}

// Schema field names per object level, for dropMiscasedKeys.
var (
	rootFields         = []string{"daemon", "verbosity", "api", "remote_config", "plugins", "agent_evidence"}
	apiFields          = []string{"url", "auth"}
	apiAuthFields      = []string{"client_id", "client_secret"}
	remoteConfigFields = []string{"mode", "poll_interval", "trusted_sources", "overridable_config_flags", "allow_local_sources"}
	evidenceFields     = []string{"enabled", "emit_on_run_completion", "interval"}
	pluginFields       = []string{"enabled", "protocol_version", "schedule", "source", "policies", "config", "labels", "policy_data", "policy_behavior"}
)

// dropMiscasedKeys removes keys that encoding/json would match case-insensitively to a schema
// field without being that exact field name (e.g. "Plugins" or "plugins.x.Source"). Without
// this a document could smuggle a value in through a differently-cased key that no strict
// check looks at. Other unknown keys are left alone (the non-strict decode ignores them).
func dropMiscasedKeys(root map[string]any) {
	dropMiscased(root, rootFields)
	if api, ok := root["api"].(map[string]any); ok {
		dropMiscased(api, apiFields)
		if auth, ok := api["auth"].(map[string]any); ok {
			dropMiscased(auth, apiAuthFields)
		}
	}
	if rc, ok := root["remote_config"].(map[string]any); ok {
		dropMiscased(rc, remoteConfigFields)
	}
	if ev, ok := root["agent_evidence"].(map[string]any); ok {
		dropMiscased(ev, evidenceFields)
	}
	if plugins, ok := root["plugins"].(map[string]any); ok {
		for _, raw := range plugins {
			if p, ok := raw.(map[string]any); ok {
				dropMiscased(p, pluginFields)
			}
		}
	}
}

func dropMiscased(obj map[string]any, fields []string) {
	for k := range obj {
		if slices.Contains(fields, k) {
			continue
		}
		for _, f := range fields {
			if strings.EqualFold(k, f) {
				delete(obj, k)
				break
			}
		}
	}
}

// DecodeConfig decodes a reported config document (base or effective) non-strictly: unknown
// fields are ignored so a newer agent's fields never make the API reject a report (R51).
func DecodeConfig(data []byte) (Config, error) {
	c, err := decodeConfig(data)
	if err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	return c, nil
}

// clone deep-copies a Config. Free-form values (policy_data) are normalized
// on the way: map[any]any (as produced by some YAML decoders) becomes map[string]any, so the
// copy is always JSON-encodable.
func (c Config) clone() Config {
	out := c
	if c.API != nil {
		api := *c.API
		if c.API.Auth != nil {
			auth := *c.API.Auth
			api.Auth = &auth
		}
		out.API = &api
	}
	if c.RemoteConfig != nil {
		rc := *c.RemoteConfig
		rc.TrustedSources = cloneStrings(c.RemoteConfig.TrustedSources)
		rc.OverridableConfigFlags = cloneStrings(c.RemoteConfig.OverridableConfigFlags)
		out.RemoteConfig = &rc
	}
	if c.AgentEvidence != nil {
		ev := *c.AgentEvidence
		ev.Enabled = cloneBoolPtr(c.AgentEvidence.Enabled)
		ev.EmitOnRunCompletion = cloneBoolPtr(c.AgentEvidence.EmitOnRunCompletion)
		out.AgentEvidence = &ev
	}
	if c.Plugins != nil {
		out.Plugins = make(map[string]*Plugin, len(c.Plugins))
		for name, p := range c.Plugins {
			out.Plugins[name] = p.clone()
		}
	}
	return out
}

func (p *Plugin) clone() *Plugin {
	if p == nil {
		return nil
	}
	out := *p
	out.Enabled = cloneBoolPtr(p.Enabled)
	if p.Schedule != nil {
		s := *p.Schedule
		out.Schedule = &s
	}
	out.Policies = cloneStrings(p.Policies)
	out.Config = cloneStringMap(p.Config)
	out.Labels = cloneStringMap(p.Labels)
	if p.PolicyData != nil {
		out.PolicyData = deepCopyAny(map[string]any(p.PolicyData)).(map[string]any)
	}
	if p.PolicyBehavior != nil {
		out.PolicyBehavior = make(map[string][]string, len(p.PolicyBehavior))
		for k, v := range p.PolicyBehavior {
			out.PolicyBehavior[k] = cloneStrings(v)
		}
	}
	return &out
}

func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	return append(make([]string, 0, len(s)), s...)
}

func cloneStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneBoolPtr(b *bool) *bool {
	if b == nil {
		return nil
	}
	v := *b
	return &v
}

// deepCopyAny deep-copies a free-form value, converting map[any]any to map[string]any.
func deepCopyAny(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = deepCopyAny(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[fmt.Sprint(k)] = deepCopyAny(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = deepCopyAny(val)
		}
		return out
	case []string:
		return cloneStrings(t)
	case map[string]string:
		return cloneStringMap(t)
	default:
		return v
	}
}
