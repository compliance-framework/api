package agentconfig

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func redactBase() Config {
	return Config{
		Daemon: true,
		API: &APIConfig{
			URL:  "https://api.example.com",
			Auth: &APIAuth{ClientID: "0b3c1b8a-7c8e-4d53-9a52-9a3c1d1f2e10", ClientSecret: "s3cret"},
		},
		Plugins: map[string]*Plugin{
			"local-ssh": {
				Source: srcSSH,
				Config: map[string]string{
					"host":        "localhost",
					"user":        "root",
					"password":    "hunter2",
					"api_key":     "k",
					"AuthHeader":  "Bearer x",
					"db_password": "${env:DB_PASSWORD}",
					"dsn":         "postgres://u:${env:PG_PASS}@h/db",
				},
				Labels: map[string]string{"token": "label-values-are-not-redacted"},
				PolicyData: map[string]any{
					"threshold": json.Number("5"),
					"db": map[string]any{
						"host":     "h",
						"password": "p",
						"port":     json.Number("5432"),
					},
					"credentials": map[string]any{"user": "a", "pass": "b"},
					"tokens":      []any{"t1", "t2"},
					"secret_n":    json.Number("42"),
					"items":       []any{map[string]any{"passwd": "x", "name": "n"}},
					"env_token":   "${env:TOKEN}",
					"nothing":     nil,
				},
			},
			"nil-plugin": nil,
		},
	}
}

func TestRedact(t *testing.T) {
	in := redactBase()
	out := Redact(in)

	assert.Equal(t, "••••", MaskedValue, "the mask is exactly four bullets")

	require.NotNil(t, out.API)
	assert.Equal(t, "https://api.example.com", out.API.URL)
	assert.Equal(t, "0b3c1b8a-7c8e-4d53-9a52-9a3c1d1f2e10", out.API.Auth.ClientID)
	assert.Empty(t, out.API.Auth.ClientSecret, "client secret cleared")

	cfg := out.Plugins["local-ssh"].Config
	assert.Equal(t, "localhost", cfg["host"])
	assert.Equal(t, "root", cfg["user"])
	assert.Equal(t, MaskedValue, cfg["password"])
	assert.Equal(t, MaskedValue, cfg["api_key"])
	assert.Equal(t, MaskedValue, cfg["AuthHeader"], "case-insensitive key match")
	assert.Equal(t, "${env:DB_PASSWORD}", cfg["db_password"], "env placeholders kept verbatim")
	assert.Equal(t, "postgres://u:${env:PG_PASS}@h/db", cfg["dsn"], "embedded placeholders kept verbatim")

	assert.Equal(t, "label-values-are-not-redacted", out.Plugins["local-ssh"].Labels["token"], "labels are not in the mask scope")
	assert.Equal(t, srcSSH, out.Plugins["local-ssh"].Source)
	assert.Nil(t, out.Plugins["nil-plugin"])

	pd := out.Plugins["local-ssh"].PolicyData
	assert.Equal(t, json.Number("5"), pd["threshold"])
	assert.Equal(t, map[string]any{"host": "h", "password": MaskedValue, "port": json.Number("5432")}, pd["db"])
	assert.Equal(t, MaskedValue, pd["credentials"], "non-string value under a matching key masked whole")
	assert.Equal(t, MaskedValue, pd["tokens"], "array under a matching key masked whole")
	assert.Equal(t, MaskedValue, pd["secret_n"], "number under a matching key masked")
	assert.Equal(t, []any{map[string]any{"passwd": MaskedValue, "name": "n"}}, pd["items"])
	assert.Equal(t, "${env:TOKEN}", pd["env_token"])
	assert.Contains(t, pd, "nothing")
	assert.Nil(t, pd["nothing"])

	assert.Equal(t, redactBase(), in, "input not mutated")
}

func TestRedactWithMaskedPointers(t *testing.T) {
	out := Redact(redactBase(), WithMaskedPointers(
		"/plugins/local-ssh/config/user",
		"/plugins/local-ssh/config/db_password", // placeholder wins over the pointer
		"/plugins/local-ssh/policy_data/db/host",
		"/plugins/local-ssh/policy_data/threshold",
	), WithMaskedPointers("/plugins/local-ssh/config/host"))

	cfg := out.Plugins["local-ssh"].Config
	assert.Equal(t, MaskedValue, cfg["user"])
	assert.Equal(t, MaskedValue, cfg["host"], "options accumulate")
	assert.Equal(t, "${env:DB_PASSWORD}", cfg["db_password"])
	pd := out.Plugins["local-ssh"].PolicyData
	assert.Equal(t, MaskedValue, pd["db"].(map[string]any)["host"])
	assert.Equal(t, MaskedValue, pd["threshold"], "non-string at a masked pointer")
}

func TestRedactPointerEscaping(t *testing.T) {
	c := Config{Plugins: map[string]*Plugin{"p": {Source: srcSSH, Config: map[string]string{"a/b": "v", "a~b": "w"}}}}
	out := Redact(c, WithMaskedPointers(Pointer("plugins", "p", "config", "a/b")))
	assert.Equal(t, MaskedValue, out.Plugins["p"].Config["a/b"])
	assert.Equal(t, "w", out.Plugins["p"].Config["a~b"])
}

func TestRedactIdempotent(t *testing.T) {
	opts := []RedactOption{WithMaskedPointers("/plugins/local-ssh/config/user")}
	once := Redact(redactBase(), opts...)
	twice := Redact(once, opts...)
	assert.Equal(t, once, twice)
	assert.Equal(t, Digest(once, opts...), Digest(twice, opts...))
}

func TestRedactYAMLMaps(t *testing.T) {
	c := Config{Plugins: map[string]*Plugin{"p": {Source: srcSSH, PolicyData: map[string]any{"m": map[any]any{"token": "x", 1: "y"}}}}}
	out := Redact(c)
	assert.Equal(t, map[string]any{"token": MaskedValue, "1": "y"}, out.Plugins["p"].PolicyData["m"])
	_, err := json.Marshal(out)
	assert.NoError(t, err)
}

func TestDigest(t *testing.T) {
	d := Digest(redactBase())
	assert.True(t, strings.HasPrefix(d, "sha256:"), d)
	assert.Len(t, d, len("sha256:")+64)

	t.Run("stable", func(t *testing.T) {
		opts := []RedactOption{WithMaskedPointers("/plugins/local-ssh/config/user")}
		first := Digest(redactBase(), opts...)
		for range 20 {
			assert.Equal(t, first, Digest(redactBase(), opts...))
		}
	})
	t.Run("differs when options differ", func(t *testing.T) {
		assert.NotEqual(t, Digest(redactBase()), Digest(redactBase(), WithMaskedPointers("/plugins/local-ssh/config/user")))
	})
	t.Run("equal when masking makes documents equal", func(t *testing.T) {
		a := redactBase()
		b := redactBase()
		b.Plugins["local-ssh"].Config["password"] = "different"
		assert.Equal(t, Digest(a), Digest(b))
	})
	t.Run("differs on a real change", func(t *testing.T) {
		b := redactBase()
		b.Plugins["local-ssh"].Config["host"] = "other"
		assert.NotEqual(t, Digest(redactBase()), Digest(b))
	})
	t.Run("ignores api block", func(t *testing.T) {
		b := redactBase()
		b.API = &APIConfig{URL: "https://other.example.com", Auth: &APIAuth{ClientID: "x", ClientSecret: "y"}}
		assert.Equal(t, Digest(redactBase()), Digest(b))
		b.API = nil
		assert.Equal(t, Digest(redactBase()), Digest(b))
	})
	t.Run("matches the canonical redacted document", func(t *testing.T) {
		r := Redact(redactBase())
		r.API = nil
		raw, err := CanonicalJSON(r)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), `&`, "no HTML escaping")
		assert.False(t, strings.HasSuffix(string(raw), "\n"))
		// Digest of a round-tripped document is the same.
		back, err := DecodeConfig(raw)
		require.NoError(t, err)
		assert.Equal(t, Digest(redactBase()), Digest(back))
	})
}

func TestCanonicalJSON(t *testing.T) {
	raw, err := CanonicalJSON(map[string]any{"b": "<&>", "a": json.Number("12345678901234567890"), "c": []any{}})
	require.NoError(t, err)
	assert.Equal(t, `{"a":12345678901234567890,"b":"<&>","c":[]}`, string(raw))
}

func TestBundleTreeDigestGolden(t *testing.T) {
	got := BundleTreeDigest(map[string][]byte{
		"a.rego":    []byte("package a\n"),
		"data.json": []byte("{}"),
	})
	// Also documented in the BundleTreeDigest godoc for the agent.
	assert.Equal(t, "tree:sha256:7e0808049205b3cce8b6f1bbedbef302d261072214504dd6add0d5674d2e5c2c", got)
}

func TestBundleTreeDigest(t *testing.T) {
	a := map[string][]byte{"z.rego": []byte("package z"), "a.rego": []byte("package a"), "sub/data.json": []byte(`{"x":1}`)}
	b := map[string][]byte{"sub/data.json": []byte(`{"x":1}`), "a.rego": []byte("package a"), "z.rego": []byte("package z")}
	assert.Equal(t, BundleTreeDigest(a), BundleTreeDigest(b), "independent of map order")
	for range 20 {
		assert.Equal(t, BundleTreeDigest(a), BundleTreeDigest(b))
	}

	changed := map[string][]byte{"z.rego": []byte("package z"), "a.rego": []byte("package a2"), "sub/data.json": []byte(`{"x":1}`)}
	assert.NotEqual(t, BundleTreeDigest(a), BundleTreeDigest(changed), "content matters")

	renamed := map[string][]byte{"z.rego": []byte("package z"), "b.rego": []byte("package a"), "sub/data.json": []byte(`{"x":1}`)}
	assert.NotEqual(t, BundleTreeDigest(a), BundleTreeDigest(renamed), "paths matter")

	empty := BundleTreeDigest(nil)
	// sha256 of the empty string.
	assert.Equal(t, "tree:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", empty)
}
