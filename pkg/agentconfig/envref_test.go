package agentconfig

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvRefs(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"plain", nil},
		{"${env:A}", []string{"A"}},
		{"x-${env:B}-${env:A}-${env:B}-${env:A}", []string{"B", "A"}},
		{"${env:lower_case1}", []string{"lower_case1"}},
		{"${env:_X}", []string{"_X"}},
		{"${env:1A}", nil},
		{"${env:}", nil},
		{"$env:A", nil},
		{"${ENV:A}", nil},
		{"${env:A-B}", nil},
		{"${env:A", nil},
		{"$${env:A}", []string{"A"}}, // no escaping syntax in v1
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, EnvRefs(tt.in), tt.in)
	}
}

func TestIsForbiddenEnvName(t *testing.T) {
	for _, n := range []string{"CCF_API_AUTH_CLIENT_SECRET", "CCF_API_AUTH_CLIENT_ID", "ccf_api_auth_client_secret", "Ccf_Api_Auth_X", "CCF_API_AUTH_"} {
		assert.True(t, IsForbiddenEnvName(n), n)
	}
	for _, n := range []string{"CCF_API_URL", "CCF_API_AUTH", "X_CCF_API_AUTH_Y", "HOME", ""} {
		assert.False(t, IsForbiddenEnvName(n), n)
	}
}

func envConfig() Config {
	return Config{
		Plugins: map[string]*Plugin{
			"p": {
				Source: "ghcr.io/x/${env:ORG}:v1",
				Config: map[string]string{
					"password": "${env:PW}",
					"dsn":      "user=${env:USER}&pw=${env:PW}&again=${env:USER}",
					"plain":    "no refs",
				},
				Labels:     map[string]string{"l": "${env:PW}"},
				PolicyData: map[string]any{"d": "${env:PW}"},
			},
			"nil": nil,
		},
	}
}

func TestResolveEnv(t *testing.T) {
	env := map[string]string{"PW": "hunter2", "USER": "root", "ORG": "acme"}
	lookup := func(n string) (string, bool) { v, ok := env[n]; return v, ok }

	in := envConfig()
	out, err := ResolveEnv(in, lookup)
	require.NoError(t, err)

	p := out.Plugins["p"]
	assert.Equal(t, "hunter2", p.Config["password"], "whole value")
	assert.Equal(t, "user=root&pw=hunter2&again=root", p.Config["dsn"], "embedded values")
	assert.Equal(t, "no refs", p.Config["plain"])
	assert.Equal(t, "ghcr.io/x/${env:ORG}:v1", p.Source, "only plugins.*.config is resolved")
	assert.Equal(t, "${env:PW}", p.Labels["l"])
	assert.Equal(t, "${env:PW}", p.PolicyData["d"])
	assert.Nil(t, out.Plugins["nil"])

	assert.Equal(t, envConfig(), in, "input not mutated")
}

func TestResolveEnvEmptyValue(t *testing.T) {
	c := Config{Plugins: map[string]*Plugin{"p": {Config: map[string]string{"k": "a${env:E}b"}}}}
	out, err := ResolveEnv(c, func(string) (string, bool) { return "", true })
	require.NoError(t, err)
	assert.Equal(t, "ab", out.Plugins["p"].Config["k"], "set but empty is not missing")
}

func TestResolveEnvErrors(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		c := envConfig()
		_, err := ResolveEnv(c, func(n string) (string, bool) { return "x", n != "USER" })
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrEnvMissing))
		assert.False(t, errors.Is(err, ErrEnvForbidden))
		assert.Contains(t, err.Error(), "USER")
		assert.Contains(t, err.Error(), "/plugins/p/config/dsn")
		assert.Equal(t, envConfig(), c, "input not mutated")
	})
	t.Run("forbidden", func(t *testing.T) {
		c := Config{Plugins: map[string]*Plugin{"p": {Config: map[string]string{"s": "${env:ccf_api_auth_client_secret}"}}}}
		called := false
		_, err := ResolveEnv(c, func(string) (string, bool) { called = true; return "leak", true })
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrEnvForbidden))
		assert.False(t, called, "a forbidden variable is never looked up")
		assert.Equal(t, "${env:ccf_api_auth_client_secret}", c.Plugins["p"].Config["s"])
	})
	t.Run("forbidden alongside a set variable", func(t *testing.T) {
		c := Config{Plugins: map[string]*Plugin{"p": {Config: map[string]string{"s": "${env:A}${env:CCF_API_AUTH_CLIENT_ID}"}}}}
		_, err := ResolveEnv(c, func(string) (string, bool) { return "x", true })
		assert.True(t, errors.Is(err, ErrEnvForbidden))
	})
}

func TestResolveEnvKeepsFreeFormNumbers(t *testing.T) {
	c := Config{Plugins: map[string]*Plugin{"p": {PolicyData: map[string]any{"n": json.Number("12345678901234567890")}}}}
	out, err := ResolveEnv(c, func(string) (string, bool) { return "", false })
	require.NoError(t, err)
	assert.Equal(t, json.Number("12345678901234567890"), out.Plugins["p"].PolicyData["n"])
}
