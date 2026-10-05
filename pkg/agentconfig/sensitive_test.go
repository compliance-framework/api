package agentconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fake token fixtures are assembled at run time so the literal source never looks like a
// live credential to secret scanners.
func fake(parts ...string) string { return strings.Join(parts, "") }

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestIsSecretKey(t *testing.T) {
	secret := []string{
		// stems, anywhere in the key
		"password", "db_password", "dbPassword", "dbpassword", "DB-PASSWORD", "passwd",
		"passphrase", "ssh_key_passphrase", "secret", "client_secret", "clientsecret",
		"token", "access_token", "accessToken", "tokens", "credentials", "credentials_json",
		"api_key", "apiKey", "APIKey", "apikey", "x-api-key", "private_key", "privateKey",
		"access_key", "aws_secret_access_key", "connection_string",
		"connectionString", "conn_str", "connstr", "session_id", "sessionid", "SessionID",
		"authorization", "Authorization", "auth_header", "AuthHeader", "authheader",
		// last-word matches
		"key", "keys", "client_key", "tls.key", "ssh-key", "sshkey", "signing_key_b64",
		"encryption_key_hex", "private_key_pem", "passkey", "pass", "db_pass", "dbpass",
		"pwd", "db_pwd", "auth", "basic_auth", "basicauth", "oauth", "proxyAuth", "dsn",
		"sentry_dsn", "sentrydsn", "cookie", "cookies", "session_cookie", "setCookie",
		// a stem that needs the last word still names a secret
		"session_id", "sessionId",
	}
	for _, k := range secret {
		assert.True(t, isSecretKey(k), "%q should be secret-like", k)
	}
	notSecret := []string{
		"", "host", "user", "username", "port", "keyword", "keywords", "monkey", "monkeys",
		"turkey", "hockey", "whiskey", "hotkey", "turnkey", "bypass", "compass",
		"key_id", "kms_key_id", "key_file", "keyspace", "keyboard", "pass_rate",
		"min_pass_percentage", "passthrough", "author", "authority", "authentication_method",
		"auth_method", "authz_mode", "cookie_secure", "cookie_name", "dsn_timeout",
		"session", "session_timeout", "cert", "certificate", "client_cert", "ca_cert",
		"signature", "sig", "threshold", "keyed", "monkey_patch",
		// keys that describe a secret rather than hold one (the value is still content-checked)
		"tokens_per_minute", "max_tokens", "maxTokens", "min_key_size", "secret_name",
		"password_file", "private_key_path", "token_url", "auth_uri", "secrets_dir",
		"api_key_id", "token_count", "token_limit", "token_ttl", "secret_size",
		"password_length", "auth_enabled",
	}
	for _, k := range notSecret {
		assert.False(t, isSecretKey(k), "%q should not be secret-like", k)
	}
}

func TestKeyWords(t *testing.T) {
	tests := map[string][]string{
		"api_key":         {"api", "key"},
		"APIKey":          {"api", "key"},
		"apiKeyID":        {"api", "key", "id"},
		"authHeader":      {"auth", "header"},
		"x-api-key":       {"x", "api", "key"},
		"tls.key":         {"tls", "key"},
		"OAuth2Token":     {"o", "auth2", "token"},
		"key2":            {"key2"},
		"HTTPServerURL":   {"http", "server", "url"},
		"__":              nil,
		"snake_CASE_key":  {"snake", "case", "key"},
		"päss wörd":       {"päss", "wörd"},
		"aws_access_key1": {"aws", "access", "key1"},
	}
	for in, want := range tests {
		assert.Equal(t, want, keyWords(in), in)
	}
}

func TestContainsSecretValue(t *testing.T) {
	alnum36 := strings.Repeat("a1B2", 9)
	positives := map[string]string{
		"url password":                         "postgres://user:hunter2@db.example.com:5432/app",
		"url empty user":                       "redis://:hunter2@cache:6379/0",
		"url in a longer string":               "--dsn=postgres://user:hunter2@db/app --verbose",
		"url in a jdbc dsn":                    "jdbc:postgresql://user:hunter2@db/app",
		"url unparseable password":             "postgres://user:pa/ss#w?rd@db/app",
		"url password with at":                 "mongodb://user:p@ss@db/app",
		"url escaped password":                 "amqp://user:p%40ss@mq/vhost",
		"second url has a password":            "https://example.com/a https://u:p@example.org",
		"pem private key":                      "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----",
		"pem rsa private key":                  "-----BEGIN RSA PRIVATE KEY-----",
		"pem openssh private key":              "x -----BEGIN OPENSSH PRIVATE KEY----- y",
		"pem pgp private key block":            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
		"libpq password":                       "host=db user=app password=hunter2 sslmode=require",
		"odbc pwd":                             "Server=db;Uid=app;Pwd=hunter2;",
		"jdbc query password":                  "jdbc:mysql://db/app?user=app&password=hunter2",
		"aws access key id":                    fake("AKIA", "IOSFODNN7EXAMPLE"),
		"aws session key id":                   fake("ASIA", "IOSFODNN7EXAMPLE"),
		"github pat":                           fake("gh", "p_", alnum36),
		"github oauth":                         fake("gh", "o_", alnum36),
		"github user-to-server":                fake("gh", "u_", alnum36),
		"github server-to-server":              fake("gh", "s_", alnum36),
		"github refresh":                       fake("gh", "r_", alnum36),
		"github fine-grained pat":              fake("github", "_pat_", strings.Repeat("a1B2_", 16), "ab"),
		"gitlab pat":                           fake("gl", "pat-", strings.Repeat("aB3-", 5)),
		"slack bot token":                      fake("xo", "xb-", "1234567890-1234567890-", strings.Repeat("aB3", 8)),
		"slack user token":                     fake("xo", "xp-", "1234567890-1234567890-1234567890-", strings.Repeat("ab12", 8)),
		"slack app token":                      fake("xa", "pp-1-A0123BCDEF-1234567890-", strings.Repeat("ab12", 16)),
		"slack webhook":                        fake("https://hooks.", "slack.com/services/", strings.Repeat("A1b2", 11)),
		"google api key":                       fake("AI", "za", strings.Repeat("Sy0_-", 7)),
		"stripe live key":                      fake("sk", "_live_", strings.Repeat("a1B2", 6)),
		"stripe restricted key":                fake("rk", "_live_", strings.Repeat("a1B2", 6)),
		"stripe test key":                      fake("sk", "_test_", strings.Repeat("a1B2", 6)),
		"jwt":                                  fake("ey", "JhbGciOiJIUzI1NiJ9", ".", "ey", "JzdWIiOiIxMjM0NTY3ODkwIn0", ".", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
		"jwt in a header":                      fake("Bearer ey", "JhbGciOiJIUzI1NiJ9", ".", "ey", "JzdWIiOiIxMjM0NTY3ODkwIn0", "."),
		"sendgrid":                             fake("SG", ".", strings.Repeat("a", 22), ".", strings.Repeat("b", 43)),
		"npm":                                  fake("np", "m_", alnum36),
		"pypi":                                 fake("pypi-", "AgEIcHlwaS5vcmc", strings.Repeat("ab_-", 13)),
		"openai":                               fake("sk-proj-", strings.Repeat("a", 24), "T3Blbk", "FJ", strings.Repeat("b", 24)),
		"anthropic":                            fake("sk-", "ant-api03-", strings.Repeat("aB3_", 22)),
		"huggingface":                          fake("hf", "_", strings.Repeat("abcd", 8), "ab"),
		"digitalocean":                         fake("do", "p_v1_", strings.Repeat("0a", 32)),
		"shopify":                              fake("shp", "at_", strings.Repeat("0a", 16)),
		"terraform cloud":                      fake(strings.Repeat("a", 14), ".atlas", "v1.", strings.Repeat("ab", 32)),
		"vault":                                fake("hv", "s.", strings.Repeat("aB3_", 25)),
		"azure ad client secret":               fake("abc", "8Q~", strings.Repeat("aB3.", 8), "xy"),
		"age secret key":                       fake("AGE-SECRET", "-KEY-1", strings.Repeat("QPZRY9X8GF", 5), "2TVDW0S3"),
		"token inside a longer value":          fake("token for ci: gh", "p_", alnum36, " (rotate monthly)"),
		"url digits password parsed as a port": "https://user:5678/abc@host",
		"mysql dsn without a scheme":           "user:hunter2@tcp(db:3306)/app",
		"mysql dsn unix socket":                "app:hunter2@unix(/var/run/mysqld.sock)/app",
	}
	for name, v := range positives {
		assert.True(t, containsSecretValue(v), "%s: %q", name, v)
	}

	negatives := map[string]string{
		"empty":                    "",
		"masked":                   MaskedValue,
		"plain":                    "localhost",
		"url without userinfo":     "https://api.example.com:8443/v1?x=1",
		"url user only":            "ssh://git@github.com/org/repo.git",
		"url empty password":       "redis://user:@cache:6379",
		"url port then at in path": "https://example.com:443/users/@me",
		"scp-like git":             "git@github.com:org/repo.git",
		"mailto":                   "mailto:someone@example.com",
		"sha256 hash":              strings.Repeat("0123456789abcdef", 4),
		"uuid":                     "0b3c1b8a-7c8e-4d53-9a52-9a3c1d1f2e10",
		"image digest":             "sha256:" + strings.Repeat("ab", 32),
		"base64 blob":              "SGVsbG8sIFdvcmxkIQ==",
		"password word":            "the password must be rotated",
		"password key empty":       "password=",
		"password placeholder gap": "password=;host=db",
		"public cert":              "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
		"public key":               "-----BEGIN PUBLIC KEY-----",
		"short ghp prefix":         "ghp_short",
		"akia too short":           "AKIA123",
		"one dot ey":               "eyJhbGciOiJIUzI1NiJ9.notjwt",
		"oci ref":                  "ghcr.io/compliance-framework/plugin-local-ssh:v1.2.3",
		"cron":                     "*/5 * * * *",
		"keyword like value":       "monkey",
		"oci digest with a port":   "oci://registry.local:5000/plugins/ssh@sha256:" + strings.Repeat("ab", 32),
		"mysql dsn no password":    "user@tcp(db:3306)/app",
		"mysql dsn empty password": "user:@tcp(db:3306)/app",
	}
	for name, v := range negatives {
		assert.False(t, containsSecretValue(v), "%s: %q", name, v)
	}
}

// The URL scan is linear: a long value of back-to-back schemes with no terminator used to
// re-parse the rest of the string for every match.
func TestContainsSecretValueLinear(t *testing.T) {
	adversarial := strings.Repeat("a://", (1<<20)/4)
	start := time.Now()
	assert.False(t, containsSecretValue(adversarial))
	assert.Less(t, time.Since(start), 2*time.Second)

	// A real URL password within the scanned prefix is still detected.
	assert.True(t, containsSecretValue(strings.Repeat("a://", 50)+" https://u:pw@h/x"))
	assert.True(t, containsSecretValue(strings.Repeat("x", 1000)+"https://u:pw@h/x"))
}

func TestScrubSecretText(t *testing.T) {
	got, scrubbed := ScrubSecretText("dial postgres://app:hunter2@db:5432/app: connection refused")
	assert.True(t, scrubbed)
	assert.Equal(t, MaskedValue, got)

	got, scrubbed = ScrubSecretText("dial tcp db:5432: connection refused")
	assert.False(t, scrubbed)
	assert.Equal(t, "dial tcp db:5432: connection refused", got)

	got, scrubbed = ScrubSecretText(MaskedValue)
	assert.False(t, scrubbed)
	assert.Equal(t, MaskedValue, got)
}

func TestRedactSourcesAndPolicies(t *testing.T) {
	c := Config{Plugins: map[string]*Plugin{"p": {
		Source:   "https://u:pw@plugins.example.com/ssh.tar.gz",
		Policies: []string{srcPolicies, "https://ci:hunter2@policies.example.com/p.tar.gz"},
	}, "q": {
		Source:   srcSSH,
		Policies: []string{srcCommon},
		Labels:   map[string]string{"token": "x"},
	}}}
	out := Redact(c)
	assert.Equal(t, MaskedValue, out.Plugins["p"].Source)
	assert.Equal(t, []string{srcPolicies, MaskedValue}, out.Plugins["p"].Policies)
	assert.Equal(t, srcSSH, out.Plugins["q"].Source, "no key rule on sources")
	assert.Equal(t, []string{srcCommon}, out.Plugins["q"].Policies)
	assert.Equal(t, "x", out.Plugins["q"].Labels["token"], "labels are never masked")
	assert.Equal(t, "https://u:pw@plugins.example.com/ssh.tar.gz", c.Plugins["p"].Source, "input not mutated")

	raw, err := json.Marshal(c)
	require.NoError(t, err)
	doc, changed, err := RedactDocument(raw)
	require.NoError(t, err)
	assert.True(t, changed)
	want, err := CanonicalJSON(Redact(c))
	require.NoError(t, err)
	assert.JSONEq(t, string(want), string(doc), "RedactDocument applies the same rules")
}

func TestRedactValueAndPlaceholderRules(t *testing.T) {
	ghp := fake("gh", "p_", strings.Repeat("a1B2", 9))
	c := Config{
		API: &APIConfig{URL: "https://agent:hunter2@api.example.com", Auth: &APIAuth{ClientID: "id", ClientSecret: "s"}},
		Plugins: map[string]*Plugin{"p": {
			Source: srcSSH,
			Config: map[string]string{
				// content rules, whatever the key
				"url":           "postgres://user:hunter2@db/app",
				"url_user_only": "postgres://user@db/app",
				"args":          "--token-file /x " + ghp,
				"ca":            "-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----",
				"conn":          "host=db password=hunter2",
				"host":          "localhost",
				// placeholder rules
				"only_ref":          "${env:PG_PASS}",
				"refs_and_seps":     "${env:USER}:${env:PASS}",
				"refs_ws":           " ${env:A} , ${env:B} ",
				"password":          "lit${env:X}",
				"api_key":           "${env:A}${env:B}x",
				"url_with_ref":      "postgres://user:${env:PG_PASS}@db/app",
				"url_mixed_ref":     "postgres://user:lit${env:PG_PASS}@db/app",
				"ref_and_token":     "${env:A} " + ghp,
				"plain_ref_literal": "prefix-${env:REGION}-suffix",
			},
			PolicyData: map[string]any{
				"enabled":     true,
				"pass":        false,
				"key":         nil,
				"pass_rate":   json.Number("0.9"),
				"signing_key": json.Number("1234"),
				"allowed":     []any{"ok", "postgres://u:p@h/db", map[string]any{"note": ghp, "id": "x"}},
				"nested":      map[string]any{"connection_string": "Server=x", "public": "y"},
				"credentials": true,
			},
		}},
	}
	out := Redact(c)

	assert.Equal(t, MaskedValue, out.API.URL, "api.url with a password is masked whole")
	assert.Empty(t, out.API.Auth.ClientSecret)

	cfg := out.Plugins["p"].Config
	want := map[string]string{
		"url":               MaskedValue,
		"url_user_only":     "postgres://user@db/app",
		"args":              MaskedValue,
		"ca":                MaskedValue,
		"conn":              MaskedValue,
		"host":              "localhost",
		"only_ref":          "${env:PG_PASS}",
		"refs_and_seps":     "${env:USER}:${env:PASS}",
		"refs_ws":           " ${env:A} , ${env:B} ",
		"password":          MaskedValue,
		"api_key":           MaskedValue,
		"url_with_ref":      "postgres://user:${env:PG_PASS}@db/app",
		"url_mixed_ref":     MaskedValue,
		"ref_and_token":     MaskedValue,
		"plain_ref_literal": "prefix-${env:REGION}-suffix",
	}
	assert.Equal(t, want, cfg)
	for k, v := range cfg {
		assert.True(t, v == MaskedValue || !strings.Contains(v, MaskedValue), "%s: masked whole, never partially", k)
	}

	pd := out.Plugins["p"].PolicyData
	assert.Equal(t, true, pd["enabled"])
	assert.Equal(t, false, pd["pass"], "booleans are never secret")
	assert.Equal(t, true, pd["credentials"], "booleans are never secret")
	assert.Nil(t, pd["key"])
	assert.Equal(t, json.Number("0.9"), pd["pass_rate"], "pass is only secret as the last word")
	assert.Equal(t, MaskedValue, pd["signing_key"], "number under a secret-like key")
	assert.Equal(t, []any{"ok", MaskedValue, map[string]any{"note": MaskedValue, "id": "x"}}, pd["allowed"])
	assert.Equal(t, map[string]any{"connection_string": MaskedValue, "public": "y"}, pd["nested"])

	t.Run("masked pointer masks a boolean", func(t *testing.T) {
		got := Redact(c, WithMaskedPointers("/plugins/p/policy_data/enabled"))
		assert.Equal(t, MaskedValue, got.Plugins["p"].PolicyData["enabled"])
	})
	t.Run("masked pointer masks mixed placeholder values", func(t *testing.T) {
		got := Redact(c, WithMaskedPointers("/plugins/p/config/plain_ref_literal", "/plugins/p/config/only_ref"))
		assert.Equal(t, MaskedValue, got.Plugins["p"].Config["plain_ref_literal"])
		assert.Equal(t, "${env:PG_PASS}", got.Plugins["p"].Config["only_ref"], "placeholder-only wins")
	})
	t.Run("idempotent", func(t *testing.T) {
		assert.Equal(t, out, Redact(out))
		assert.Equal(t, Digest(c), Digest(out))
	})
	t.Run("input not mutated", func(t *testing.T) {
		assert.Equal(t, "https://agent:hunter2@api.example.com", c.API.URL)
		assert.Equal(t, "postgres://user:hunter2@db/app", c.Plugins["p"].Config["url"])
	})
}

func TestRedactDocumentParity(t *testing.T) {
	ghp := fake("gh", "p_", strings.Repeat("a1B2", 9))
	c := redactBase()
	c.API.URL = "https://agent:hunter2@api.example.com"
	p := c.Plugins["local-ssh"]
	p.Config["url"] = "postgres://user:hunter2@db/app"
	p.Config["mixed"] = "lit${env:X}"
	p.Config["password_mixed"] = "lit${env:X}"
	p.Config["refs"] = "${env:A}:${env:B}"
	p.PolicyData["list"] = []any{ghp, "plain", true}
	p.PolicyData["flag"] = true

	raw, err := json.Marshal(c)
	require.NoError(t, err)
	doc, changed, err := RedactDocument(raw)
	require.NoError(t, err)
	assert.True(t, changed)

	want, err := CanonicalJSON(Redact(c))
	require.NoError(t, err)
	// Redact keeps an empty client_secret field that RedactDocument deletes; compare the rest.
	var gotObj, wantObj map[string]any
	require.NoError(t, json.Unmarshal(doc, &gotObj))
	require.NoError(t, json.Unmarshal(want, &wantObj))
	assert.Equal(t, wantObj["plugins"], gotObj["plugins"], "same rules on the raw document")
	assert.Equal(t, MaskedValue, gotObj["api"].(map[string]any)["url"])
	assert.NotContains(t, gotObj["api"].(map[string]any)["auth"], "client_secret")

	again, changed, err := RedactDocument(doc)
	require.NoError(t, err)
	assert.False(t, changed, "no-op on a redacted document")
	assert.JSONEq(t, string(doc), string(again))

	agentRedacted, err := json.Marshal(Redact(c))
	require.NoError(t, err)
	_, changed, err = RedactDocument(agentRedacted)
	require.NoError(t, err)
	assert.False(t, changed, "no-op on a document Redact produced")
}

func TestDigestStableForNonSecretConfig(t *testing.T) {
	c := Config{Plugins: map[string]*Plugin{"p": {
		Source:     srcSSH,
		Config:     map[string]string{"host": "localhost", "port": "22", "user": "root", "region": "${env:REGION}"},
		PolicyData: map[string]any{"threshold": json.Number("5"), "enabled": true, "ids": []any{"a", "b"}},
	}}}
	// Nothing in c is secret-like, so redaction leaves it as is and the digest is that of
	// the config itself.
	assert.Equal(t, c.clone(), Redact(c))
	raw, err := CanonicalJSON(c)
	require.NoError(t, err)
	assert.Equal(t, DigestPrefix+sha256Hex(raw), Digest(c))
}
