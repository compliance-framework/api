package agentconfig

import (
	"strconv"
)

// RedactOption configures Redact and Digest.
type RedactOption func(*redactOpts)

type redactOpts struct {
	masked map[string]bool
}

// WithMaskedPointers masks the values at these RFC 6901 pointers. The agent passes the
// plugin config values that came from viper env (CCF_PLUGINS_<P>_CONFIG_<K>) rather than from
// placeholders (R25, R44). Pass the SAME pointers to Redact and Digest (R55).
func WithMaskedPointers(ptrs ...string) RedactOption {
	return func(o *redactOpts) {
		if o.masked == nil {
			o.masked = map[string]bool{}
		}
		for _, p := range ptrs {
			o.masked[p] = true
		}
	}
}

// Redact returns a deep copy of c with api.auth.client_secret cleared and secret-like values
// replaced by MaskedValue. Apply it to the UNRESOLVED config (placeholders intact). It is
// idempotent, and Digest hashes its output, so both always apply the same rules (R55).
//
// A value is masked whole: the result is exactly MaskedValue, never a partially masked
// string, so a redacted view can never be resubmitted (ValidateOverlay rejects MaskedValue,
// O10). The rules, under plugins.*.config and plugins.*.policy_data (any depth):
//
// For a string value, let literal be the value with its ${env:NAME} placeholders removed.
//  1. A value whose literal is empty or only whitespace and the separators ":;,|/@=&"
//     (placeholder-only, e.g. "${env:PASS}" or "${env:USER}:${env:PASS}") is kept verbatim.
//  2. Else it is masked when it is at a pointer given to WithMaskedPointers, or its key is
//     secret-like (isSecretKey: e.g. password, passphrase, secret, token, credential,
//     api_key, private_key, dsn, connection_string, auth, cookie, session_id; see
//     secretKeyStems and secretKeyWords). Under such a key, literal text mixed with a
//     placeholder ("lit${env:X}") is masked.
//  3. Else it is masked when its literal contains a secret by content, whatever the key
//     (containsSecretValue): a URL with a password in its userinfo (also inside a longer
//     string such as a DSN), a PEM private key, a password=... assignment, or a
//     high-confidence provider token (AWS access key ID, GitHub, GitLab, Slack, Google API
//     key, Stripe, JWT, SendGrid, npm, PyPI, OpenAI, Anthropic, Hugging Face,
//     DigitalOcean, Shopify, Terraform Cloud, Vault, Azure AD client secret, age).
//
// A non-string value (number, object, array) at a masked pointer or under a secret-like key
// is masked whole; booleans and null are never secret and are kept unless at a masked
// pointer. Strings nested in kept objects and arrays get the same rules, with the nearest
// enclosing object key as their key. api.url is masked when it contains a secret by content
// (rule 3). Map keys, labels, sources and policies are never masked.
func Redact(c Config, opts ...RedactOption) Config {
	var o redactOpts
	for _, opt := range opts {
		opt(&o)
	}
	out := c.clone()
	if out.API != nil {
		if out.API.Auth != nil {
			out.API.Auth.ClientSecret = ""
		}
		if containsSecretValue(out.API.URL) {
			out.API.URL = MaskedValue
		}
	}
	for pluginName, p := range out.Plugins {
		if p == nil {
			continue
		}
		for key, value := range p.Config {
			ptr := Pointer("plugins", pluginName, "config", key)
			if o.shouldMask(ptr, key, value) {
				p.Config[key] = MaskedValue
			}
		}
		if p.PolicyData != nil {
			p.PolicyData = o.redactMap(Pointer("plugins", pluginName, "policy_data"), p.PolicyData)
		}
	}
	return out
}

// shouldMask applies the mask rule (see Redact) to one string value.
func (o redactOpts) shouldMask(ptr, key, value string) bool {
	literal, hasRef := envLiteral(value)
	if hasRef && isPlaceholderOnly(literal) {
		return false
	}
	if o.masked[ptr] || isSecretKey(key) {
		return true
	}
	return containsSecretValue(literal)
}

// redactMap redacts the entries of a free-form object.
func (o redactOpts) redactMap(ptr string, m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, val := range m {
		out[k] = o.redactTree(appendPointer(ptr, k), k, val)
	}
	return out
}

// redactTree returns a redacted copy of a free-form value. key is the nearest enclosing map
// key.
func (o redactOpts) redactTree(ptr, key string, v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if o.shouldMask(ptr, key, t) {
			return MaskedValue
		}
		return t
	case bool:
		if o.masked[ptr] {
			return MaskedValue
		}
		return t
	}
	// Any other value at a masked pointer or under a secret-like key is masked whole.
	if o.masked[ptr] || (key != "" && isSecretKey(key)) {
		return MaskedValue
	}
	switch t := v.(type) {
	case map[string]any:
		return o.redactMap(ptr, t)
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = o.redactTree(appendPointer(ptr, strconv.Itoa(i)), key, val)
		}
		return out
	default:
		return t
	}
}
