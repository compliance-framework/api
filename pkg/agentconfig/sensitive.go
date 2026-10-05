package agentconfig

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// Secret detection for Redact, Digest and RedactDocument. Two independent checks decide
// whether a value is secret-like: its key name (isSecretKey) and its content
// (containsSecretValue). Both are deliberately free of entropy heuristics, since
// policy_data legitimately holds hashes and IDs.

// secretKeyStems mark a key as secret wherever they occur in it. They are matched against
// the key lowercased with every non-alphanumeric character removed, so "db_password",
// "dbPassword", "dbpassword" (viper lowercases keys) and "API-Key" all match. Matching
// anywhere is deliberate: a false positive only hides a value from reports and digests; a
// miss leaks a secret. Keys that only describe a secret (nonSecretKeyLastWords,
// nonSecretKeyFirstWords) are exempt, so "max_tokens", "tokens_per_minute", "secret_name",
// "token_url" and "password_file" are not masked by key; their values still get the
// content check (containsSecretValue).
var secretKeyStems = []string{
	"password", "passwd", "passphrase",
	"secret", "token", "credential",
	"apikey", "privatekey", "accesskey",
	"connectionstring", "connstring", "connstr",
	"sessionid", "authorization", "authheader",
}

// secretKeyWords mark a key as secret when they are its last word, or the suffix of its
// last word ("sshkey", "dbpass", "basicauth", "sentrydsn" as viper lowercases them), after
// dropping trailing format words (secretKeyFormatWords). Words are split at
// non-alphanumeric characters and camelCase boundaries. So "api_key", "client_key",
// "private_key_pem", "db_pass", "auth", "oauth" and "session_cookie" match, while
// "keyword", "key_id", "key_file", "pass_rate", "auth_method" and "cookie_secure" do not.
var secretKeyWords = []string{"key", "keys", "pass", "pwd", "auth", "dsn", "cookie", "cookies"}

// secretKeyFormatWords are trailing words that name an encoding of the value rather than
// what it is: "signing_key_b64" is a key.
var secretKeyFormatWords = []string{"b64", "base64", "hex", "pem", "der", "raw", "data", "value", "json", "string", "str"}

// secretKeyWordExceptions are ordinary words that end in a secretKeyWords entry.
var secretKeyWordExceptions = []string{
	"monkey", "monkeys", "donkey", "donkeys", "turkey", "turkeys", "hockey", "jockey",
	"jockeys", "whiskey", "lackey", "turnkey", "hotkey", "hotkeys",
	"bypass", "compass", "encompass", "surpass", "overpass", "underpass", "trespass",
}

// nonSecretKeyLastWords end a key that describes a secret rather than holds one: its name,
// location, identifier, size or switch ("secret_name", "token_url", "password_file",
// "api_key_id", "token_ttl", "auth_enabled").
var nonSecretKeyLastWords = []string{
	"name", "url", "uri", "file", "path", "dir", "id", "count", "limit", "ttl", "size",
	"length", "enabled",
}

// nonSecretKeyFirstWords start a key that bounds a quantity ("max_tokens", "min_key_size").
var nonSecretKeyFirstWords = []string{"max", "min"}

// isNonSecretKeyName reports whether a key (split by keyWords) describes a secret rather
// than holds one: it starts with max/min or "tokens_per", or its last word is in
// nonSecretKeyLastWords. A key whose secret stem needs that last word still names a secret
// ("session_id" is the stem "sessionid").
func isNonSecretKeyName(words []string) bool {
	if len(words) < 2 {
		return false
	}
	if slices.Contains(nonSecretKeyFirstWords, words[0]) || (words[0] == "tokens" && words[1] == "per") {
		return true
	}
	if !slices.Contains(nonSecretKeyLastWords, words[len(words)-1]) {
		return false
	}
	joined := strings.Join(words, "")
	prefix := strings.Join(words[:len(words)-1], "")
	for _, stem := range secretKeyStems {
		if strings.Contains(joined, stem) && !strings.Contains(prefix, stem) {
			return false
		}
	}
	return true
}

// isSecretKey reports whether a config or policy_data key names a secret. Keys that name
// public or non-secret material, such as "cert", "certificate", "signature" or "session",
// do not match; private key material is caught by its content (containsSecretValue).
func isSecretKey(key string) bool {
	words := keyWords(key)
	if len(words) == 0 || isNonSecretKeyName(words) {
		return false
	}
	joined := strings.Join(words, "")
	for _, stem := range secretKeyStems {
		if strings.Contains(joined, stem) {
			return true
		}
	}
	for len(words) > 1 && slices.Contains(secretKeyFormatWords, words[len(words)-1]) {
		words = words[:len(words)-1]
	}
	last := words[len(words)-1]
	if slices.Contains(secretKeyWordExceptions, last) {
		return false
	}
	for _, w := range secretKeyWords {
		if strings.HasSuffix(last, w) {
			return true
		}
	}
	return false
}

// keyWords splits a key into lowercase words at non-alphanumeric characters and camelCase
// boundaries ("APIKey" -> "api", "key"; "authHeader" -> "auth", "header").
func keyWords(key string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	runes := []rune(key)
	for i, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if unicode.IsUpper(r) && len(cur) > 0 {
			prev := cur[len(cur)-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return words
}

// secretValuePattern is a high-confidence secret format.
type secretValuePattern struct {
	name string
	re   *regexp.Regexp
}

// secretValuePatterns are formats that identify a secret by content alone. The provider
// token formats are adapted from gitleaks' default rules
// (https://github.com/gitleaks/gitleaks, config/gitleaks.toml; MIT License, Copyright (c)
// 2019 Zachary Rice). Only formats with a distinctive prefix or structure are included.
var secretValuePatterns = []secretValuePattern{
	{"private-key", regexp.MustCompile(`-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----`)},
	{"password-assignment", regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])(?:password|passwd|pwd)\s*=\s*[^\s;&,'"]`)},
	{"aws-access-key-id", regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b`)},
	{"github-token", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36}\b`)},
	{"github-fine-grained-pat", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{82}\b`)},
	{"gitlab-token", regexp.MustCompile(`\bglpat-[0-9A-Za-z_-]{20,}`)},
	{"slack-token", regexp.MustCompile(`\bxox[abeoprs]-[0-9]+-[0-9A-Za-z-]{8,}`)},
	{"slack-app-token", regexp.MustCompile(`(?i)\bxapp-[0-9]+-[A-Z0-9]+-[0-9]+-[a-z0-9]+`)},
	{"slack-webhook-url", regexp.MustCompile(`hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}`)},
	{"google-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}(?:[^0-9A-Za-z_-]|$)`)},
	{"stripe-key", regexp.MustCompile(`\b(?:sk|rk)_(?:live|test|prod)_[0-9A-Za-z]{10,99}\b`)},
	{"jwt", regexp.MustCompile(`\bey[A-Za-z0-9_-]{17,}\.ey[A-Za-z0-9_/\\-]{17,}\.`)},
	{"sendgrid-api-key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`)},
	{"npm-token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"pypi-token", regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}`)},
	{"openai-api-key", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}`)},
	{"anthropic-api-key", regexp.MustCompile(`\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{80,}`)},
	{"huggingface-token", regexp.MustCompile(`\bhf_[A-Za-z]{34}\b`)},
	{"digitalocean-token", regexp.MustCompile(`\bdo[opr]_v1_[a-f0-9]{64}\b`)},
	{"shopify-token", regexp.MustCompile(`\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b`)},
	{"terraform-cloud-token", regexp.MustCompile(`\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70}`)},
	{"vault-token", regexp.MustCompile(`\bhv[sb]\.[A-Za-z0-9_-]{90,}`)},
	{"azure-ad-client-secret", regexp.MustCompile(`(?:^|[\\'"\x60\s>=:(,)])[A-Za-z0-9_~.]{3}[0-9]Q~[A-Za-z0-9_~.-]{31,34}(?:$|[\\'"\x60\s<),])`)},
	{"age-secret-key", regexp.MustCompile(`AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`)},
	// Go MySQL driver DSN without a scheme: user:password@tcp(host:port)/db.
	{"mysql-dsn", regexp.MustCompile(`[^\s:@/]*:[^\s@]+@(?:tcp[46]?|udp[46]?|unix)\(`)},
}

// urlSchemePattern finds the start of each URL in a string.
var urlSchemePattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://`)

// urlUserinfoPattern recognizes "scheme://user:password@" in a URL net/url cannot parse
// (an unescaped '/', '#', '?' or '@' in the password is common in hand-written DSNs) or
// parses as host:port (a password starting with digits then '/'). A password ending in '/'
// is not matched, so "https://host:443/users/@me" (a path) is not taken for userinfo.
var urlUserinfoPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*://[^\s/@:]*:[^\s@]*[^\s@/]@`)

// Bounds on the URL password scan (hasURLPassword), so its cost is linear in the input.
const (
	// maxURLScanBytes is the prefix of a value scanned for URLs with a password. The token
	// patterns (RE2, linear) still run on the whole value.
	maxURLScanBytes = 64 << 10
	// maxURLCandidates caps the URLs inspected in one value.
	maxURLCandidates = 64
	// maxURLCandidateBytes caps the length of one URL candidate.
	maxURLCandidateBytes = 2048
)

// ScrubSecretText returns MaskedValue and true when s contains a secret by content (the
// rule Redact applies whatever the key: a URL with a password, a DSN, a PEM private key, a
// password=... assignment or a provider token), else s and false. It masks the whole string.
// Use it on free text such as error messages and plugin sources.
func ScrubSecretText(s string) (string, bool) {
	if containsSecretValue(s) {
		return MaskedValue, true
	}
	return s, false
}

// containsSecretValue reports whether s holds a secret whatever its key: a URL with a
// non-empty password in its userinfo (anywhere in s, so DSNs and command lines count), a
// PEM private key, a password=... assignment, or a high-confidence provider token
// (secretValuePatterns).
func containsSecretValue(s string) bool {
	if s == "" || s == MaskedValue {
		return false
	}
	if hasURLPassword(s) {
		return true
	}
	for _, p := range secretValuePatterns {
		if p.re.MatchString(s) {
			return true
		}
	}
	return false
}

// hasURLPassword reports whether any URL in s carries a non-empty password. Only the first
// maxURLScanBytes of s and its first maxURLCandidates URLs are inspected, and each candidate
// ends at the next URL, so the work is linear in len(s).
func hasURLPassword(s string) bool {
	if len(s) > maxURLScanBytes {
		s = s[:maxURLScanBytes]
	}
	locs := urlSchemePattern.FindAllStringIndex(s, maxURLCandidates)
	for i, loc := range locs {
		end := len(s)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		end = min(end, loc[0]+maxURLCandidateBytes)
		candidate := s[loc[0]:end]
		if t := strings.IndexFunc(candidate, isURLTerminator); t >= 0 {
			candidate = candidate[:t]
		}
		if u, err := url.Parse(candidate); err == nil && u.User != nil {
			if password, ok := u.User.Password(); ok && password != "" {
				return true
			}
		}
		// Also when net/url parses the candidate without a password: it reads
		// "https://user:5678/abc@host" as host "user" and port 5678. An image digest after
		// the '@' ("oci://registry:5000/plugin@sha256:...") is a reference, not userinfo.
		if m := urlUserinfoPattern.FindStringIndex(candidate); m != nil && !isDigestReference(candidate[m[1]:]) {
			return true
		}
	}
	return false
}

// isDigestReference reports whether s starts with a content digest ("sha256:...").
func isDigestReference(s string) bool {
	return strings.HasPrefix(s, "sha256:") || strings.HasPrefix(s, "sha384:") || strings.HasPrefix(s, "sha512:")
}

func isURLTerminator(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune("\"'`<>", r)
}

// placeholderSeparators may join placeholders in a value that is still placeholder-only,
// e.g. "${env:USER}:${env:PASS}" or "${env:A}, ${env:B}".
const placeholderSeparators = ":;,|/@=&"

// envLiteral returns s with every ${env:NAME} placeholder removed, and whether s had any.
func envLiteral(s string) (literal string, hasRef bool) {
	if !strings.Contains(s, "${env:") {
		return s, false
	}
	literal = EnvRefPattern.ReplaceAllString(s, "")
	return literal, literal != s
}

// isPlaceholderOnly reports whether the literal part of a value (envLiteral) carries no
// content: only whitespace and placeholderSeparators.
func isPlaceholderOnly(literal string) bool {
	return strings.IndexFunc(literal, func(r rune) bool {
		return !unicode.IsSpace(r) && !strings.ContainsRune(placeholderSeparators, r)
	}) < 0
}
