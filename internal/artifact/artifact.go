// Package artifact defines the content-addressed forms of what a policy evaluation depends
// on: the policy bundle, the input data and the policy data. Agents upload these as they
// have them; the API converts them to the canonical forms here and hashes the result, so
// equal content always has one digest. Stored digests must stay reproducible, so the forms
// are permanent. Golden tests pin them.
package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/bundle"
)

const (
	// MediaTypePolicyBundle is a policy bundle. Uploads may be a tar or a gzipped tar; the
	// stored form is always the canonical tar CanonicalBundle writes.
	MediaTypePolicyBundle = "application/vnd.ccf.policy-bundle.v1+tar"
	// MediaTypeJSON is JSON. Uploads may be formatted in any way; the stored form is always
	// the canonical JSON CanonicalJSON writes.
	MediaTypeJSON = "application/json"

	digestPrefix = "sha256:"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ErrInvalid wraps every reason content cannot be made canonical.
var ErrInvalid = errors.New("invalid artifact content")

// Digest returns the content address of b: "sha256:" and 64 lowercase hex characters.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return digestPrefix + hex.EncodeToString(sum[:])
}

// ValidDigest reports whether s is a well-formed digest.
func ValidDigest(s string) bool {
	return digestPattern.MatchString(s)
}

// Canonical converts uploaded content of mediaType to its canonical form. maxBytes bounds
// the canonical size, which also bounds how far a compressed bundle may expand.
func Canonical(mediaType string, content []byte, maxBytes int64) ([]byte, error) {
	var (
		canonical []byte
		err       error
	)
	switch mediaType {
	case MediaTypeJSON:
		canonical, err = CanonicalJSON(json.RawMessage(content))
	case MediaTypePolicyBundle:
		canonical, err = CanonicalBundle(content, maxBytes)
	default:
		return nil, fmt.Errorf("%w: unsupported media type %q, want %q or %q", ErrInvalid, mediaType, MediaTypeJSON, MediaTypePolicyBundle)
	}
	if err != nil {
		return nil, err
	}
	if int64(len(canonical)) > maxBytes {
		return nil, fmt.Errorf("%w: canonical form is %d bytes, over the %d byte limit", ErrInvalid, len(canonical), maxBytes)
	}
	return canonical, nil
}

// CanonicalJSON encodes v so that equal JSON values always give equal bytes: object keys
// sorted, no insignificant whitespace, no HTML escaping, and numbers kept exactly as they
// were written rather than rounded through float64. The playback endpoint decodes input the
// same way, so a policy replayed from these bytes sees the values the agent evaluated.
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := encodeJSON(v)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, fmt.Errorf("%w: json: %v", ErrInvalid, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: json: trailing data after value", ErrInvalid)
	}
	return encodeJSON(generic)
}

func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, fmt.Errorf("%w: json: %v", ErrInvalid, err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// CanonicalBundle rewrites a policy bundle archive, a tar or a gzipped tar, as an
// uncompressed tar with every variable removed: regular files only, sorted by slash-separated
// path, mode 0644, owner 0/0, zero modification time. Directory entries are dropped. Links,
// devices, absolute or escaping paths and duplicate paths are rejected, and the files may
// total at most maxBytes, however well they compress.
func CanonicalBundle(archive []byte, maxBytes int64) ([]byte, error) {
	var reader io.Reader = bytes.NewReader(archive)
	if bytes.HasPrefix(archive, []byte{0x1f, 0x8b}) {
		zr, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("%w: bundle: %v", ErrInvalid, err)
		}
		defer func() { _ = zr.Close() }()
		reader = zr
	}

	type entry struct {
		name    string
		content []byte
	}
	var (
		entries []entry
		seen    = map[string]bool{}
		total   int64
	)
	tr := tar.NewReader(reader)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: bundle: %v", ErrInvalid, err)
		}

		switch header.Typeflag {
		case tar.TypeDir, tar.TypeXGlobalHeader:
			continue
		case tar.TypeReg:
		default:
			return nil, fmt.Errorf("%w: bundle: %s is not a regular file", ErrInvalid, header.Name)
		}

		name, err := cleanBundlePath(header.Name)
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, fmt.Errorf("%w: bundle: %s appears more than once", ErrInvalid, name)
		}
		seen[name] = true

		content, err := io.ReadAll(io.LimitReader(tr, maxBytes-total+1))
		if err != nil {
			return nil, fmt.Errorf("%w: bundle: %v", ErrInvalid, err)
		}
		total += 512 + int64(len(content))
		if total > maxBytes {
			return nil, fmt.Errorf("%w: bundle files exceed %d bytes", ErrInvalid, maxBytes)
		}
		entries = append(entries, entry{name: name, content: content})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: bundle has no files", ErrInvalid)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     e.name,
			Mode:     0o644,
			Size:     int64(len(e.content)),
			ModTime:  time.Unix(0, 0).UTC(),
			Format:   tar.FormatPAX,
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.content); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}

	canonical := buf.Bytes()
	if _, err := ReadBundleTar(canonical); err != nil {
		return nil, err
	}
	return canonical, nil
}

// cleanBundlePath makes an archive path relative and slash-separated, and rejects paths that
// would leave the bundle.
func cleanBundlePath(name string) (string, error) {
	slashed := strings.ReplaceAll(name, "\\", "/")
	if slices.Contains(strings.Split(slashed, "/"), "..") {
		return "", fmt.Errorf("%w: bundle: path %q leaves the bundle", ErrInvalid, name)
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+slashed), "/")
	if cleaned == "" {
		return "", fmt.Errorf("%w: bundle: empty path", ErrInvalid)
	}
	return cleaned, nil
}

// Bundle is a policy bundle read back from its canonical tar.
type Bundle struct {
	// Modules maps each Rego file's path in the bundle to its source.
	Modules map[string]string
	// Data is the bundle's merged data documents (data.json / data.yaml files).
	Data map[string]any
}

// ReadBundleTar parses a bundle tar with OPA's bundle reader, so modules and data documents
// are interpreted exactly as when the agent loads the bundle directory.
func ReadBundleTar(b []byte) (*Bundle, error) {
	// OPA's tarball loader reads gzip only; compress in memory. The stored form stays plain.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	parsed, err := bundle.NewCustomReader(bundle.NewTarballLoader(&gz)).Read()
	if err != nil {
		return nil, fmt.Errorf("%w: read policy bundle: %v", ErrInvalid, err)
	}

	out := &Bundle{
		Modules: make(map[string]string, len(parsed.Modules)),
		Data:    parsed.Data,
	}
	for _, module := range parsed.Modules {
		out.Modules[strings.TrimPrefix(module.Path, "/")] = string(module.Raw)
	}
	if out.Data == nil {
		out.Data = map[string]any{}
	}
	return out, nil
}

// Info describes a stored artifact without its content.
type Info struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	SizeBytes int64  `json:"sizeBytes"`
}

// Evidence props the API writes to record which artifacts produced a piece of evidence.
// They are covered by the evidence signature. Clients may not set them themselves.
const (
	PropPolicyBundleDigest = "_policy_bundle_digest"
	PropPolicyInputDigest  = "_policy_input_digest"
	PropPolicyDataDigest   = "_policy_data_digest"
)

// IsReservedProp reports whether name is one of the props only the API may write.
func IsReservedProp(name string) bool {
	switch name {
	case PropPolicyBundleDigest, PropPolicyInputDigest, PropPolicyDataDigest:
		return true
	}
	return false
}
