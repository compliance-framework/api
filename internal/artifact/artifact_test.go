package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Golden digests. Stored evidence refers to artifacts by these digests forever, so a change
// here means previously stored digests can no longer be reproduced. Do not update them to
// make a test pass; fix the canonical form instead.
const (
	goldenBundleDigest = "sha256:697674955cdf6945eff81543dfb8dd5594762e6f7029a308c7dd3e86e6abfbae"
	goldenInputDigest  = "sha256:f62250fbefcaacaac32cda7c682bed2894a7520f0c4e649a84e8e055ab1ec42d"
	limit              = 1 << 20
)

var goldenInput = map[string]any{
	"hostname":   "web-1 <prod>",
	"open_ports": []any{22, 8080},
	"uptime":     json.Number("12345678901234567890"),
	"ratio":      json.Number("0.10"),
	"tags":       map[string]any{"z": true, "a": nil},
}

type tarEntry struct {
	header  tar.Header
	content string
}

func buildTar(t *testing.T, entries []tarEntry, gzipped bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := e.header
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.content))
		}
		require.NoError(t, tw.WriteHeader(&h))
		if e.content != "" {
			_, err := tw.Write([]byte(e.content))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	if !gzipped {
		return buf.Bytes()
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, err := zw.Write(buf.Bytes())
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return gz.Bytes()
}

// tarDir archives dir the way an agent might: with directory entries, a "./" prefix, real
// modes, owners and times, in the given file order.
func tarDir(t *testing.T, dir string, reverse, gzipped bool) []byte {
	t.Helper()
	var files []string
	require.NoError(t, filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			files = append(files, p)
		}
		return err
	}))
	if reverse {
		slices.Reverse(files)
	}
	entries := []tarEntry{{header: tar.Header{Typeflag: tar.TypeDir, Name: "./", Mode: 0o755}}}
	for i, f := range files {
		rel, err := filepath.Rel(dir, f)
		require.NoError(t, err)
		content, err := os.ReadFile(f)
		require.NoError(t, err)
		entries = append(entries, tarEntry{
			header: tar.Header{
				Typeflag: tar.TypeReg,
				Name:     "./" + filepath.ToSlash(rel),
				Mode:     0o600 + int64(i),
				Uid:      501,
				Gid:      20,
				Uname:    "someone",
				ModTime:  time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC).Add(time.Duration(i) * time.Hour),
			},
			content: string(content),
		})
	}
	return buildTar(t, entries, gzipped)
}

func TestDigest(t *testing.T) {
	d := Digest([]byte("hello"))
	assert.Equal(t, "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", d)
	assert.True(t, ValidDigest(d))
	assert.False(t, ValidDigest(strings.ToUpper(d)))
	assert.False(t, ValidDigest("md5:5d41402abc4b2a76b9719d911017c592"))
	assert.False(t, ValidDigest("sha256:abc"))
}

func TestCanonicalJSON(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"sorts keys and drops whitespace": {`{ "b": 1, "a": {"d": [1, 2], "c": null} }`, `{"a":{"c":null,"d":[1,2]},"b":1}`},
		"keeps numbers exactly":           {`{"big": 12345678901234567890, "ratio": 0.10, "exp": 1e2}`, `{"big":12345678901234567890,"exp":1e2,"ratio":0.10}`},
		"does not escape HTML":            {`{"q": "<a & b>"}`, `{"q":"<a & b>"}`},
		"accepts any JSON value":          {` [1, "x"] `, `[1,"x"]`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Canonical(MediaTypeJSON, []byte(tc.in), limit)
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(got))
		})
	}

	t.Run("rejects invalid JSON and trailing data", func(t *testing.T) {
		for _, in := range []string{`{"a":`, `{"a":1} {"b":2}`, ``} {
			_, err := Canonical(MediaTypeJSON, []byte(in), limit)
			assert.ErrorIs(t, err, ErrInvalid, in)
		}
	})

	t.Run("is idempotent", func(t *testing.T) {
		once, err := CanonicalJSON(goldenInput)
		require.NoError(t, err)
		twice, err := Canonical(MediaTypeJSON, once, limit)
		require.NoError(t, err)
		assert.Equal(t, once, twice)
	})

	t.Run("golden digest", func(t *testing.T) {
		got, err := CanonicalJSON(goldenInput)
		require.NoError(t, err)
		assert.Equal(t, `{"hostname":"web-1 <prod>","open_ports":[22,8080],"ratio":0.10,"tags":{"a":null,"z":true},"uptime":12345678901234567890}`, string(got))
		assert.Equal(t, goldenInputDigest, Digest(got))
	})

	t.Run("canonical form is bounded", func(t *testing.T) {
		_, err := Canonical(MediaTypeJSON, []byte(`{"a":"`+strings.Repeat("x", 100)+`"}`), 16)
		assert.ErrorIs(t, err, ErrInvalid)
	})
}

func TestCanonicalBundle(t *testing.T) {
	t.Run("every archive shape of the same files has one digest", func(t *testing.T) {
		var digests []string
		for _, shape := range []struct{ reverse, gzipped bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
			got, err := Canonical(MediaTypePolicyBundle, tarDir(t, "testdata/bundle", shape.reverse, shape.gzipped), limit)
			require.NoError(t, err)
			digests = append(digests, Digest(got))
		}
		assert.Equal(t, []string{goldenBundleDigest, goldenBundleDigest, goldenBundleDigest, goldenBundleDigest}, digests)
	})

	t.Run("is idempotent", func(t *testing.T) {
		once, err := CanonicalBundle(tarDir(t, "testdata/bundle", false, true), limit)
		require.NoError(t, err)
		twice, err := CanonicalBundle(once, limit)
		require.NoError(t, err)
		assert.Equal(t, once, twice)
	})

	t.Run("changed content changes the digest", func(t *testing.T) {
		a := buildTar(t, []tarEntry{{header: tar.Header{Typeflag: tar.TypeReg, Name: "p.rego"}, content: "package a\n"}}, false)
		b := buildTar(t, []tarEntry{{header: tar.Header{Typeflag: tar.TypeReg, Name: "p.rego"}, content: "package b\n"}}, false)
		ca, err := CanonicalBundle(a, limit)
		require.NoError(t, err)
		cb, err := CanonicalBundle(b, limit)
		require.NoError(t, err)
		assert.NotEqual(t, Digest(ca), Digest(cb))
	})

	reg := func(name, content string) tarEntry {
		return tarEntry{header: tar.Header{Typeflag: tar.TypeReg, Name: name}, content: content}
	}
	rejected := map[string][]tarEntry{
		"parent path":    {reg("../escape.rego", "package x\n")},
		"nested parent":  {reg("lib/../../escape.rego", "package x\n")},
		"duplicate path": {reg("p.rego", "package a\n"), reg("./p.rego", "package a\n")},
		"symlink":        {{header: tar.Header{Typeflag: tar.TypeSymlink, Name: "p.rego", Linkname: "/etc/passwd"}}},
		"hard link":      {{header: tar.Header{Typeflag: tar.TypeLink, Name: "p.rego", Linkname: "other.rego"}}},
		"no files":       {{header: tar.Header{Typeflag: tar.TypeDir, Name: "lib/"}}},
		"invalid rego":   {reg("p.rego", "this is not rego")},
	}
	for name, entries := range rejected {
		t.Run("rejects "+name, func(t *testing.T) {
			_, err := CanonicalBundle(buildTar(t, entries, false), limit)
			assert.ErrorIs(t, err, ErrInvalid)
		})
	}

	t.Run("absolute paths are made relative", func(t *testing.T) {
		got, err := CanonicalBundle(buildTar(t, []tarEntry{reg("/p.rego", "package a\n")}, false), limit)
		require.NoError(t, err)
		b, err := ReadBundleTar(got)
		require.NoError(t, err)
		assert.Contains(t, b.Modules, "p.rego")
	})

	t.Run("rejects a gzip bomb", func(t *testing.T) {
		bomb := buildTar(t, []tarEntry{reg("data.json", `{"a":"`+strings.Repeat("x", 4<<20)+`"}`)}, true)
		require.Less(t, len(bomb), 64<<10, "the compressed archive is small")
		_, err := CanonicalBundle(bomb, limit)
		assert.ErrorIs(t, err, ErrInvalid)
	})

	t.Run("rejects data that is not an archive", func(t *testing.T) {
		_, err := Canonical(MediaTypePolicyBundle, []byte("not a tar"), limit)
		assert.ErrorIs(t, err, ErrInvalid)
	})
}

func TestCanonicalRejectsUnknownMediaType(t *testing.T) {
	_, err := Canonical("text/plain", []byte("x"), limit)
	assert.ErrorIs(t, err, ErrInvalid)
}

func TestReadBundleTar(t *testing.T) {
	canonical, err := CanonicalBundle(tarDir(t, "testdata/bundle", false, false), limit)
	require.NoError(t, err)

	b, err := ReadBundleTar(canonical)
	require.NoError(t, err)

	policy, err := os.ReadFile("testdata/bundle/policy.rego")
	require.NoError(t, err)
	assert.Equal(t, string(policy), b.Modules["policy.rego"])
	assert.Contains(t, b.Modules, "lib/helpers.rego")
	assert.Len(t, b.Modules, 2)
	assert.Equal(t, map[string]any{
		"config": map[string]any{"approved_ports": []any{json.Number("22"), json.Number("443")}},
	}, b.Data)
}
