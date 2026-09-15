// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"testing"
	"testing/fstest"

	"github.com/carabiner-dev/attestation"
	"github.com/stretchr/testify/require"
)

// policySetDocument is a bare policy set, which the predicate parsers turn
// into a policy set statement. JSON is valid HJSON, so the same bytes serve
// both extensions here.
const policySetDocument = `{"id": "test-set", "meta": {"version": 1}, "policies": [{"id": "p", "tenets": [{"id": "t", "code": "true"}]}]}`

func TestExtensions(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"set.json":  &fstest.MapFile{Data: []byte(policySetDocument)},
		"set.hjson": &fstest.MapFile{Data: []byte(policySetDocument)},
		"set.txt":   &fstest.MapFile{Data: []byte(policySetDocument)},
	}

	for _, tc := range []struct {
		name   string
		opts   []OptFn
		expect int
	}{
		{"defaults-read-json-and-hjson", nil, 2},
		{"json-only", []OptFn{WithExtensions([]string{"json"})}, 1},
		{"custom-list", []OptFn{WithExtensions([]string{"txt", "hjson"})}, 2},
		{"empty-list-reads-nothing", []OptFn{WithExtensions([]string{})}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(append([]OptFn{WithFS(fsys)}, tc.opts...)...)
			require.NoError(t, err)
			atts, err := c.Fetch(t.Context(), attestation.FetchOptions{})
			require.NoError(t, err)
			require.Len(t, atts, tc.expect)
		})
	}
}

func TestDefaultExtensionsAreCopied(t *testing.T) {
	t.Parallel()
	c, err := New()
	require.NoError(t, err)
	require.Equal(t, DefaultExtensions, c.Extensions)
	require.Contains(t, c.Extensions, "hjson")

	exts := []string{"json"}
	c2, err := New(WithExtensions(exts))
	require.NoError(t, err)
	exts[0] = "changed"
	require.Equal(t, []string{"json"}, c2.Extensions, "the option must not alias the caller's slice")
	c.Extensions[0] = "mutated"
	require.Equal(t, "json", DefaultExtensions[0], "collectors must not alias the package defaults")
}
