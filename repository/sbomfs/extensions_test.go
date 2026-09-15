// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sbomfs

import (
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/stretchr/testify/require"
)

func TestFetchExtensions(t *testing.T) {
	t.Parallel()
	path := writeSBOMWithAttestations(t, nil)
	dsse := testDSSE(t, "https://slsa.dev/provenance/v0.2")

	for _, tc := range []struct {
		name   string
		exts   []string
		expect int
	}{
		{"defaults", nil, 1},
		{"other-list", []string{"jsonl"}, 0},
		{"custom-includes-txt", []string{"json", "txt"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := []optFn{WithPath(path)}
			if tc.exts != nil {
				opts = append(opts, WithExtensions(tc.exts))
			}
			c, err := New(opts...)
			require.NoError(t, err)
			require.NoError(t, c.fs.WriteFile("att.json", dsse))
			require.NoError(t, c.fs.WriteFile("att.txt", dsse))

			envs, err := c.Fetch(t.Context(), attestation.FetchOptions{})
			require.NoError(t, err)
			require.Len(t, envs, tc.expect)
		})
	}
}
