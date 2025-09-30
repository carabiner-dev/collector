// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package coci

import (
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/stretchr/testify/require"
)

func TestFetch(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name         string
		ref          string
		expectedAtts int
	}{
		{"chainguard", "cgr.dev/chainguard/go", 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &Collector{
				Options: Options{
					Reference: tt.ref,
				},
			}

			atts, err := c.Fetch(t.Context(), attestation.FetchOptions{})
			require.NoError(t, err)
			require.Len(t, atts, tt.expectedAtts)
		})
	}
}
