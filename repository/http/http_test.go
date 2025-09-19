// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/stretchr/testify/require"
)

func TestFetchData(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name         string
		expectedAtts int
		mustErr      bool
		uri          string
	}{
		{"fixed-url", 2, false, "https://storage.googleapis.com/google-rebuild-attestations/npm/chalk/5.6.2/chalk-5.6.2.tgz/rebuild.intoto.jsonl"},
		{"bad-url", 0, true, "https://this-is-wrong/myadata.json"},
		{"url-404", 0, false, "https://storage-that-is-note.googleapis.com/google-rebuild-attestations/npm/chalk/5.6.2/chalk-5.6.2.tgz/SOMETHING"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			collector, err := New(WithURL(tt.uri))
			// If we know ir will err, don't retry
			if tt.mustErr {
				collector.Options.Retries = 1
			}
			require.NoError(t, err)
			atts, err := collector.Fetch(t.Context(), attestation.FetchOptions{
				Limit: 0,
				Query: nil,
			})
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, atts, tt.expectedAtts)
		})
	}
	//
}
