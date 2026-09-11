// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sbomfs

import (
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/internal/envtest"
	"github.com/carabiner-dev/collector/repository"
)

func TestStoreSkipsFailingEnvelopes(t *testing.T) {
	t.Parallel()

	path := writeSBOMWithAttestations(t, nil)
	c, err := New(WithPath(path))
	require.NoError(t, err)

	// Parse a real envelope by writing and reading it back
	require.NoError(t, c.fs.WriteFile("bootstrap.json", testDSSE(t, "https://slsa.dev/provenance/v0.2")))
	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	require.NoError(t, c.fs.RemoveFile("bootstrap.json"))

	err = c.Store(t.Context(), attestation.StoreOptions{}, []attestation.Envelope{envtest.Unserializable{}, envs[0]})
	var serr *repository.StoreError
	require.ErrorAs(t, err, &serr)
	require.Equal(t, 1, serr.Stored)
	require.Len(t, serr.Failed, 1)
	require.ErrorIs(t, serr.Failed[0], envtest.ErrUnserializable)

	// The good envelope is in the document written to disk
	c2, err := New(WithPath(path))
	require.NoError(t, err)
	stored, err := c2.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, stored, 1)
}
