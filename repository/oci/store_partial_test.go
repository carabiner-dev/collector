// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"os"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/ref"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/envelope/bundle"
	"github.com/carabiner-dev/collector/internal/envtest"
	"github.com/carabiner-dev/collector/repository"
)

func TestStoreSkipsFailingEnvelopes(t *testing.T) {
	t.Parallel()
	host, hostOpt := startRegistry(t)
	ctx := t.Context()
	rc := regclient.New(hostOpt)

	repo := host + "/test/partial"
	r, err := ref.New(repo + ":v1")
	require.NoError(t, err)
	pushSubjectImage(t, ctx, rc, &r)

	bundleData, err := os.ReadFile("testdata/bundle-provenance.json")
	require.NoError(t, err)
	env := &bundle.Envelope{}
	require.NoError(t, env.UnmarshalJSON(bundleData))

	c, err := New(WithReference(repo+":v1"), WithRegClientOpts(hostOpt))
	require.NoError(t, err)

	err = c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{envtest.Unserializable{}, env})
	var serr *repository.StoreError
	require.ErrorAs(t, err, &serr)
	require.Equal(t, 1, serr.Stored)
	require.Len(t, serr.Failed, 1)
	require.ErrorIs(t, serr.Failed[0], envtest.ErrUnserializable)

	// The good envelope made it to the registry
	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)
}
