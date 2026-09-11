// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package coci

import (
	"fmt"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/envelope/bundle"
	"github.com/carabiner-dev/collector/repository"
)

func TestStoreSkipsFailingEnvelopes(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/partial:v1", host)
	pushEmptySubject(t, ctx, repo)

	c, err := New(WithReference(repo), WithCraneOpts(crane.Insecure))
	require.NoError(t, err)

	// A bundle without a DSSE envelope cannot become a layer
	noDSSE := &bundle.Envelope{}

	err = c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{noDSSE, makeDSSEEnvelope()})
	var serr *repository.StoreError
	require.ErrorAs(t, err, &serr)
	require.Equal(t, 1, serr.Stored)
	require.Len(t, serr.Failed, 1)
	require.ErrorContains(t, serr.Failed[0], "does not contain a DSSE envelope")

	// The good envelope was pushed
	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)

	// When nothing can become a layer, nothing is pushed
	err = c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{noDSSE})
	require.ErrorAs(t, err, &serr)
	require.True(t, serr.AllFailed())
	atts, err = c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)
}
