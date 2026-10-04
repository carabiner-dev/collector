// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"os"
	"testing"

	"github.com/policylabs/signer"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/options"
	"github.com/stretchr/testify/require"
)

// A verifier passed to Verify is used in place of the shared default. The
// custom one here has no sigstore instances, so the only way to reach an
// unverifiable conclusion without touching the network is through it.
func TestVerifyUsesSuppliedVerifier(t *testing.T) {
	t.Parallel()
	f, err := os.Open("testdata/bundle-provenance.json")
	require.NoError(t, err)
	defer f.Close() //nolint:errcheck
	envelopes, err := (&Parser{}).ParseStream(f)
	require.NoError(t, err)
	env, ok := envelopes[0].(*Envelope)
	require.True(t, ok)

	noInstances := signer.NewVerifier(options.WithSigstoreRoots([]byte(`{"roots":[]}`)))
	require.NoError(t, env.Verify("ignored", noInstances))

	sv, ok := env.GetVerification().(*sapi.Verification)
	require.True(t, ok)
	require.Equal(t, sapi.VerificationStatus_UNVERIFIABLE, sv.GetSignature().GetStatus())
}
