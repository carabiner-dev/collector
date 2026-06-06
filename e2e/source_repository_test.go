// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"testing"

	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/envelope/bundle"
)

// TestBundleSourceRepositoryURICapture verifies a real GitHub Actions keyless
// bundle and checks that the source repository URI (Fulcio OID
// 1.3.6.1.4.1.57264.1.12) is captured into the signer identity, so policies can
// pin it with source_repository_uri_match. Verification fetches the sigstore
// trust root over TUF, hence the e2e tag.
func TestBundleSourceRepositoryURICapture(t *testing.T) {
	envs, err := (&bundle.Parser{}).ParseFile("testdata/github-actions-bundle.json")
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	require.NoError(t, envs[0].Verify())

	v, ok := envs[0].GetVerification().(*sapi.Verification)
	require.True(t, ok)
	ids := v.GetSignature().GetIdentities()
	require.NotEmpty(t, ids)

	require.Equal(
		t, "https://github.com/sigstore/sigstore-js",
		ids[0].GetSigstore().GetSourceRepositoryUri(),
	)
}
