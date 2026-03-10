// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package e2e contains end-to-end tests for the collector's virtual signature
// attestation generation. These tests hit real GitHub releases and external
// key servers, so they require network access.
package e2e

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/carabiner-dev/attestation"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/key"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/repository/filesystem"
	"github.com/carabiner-dev/collector/repository/release"
)

// TestSigstoreVirtualAttestations verifies that the collector generates virtual
// signature attestations for cosign v3.0.5, which ships .sigstore.json bundles
// signed with Fulcio certificates.
func TestSigstoreVirtualAttestations(t *testing.T) {
	ctx := context.Background()

	collector, err := release.New(
		release.WithRepo("sigstore/cosign"),
		release.WithTag("v3.0.5"),
	)
	require.NoError(t, err)

	atts, err := collector.FetchByPredicateType(ctx, attestation.FetchOptions{},
		[]attestation.PredicateType{filesystem.SignaturePredicateType},
	)
	require.NoError(t, err)
	require.NotEmpty(t, atts, "expected virtual signature attestations from cosign release")

	// Build a map of attestations by subject name for targeted assertions.
	byName := map[string]attestation.Envelope{}
	for _, att := range atts {
		stmt := att.GetStatement()
		require.NotNil(t, stmt)
		subjects := stmt.GetSubjects()
		require.NotEmpty(t, subjects)
		byName[subjects[0].GetName()] = att
	}

	// Spot-check a few well-known cosign artifacts.
	expectedArtifacts := []string{
		"cosign-linux-amd64",
		"cosign-linux-arm64",
		"cosign-darwin-amd64",
		"cosign-darwin-arm64",
		"cosign-windows-amd64.exe",
	}

	for _, name := range expectedArtifacts {
		att, ok := byName[name]
		if !ok {
			t.Logf("artifact %q not found in attestations (may not have sigstore bundle), skipping", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			// Verify predicate type
			pred := att.GetPredicate()
			require.NotNil(t, pred)
			require.Equal(t, filesystem.SignaturePredicateType, pred.GetType())

			// Verify subject has a sha256 digest
			subjects := att.GetStatement().GetSubjects()
			require.NotEmpty(t, subjects)
			digest := subjects[0].GetDigest()
			require.Contains(t, digest, "sha256", "subject should have a sha256 digest")
			require.NotEmpty(t, digest["sha256"])

			// Verify the verification data
			verification := att.GetVerification()
			require.NotNil(t, verification, "attestation should have verification data")
			require.True(t, verification.GetVerified(), "attestation should be verified")

			// Check the signer identity is a sigstore identity
			sapiV, ok := verification.(*sapi.Verification)
			require.True(t, ok, "verification should be *sapi.Verification")
			require.NotNil(t, sapiV.GetSignature())

			identities := sapiV.GetSignature().GetIdentities()
			require.NotEmpty(t, identities, "should have at least one signer identity")

			// cosign releases are signed with keyless signing via Google's OIDC
			identity := identities[0]
			require.NotNil(t, identity.GetSigstore(), "identity should be a sigstore identity")
			require.Equal(t, "https://accounts.google.com", identity.GetSigstore().GetIssuer())
			require.Equal(t, "keyless@projectsigstore.iam.gserviceaccount.com", identity.GetSigstore().GetIdentity())
		})
	}
}

// TestGPGVirtualAttestations verifies that the collector generates virtual
// signature attestations for curl releases signed with Daniel Stenberg's GPG key.
func TestGPGVirtualAttestations(t *testing.T) {
	ctx := context.Background()

	// Fetch Daniel Stenberg's GPG public key
	gpgKeys, err := fetchGPGKey(t, "https://daniel.haxx.se/mykey.asc")
	require.NoError(t, err)
	require.NotEmpty(t, gpgKeys)

	keys := make([]key.PublicKeyProvider, 0, len(gpgKeys))
	for _, k := range gpgKeys {
		keys = append(keys, k)
	}

	collector, err := release.New(
		release.WithRepo("curl/curl"),
		release.WithTag("curl-8_12_1"),
		release.WithKey(keys...),
	)
	require.NoError(t, err)

	atts, err := collector.FetchByPredicateType(ctx, attestation.FetchOptions{},
		[]attestation.PredicateType{filesystem.SignaturePredicateType},
	)
	require.NoError(t, err)
	require.NotEmpty(t, atts, "expected virtual signature attestations from curl release")

	// Build a map of attestations by subject name.
	byName := map[string]attestation.Envelope{}
	for _, att := range atts {
		stmt := att.GetStatement()
		require.NotNil(t, stmt)
		subjects := stmt.GetSubjects()
		require.NotEmpty(t, subjects)
		byName[subjects[0].GetName()] = att
	}

	// curl-8_12_1 ships .tar.gz, .tar.bz2, .tar.xz, and .zip with .asc sigs
	expectedArtifacts := []string{
		"curl-8.12.1.tar.gz",
		"curl-8.12.1.tar.bz2",
		"curl-8.12.1.tar.xz",
		"curl-8.12.1.zip",
	}

	for _, name := range expectedArtifacts {
		att, ok := byName[name]
		require.True(t, ok, "expected attestation for %q", name)

		t.Run(name, func(t *testing.T) {
			// Verify predicate type
			pred := att.GetPredicate()
			require.NotNil(t, pred)
			require.Equal(t, filesystem.SignaturePredicateType, pred.GetType())

			// Verify subject has digests
			subjects := att.GetStatement().GetSubjects()
			require.NotEmpty(t, subjects)
			digest := subjects[0].GetDigest()
			require.Contains(t, digest, "sha256", "subject should have a sha256 digest")
			require.NotEmpty(t, digest["sha256"])
			require.Contains(t, digest, "sha512", "subject should have a sha512 digest")
			require.NotEmpty(t, digest["sha512"])

			// Verify the verification data
			verification := att.GetVerification()
			require.NotNil(t, verification, "attestation should have verification data")
			require.True(t, verification.GetVerified(), "attestation should be verified")

			// Check the signer identity is a key identity
			sapiV, ok := verification.(*sapi.Verification)
			require.True(t, ok, "verification should be *sapi.Verification")
			require.NotNil(t, sapiV.GetSignature())

			identities := sapiV.GetSignature().GetIdentities()
			require.NotEmpty(t, identities, "should have at least one signer identity")

			// curl releases are signed with Daniel Stenberg's GPG key
			identity := identities[0]
			require.NotNil(t, identity.GetKey(), "identity should be a key identity")
			require.NotEmpty(t, identity.GetKey().GetId(), "key identity should have an ID")
			require.NotEmpty(t, identity.GetKey().GetType(), "key identity should have a type")
			require.NotEmpty(t, identity.GetKey().GetData(), "key identity should have key data")
		})
	}
}

func fetchGPGKey(t *testing.T, url string) ([]*key.GPGPublic, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // test code

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return key.ParseGPGPublicKey(data)
}
