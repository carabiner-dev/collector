// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"os"
	"testing"
	"testing/fstest"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/signer/key"
	"github.com/stretchr/testify/require"
)

func TestGetSignatureExtension(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		path string
		want string
	}{
		{"artifact.txt.sig", ".sig"},
		{"artifact.txt", ""},
		{"some/path/file.exe.sig", ".sig"},
		{"file.json", ""},
		{"file.sig.bak", ""},
		{"artifact.txt.gpg", ".gpg"},
		{"artifact.txt.asc", ".asc"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			got := getSignatureExtension(tc.path, defaultSignatureExtensions)
			require.Equal(t, tc.want, got)
		})
	}

	t.Run("sigstore-bundle-extensions", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, ".sigstore.json", getSignatureExtension("artifact.txt.sigstore.json", defaultSigstoreBundleExtensions))
		require.Equal(t, ".sigstore.json", getSignatureExtension("bundle.sigstore.json", defaultSigstoreBundleExtensions))
		require.Empty(t, getSignatureExtension("file.json", defaultSigstoreBundleExtensions))
		// .sigstore.json should NOT match default signature extensions
		require.Empty(t, getSignatureExtension("artifact.txt.sigstore.json", defaultSignatureExtensions))
	})
}

func TestGetSignatureExtensionCustom(t *testing.T) {
	t.Parallel()
	custom := []string{".p7s", ".cms"}
	require.Equal(t, ".p7s", getSignatureExtension("file.tar.gz.p7s", custom))
	require.Equal(t, ".cms", getSignatureExtension("file.tar.gz.cms", custom))
	require.Empty(t, getSignatureExtension("file.tar.gz.sig", custom))
}

func TestHasSignatureExtension(t *testing.T) {
	t.Parallel()

	c := &Collector{
		SignatureExtensions:      defaultSignatureExtensions,
		SigstoreBundleExtensions: defaultSigstoreBundleExtensions,
	}

	require.True(t, c.hasSignatureExtension("artifact.txt.sig"))
	require.True(t, c.hasSignatureExtension("artifact.txt.sigstore.json"))
	require.True(t, c.hasSignatureExtension("artifact.txt.gpg"))
	require.True(t, c.hasSignatureExtension("artifact.txt.asc"))
	require.False(t, c.hasSignatureExtension("artifact.txt"))
	require.False(t, c.hasSignatureExtension("artifact.json"))

	t.Run("custom-signature-extension", func(t *testing.T) {
		t.Parallel()
		custom := &Collector{SignatureExtensions: []string{".p7s"}}
		require.True(t, custom.hasSignatureExtension("artifact.txt.p7s"))
		// Default extensions should not match when overridden
		require.False(t, custom.hasSignatureExtension("artifact.txt.sig"))
		// Sigstore bundle extensions not set, so .sigstore.json won't match
		require.False(t, custom.hasSignatureExtension("artifact.txt.sigstore.json"))
	})

	t.Run("custom-sigstore-extension", func(t *testing.T) {
		t.Parallel()
		custom := &Collector{SigstoreBundleExtensions: []string{".bundle.json"}}
		require.True(t, custom.hasSignatureExtension("artifact.txt.bundle.json"))
		require.False(t, custom.hasSignatureExtension("artifact.txt.sigstore.json"))
	})
}

func TestRawSigVerification(t *testing.T) {
	t.Parallel()

	artifactContent := []byte("This is a test artifact for signature verification.\n")

	// Generate a test keypair
	gen := key.NewGenerator()
	privKey, err := gen.GenerateKeyPair()
	require.NoError(t, err)

	// Sign the artifact
	sgnr := key.NewSigner()
	sig, err := sgnr.SignMessage(privKey, artifactContent)
	require.NoError(t, err)

	pubKey, err := privKey.PublicKey()
	require.NoError(t, err)

	fsys := fstest.MapFS{
		"artifact.txt":     &fstest.MapFile{Data: artifactContent},
		"artifact.txt.sig": &fstest.MapFile{Data: sig},
	}

	c := &Collector{
		FS:   fsys,
		Keys: []key.PublicKeyProvider{pubKey},
	}

	// Verify the signature
	verification, err := c.verifyWithKeys("artifact.txt", sig)
	require.NoError(t, err)
	require.True(t, verification.GetVerified())
	require.Len(t, verification.GetSignature().GetIdentities(), 1)
	require.NotNil(t, verification.GetSignature().GetIdentities()[0].GetKey())
	require.Equal(t, pubKey.ID(), verification.GetSignature().GetIdentities()[0].GetKey().GetId())
}

func TestBuildVirtualAttestation(t *testing.T) {
	t.Parallel()

	artifactContent := []byte("This is a test artifact for signature verification.\n")

	// Generate a test keypair and sign
	gen := key.NewGenerator()
	privKey, err := gen.GenerateKeyPair()
	require.NoError(t, err)

	sgnr := key.NewSigner()
	sig, err := sgnr.SignMessage(privKey, artifactContent)
	require.NoError(t, err)

	pubKey, err := privKey.PublicKey()
	require.NoError(t, err)

	fsys := fstest.MapFS{
		"artifact.txt":     &fstest.MapFile{Data: artifactContent},
		"artifact.txt.sig": &fstest.MapFile{Data: sig},
	}

	c := &Collector{
		FS:   fsys,
		Keys: []key.PublicKeyProvider{pubKey},
	}

	verification, err := c.verifyWithKeys("artifact.txt", sig)
	require.NoError(t, err)

	env, err := c.buildVirtualAttestation("artifact.txt", verification)
	require.NoError(t, err)

	// Check predicate type
	require.NotNil(t, env.GetPredicate())
	require.Equal(t, SignaturePredicateType, env.GetPredicate().GetType())

	// Check predicate data is empty JSON object
	require.Equal(t, []byte("{}"), env.GetPredicate().GetData())

	// Check verification is populated
	require.NotNil(t, env.GetVerification())
	require.True(t, env.GetVerification().GetVerified())

	// Check subject
	require.NotNil(t, env.GetStatement())
	subjects := env.GetStatement().GetSubjects()
	require.Len(t, subjects, 1)
	require.Equal(t, "artifact.txt", subjects[0].GetName())
	require.NotEmpty(t, subjects[0].GetDigest())
}

func TestFetchWithSignaturePairs(t *testing.T) {
	t.Parallel()

	artifactContent := []byte("This is a test artifact for signature verification.\n")

	// Generate a test keypair and sign
	gen := key.NewGenerator()
	privKey, err := gen.GenerateKeyPair()
	require.NoError(t, err)

	sgnr := key.NewSigner()
	sig, err := sgnr.SignMessage(privKey, artifactContent)
	require.NoError(t, err)

	pubKey, err := privKey.PublicKey()
	require.NoError(t, err)

	fsys := fstest.MapFS{
		"artifact.txt":     &fstest.MapFile{Data: artifactContent},
		"artifact.txt.sig": &fstest.MapFile{Data: sig},
	}

	collector, err := New(WithFS(fsys), WithKey(pubKey))
	require.NoError(t, err)

	atts, err := collector.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)

	// Should have exactly 1 virtual attestation (the .sig file is processed
	// as a signature pair, not as an inline file)
	require.Len(t, atts, 1)
	require.Equal(t, SignaturePredicateType, atts[0].GetPredicate().GetType())
	require.True(t, atts[0].GetVerification().GetVerified())
}

func TestFetchUnpairedSigNotSkipped(t *testing.T) {
	t.Parallel()

	// An unpaired .sig file (no companion artifact) should not be skipped
	// from the normal walk — it will be attempted as a normal attestation parse.
	// Since raw sig data won't parse as any attestation format, it will error.
	// But with IgnoreOtherFiles=true and .sig not in Extensions, it's simply ignored.
	fsys := fstest.MapFS{
		"orphan.sig": &fstest.MapFile{Data: []byte("raw-sig-data")},
	}

	collector, err := New(WithFS(fsys))
	require.NoError(t, err)
	// Default: IgnoreOtherFiles=true, Extensions don't include "sig"

	atts, err := collector.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, atts)
}

func TestExistingTestdataRegression(t *testing.T) {
	t.Parallel()
	collector, err := New(WithFS(os.DirFS("testdata")))
	require.NoError(t, err)
	atts, err := collector.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 2)
}

func TestVirtualEnvelopeInterface(t *testing.T) {
	t.Parallel()

	env := &virtualEnvelope{statement: nil}

	// With nil statement, all methods should return safe defaults
	require.Nil(t, env.GetStatement())
	require.Nil(t, env.GetPredicate())
	require.Nil(t, env.GetVerification())
	require.Nil(t, env.GetSignatures())
	require.Nil(t, env.GetCertificate())
	require.NoError(t, env.Verify())
}

func TestVerifyWithNoKeys(t *testing.T) {
	t.Parallel()

	fsys := fstest.MapFS{
		"artifact.txt": &fstest.MapFile{Data: []byte("content")},
	}

	c := &Collector{FS: fsys, Keys: nil}
	v, err := c.verifyWithKeys("artifact.txt", []byte("sig"))
	require.Nil(t, v)
	require.ErrorContains(t, err, "no keys configured")
}

func TestWithSignatureExtensions(t *testing.T) {
	t.Parallel()

	artifactContent := []byte("test artifact content")

	gen := key.NewGenerator()
	privKey, err := gen.GenerateKeyPair()
	require.NoError(t, err)

	sgnr := key.NewSigner()
	sig, err := sgnr.SignMessage(privKey, artifactContent)
	require.NoError(t, err)

	pubKey, err := privKey.PublicKey()
	require.NoError(t, err)

	fsys := fstest.MapFS{
		"artifact.txt":     &fstest.MapFile{Data: artifactContent},
		"artifact.txt.p7s": &fstest.MapFile{Data: sig},
	}

	// Without custom extensions, .p7s is not recognized
	collector, err := New(WithFS(fsys), WithKey(pubKey))
	require.NoError(t, err)
	atts, err := collector.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, atts)

	// With custom extensions including .p7s, it should be recognized
	collector, err = New(WithFS(fsys), WithKey(pubKey), WithSignatureExtensions([]string{".p7s"}))
	require.NoError(t, err)
	atts, err = collector.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)
	require.Equal(t, SignaturePredicateType, atts[0].GetPredicate().GetType())
}

func TestWithSigstoreBundleExtensions(t *testing.T) {
	t.Parallel()

	// Verify that custom sigstore bundle extensions override the default
	collector, err := New(WithFS(fstest.MapFS{}), WithSigstoreBundleExtensions([]string{".bundle.json"}))
	require.NoError(t, err)
	require.Equal(t, []string{".bundle.json"}, collector.SigstoreBundleExtensions)

	// Default should not match
	require.False(t, collector.hasSignatureExtension("artifact.txt.sigstore.json"))
	// Custom should match
	require.True(t, collector.hasSignatureExtension("artifact.txt.bundle.json"))
}

func TestUnverifiableSignatureIgnored(t *testing.T) {
	t.Parallel()

	// A paired .sig file that cannot be verified (no keys, not sigstore)
	// should be silently ignored — no error returned from Fetch.
	fsys := fstest.MapFS{
		"artifact.txt":     &fstest.MapFile{Data: []byte("content")},
		"artifact.txt.sig": &fstest.MapFile{Data: []byte("not-a-valid-signature")},
	}

	collector, err := New(WithFS(fsys))
	require.NoError(t, err)

	atts, err := collector.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, atts)
}

func TestUnverifiableSignatureWithKeysIgnored(t *testing.T) {
	t.Parallel()

	// A paired .sig file with keys configured but signature doesn't match
	// should be silently ignored.
	gen := key.NewGenerator()
	privKey, err := gen.GenerateKeyPair()
	require.NoError(t, err)

	pubKey, err := privKey.PublicKey()
	require.NoError(t, err)

	fsys := fstest.MapFS{
		"artifact.txt":     &fstest.MapFile{Data: []byte("content")},
		"artifact.txt.sig": &fstest.MapFile{Data: []byte("garbage-signature-data")},
	}

	collector, err := New(WithFS(fsys), WithKey(pubKey))
	require.NoError(t, err)

	atts, err := collector.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, atts)
}

func TestVerifyWithWrongKey(t *testing.T) {
	t.Parallel()

	artifactContent := []byte("test content")

	// Generate two different keypairs
	gen := key.NewGenerator()
	signingKey, err := gen.GenerateKeyPair()
	require.NoError(t, err)

	wrongKey, err := gen.GenerateKeyPair()
	require.NoError(t, err)

	// Sign with one key
	sgnr := key.NewSigner()
	sig, err := sgnr.SignMessage(signingKey, artifactContent)
	require.NoError(t, err)

	// Try to verify with the wrong key
	wrongPub, err := wrongKey.PublicKey()
	require.NoError(t, err)

	fsys := fstest.MapFS{
		"artifact.txt": &fstest.MapFile{Data: artifactContent},
	}

	c := &Collector{FS: fsys, Keys: []key.PublicKeyProvider{wrongPub}}
	v, err := c.verifyWithKeys("artifact.txt", sig)
	require.Nil(t, v)
	require.ErrorContains(t, err, "no key verified")
}
