// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"crypto/x509"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/stretchr/testify/require"
)

func TestCertificateCompanion(t *testing.T) {
	t.Parallel()
	c := &Collector{CertificateExtensions: defaultCertificateExtensions}

	t.Run("pem-companion", func(t *testing.T) {
		t.Parallel()
		fileSet := map[string]struct{}{"bin": {}, "bin.pem": {}, "bin.sig": {}}
		got, ok := c.certificateCompanion("bin", fileSet)
		require.True(t, ok)
		require.Equal(t, "bin.pem", got)
	})

	t.Run("crt-companion", func(t *testing.T) {
		t.Parallel()
		fileSet := map[string]struct{}{"x": {}, "x.crt": {}}
		got, ok := c.certificateCompanion("x", fileSet)
		require.True(t, ok)
		require.Equal(t, "x.crt", got)
	})

	t.Run("no-companion", func(t *testing.T) {
		t.Parallel()
		fileSet := map[string]struct{}{"bin": {}, "bin.sig": {}}
		_, ok := c.certificateCompanion("bin", fileSet)
		require.False(t, ok)
	})
}

func TestHasSignatureExtensionCertificates(t *testing.T) {
	t.Parallel()
	c := &Collector{CertificateExtensions: defaultCertificateExtensions}
	require.True(t, c.hasSignatureExtension("artifact.pem"))
	require.True(t, c.hasSignatureExtension("artifact.crt"))
	require.True(t, c.hasSignatureExtension("artifact.cert"))
	require.False(t, c.hasSignatureExtension("artifact.txt"))
}

func TestDecodeCertificatePEM(t *testing.T) {
	t.Parallel()

	// The fixture certificate is stored base64-wrapped, as some release
	// pipelines publish it.
	wrapped, err := os.ReadFile("testdata/signature/publish-release-amd64-darwin.pem")
	require.NoError(t, err)

	der, err := decodeCertificatePEM(wrapped)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	require.Len(t, cert.URIs, 1)
	require.Contains(t, cert.URIs[0].String(), "kubernetes/release/.github/workflows/release.yml")

	// A raw (already-unwrapped) PEM must yield the same DER bytes.
	rawPEM, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(wrapped)))
	require.NoError(t, err)
	rawDER, err := decodeCertificatePEM(rawPEM)
	require.NoError(t, err)
	require.Equal(t, der, rawDER)

	// Non-certificate input is rejected.
	_, err = decodeCertificatePEM([]byte("not a certificate"))
	require.Error(t, err)
}

func TestDecodeSignature(t *testing.T) {
	t.Parallel()

	// cosign writes base64-encoded signatures.
	raw := []byte{0x30, 0x45, 0x02, 0x21, 0x00, 0xAB}
	require.Equal(t, raw, decodeSignature([]byte(base64.StdEncoding.EncodeToString(raw))))

	// A real fixture signature decodes to a DER ECDSA signature.
	sig, err := os.ReadFile("testdata/signature/publish-release-amd64-darwin.sig")
	require.NoError(t, err)
	decoded := decodeSignature(sig)
	require.NotEmpty(t, decoded)
	require.Equal(t, byte(0x30), decoded[0]) // DER SEQUENCE tag

	// Input that is not valid base64 is returned unchanged.
	notB64 := []byte{0xff, 0xfe, 0xfd}
	require.Equal(t, notB64, decodeSignature(notB64))
}

func TestBuildDetachedBundle(t *testing.T) {
	t.Parallel()

	cert := []byte("certificate-der")
	sig := []byte("signature-bytes")
	digest := []byte("0123456789abcdef0123456789abcdef")
	tlog := &protorekor.TransparencyLogEntry{LogIndex: 42}

	b := buildDetachedBundle(cert, sig, digest, tlog)

	require.Equal(t, detachedBundleMediaType, b.GetMediaType())
	require.Equal(t, cert, b.GetVerificationMaterial().GetCertificate().GetRawBytes())
	require.Len(t, b.GetVerificationMaterial().GetTlogEntries(), 1)
	require.Equal(t, int64(42), b.GetVerificationMaterial().GetTlogEntries()[0].GetLogIndex())

	ms := b.GetMessageSignature()
	require.NotNil(t, ms)
	require.Equal(t, sig, ms.GetSignature())
	require.Equal(t, digest, ms.GetMessageDigest().GetDigest())
	require.Equal(t, protocommon.HashAlgorithm_SHA2_256, ms.GetMessageDigest().GetAlgorithm())
}
