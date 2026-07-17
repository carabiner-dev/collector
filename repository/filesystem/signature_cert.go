// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/fs"
	"strings"

	"github.com/carabiner-dev/attestation"
	sigstore "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	rekorentries "github.com/sigstore/rekor/pkg/generated/client/entries"
	rekorindex "github.com/sigstore/rekor/pkg/generated/client/index"
	rekormodels "github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/tle"
	"github.com/sirupsen/logrus"
)

const (
	// defaultRekorURL is the public sigstore transparency log, used to look up
	// the entry backing a detached keyless signature.
	defaultRekorURL = "https://rekor.sigstore.dev"

	// detachedBundleMediaType is the sigstore bundle media type used when
	// reconstructing a bundle from a detached certificate + signature pair.
	detachedBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

// certificateCompanion returns the path of a certificate file sitting next to
// an artifact (e.g. `<artifact>.pem`), if one exists among the collected files.
func (c *Collector) certificateCompanion(artifactPath string, fileSet map[string]struct{}) (string, bool) {
	for _, ext := range c.CertificateExtensions {
		candidate := artifactPath + ext
		if _, ok := fileSet[candidate]; ok {
			return candidate, true
		}
	}
	return "", false
}

// processCertSignaturePair verifies a cosign-style keyless detached signature:
// an artifact, its raw signature and the Fulcio certificate used to sign it.
//
// The Fulcio certificate is short-lived, so verifying it requires the signing
// time, which is not present in the detached files. That signing time lives in
// the Rekor transparency log, so the entry is fetched and folded into a
// reconstructed sigstore bundle, which is then verified through the same path
// used for inline bundles. On success a virtual signature attestation exposing
// the signer identity is returned.
func (c *Collector) processCertSignaturePair(ctx context.Context, artifactPath, certPath string, sigData []byte, opts attestation.FetchOptions) []attestation.Envelope {
	certData, err := fs.ReadFile(c.FS, certPath)
	if err != nil {
		logrus.Debugf("reading certificate %s: %v", certPath, err)
		return nil
	}
	certDER, err := decodeCertificatePEM(certData)
	if err != nil {
		logrus.Debugf("decoding certificate %s: %v", certPath, err)
		return nil
	}

	artifactData, err := fs.ReadFile(c.FS, artifactPath)
	if err != nil {
		logrus.Debugf("reading artifact %s: %v", artifactPath, err)
		return nil
	}
	digest := sha256.Sum256(artifactData)

	// Look up the transparency-log entries recording this artifact digest so
	// the reconstructed bundle carries an observer timestamp.
	tlogs, err := c.fetchRekorTlogEntries(ctx, hex.EncodeToString(digest[:]))
	if err != nil {
		logrus.Debugf("fetching rekor entries for %s: %v", artifactPath, err)
		return nil
	}

	// Try each candidate entry: a successful verification confirms the entry
	// corresponds to this certificate and signature.
	sigBytes := decodeSignature(sigData)
	for _, tlog := range tlogs {
		bundle := buildDetachedBundle(certDER, sigBytes, digest[:], tlog)
		verification, err := c.verifySigstoreBundle(bundle)
		if err != nil {
			logrus.Debugf("verifying detached signature for %s: %v", artifactPath, err)
			continue
		}
		env, err := c.buildSigstoreVirtualAttestation(artifactPath, bundle, verification)
		if err != nil {
			logrus.Debugf("building virtual attestation for %s: %v", artifactPath, err)
			continue
		}
		envs := []attestation.Envelope{env}
		if opts.Query != nil {
			envs = opts.Query.Run(envs)
		}
		return envs
	}
	return nil
}

// fetchRekorTlogEntries searches the configured Rekor instance for entries
// recording the given artifact digest and converts each match into a
// transparency-log entry suitable for a sigstore bundle.
func (c *Collector) fetchRekorTlogEntries(ctx context.Context, digestHex string) ([]*protorekor.TransparencyLogEntry, error) {
	rekorURL := c.RekorURL
	if rekorURL == "" {
		rekorURL = defaultRekorURL
	}

	rc, err := rekorclient.GetRekorClient(rekorURL)
	if err != nil {
		return nil, fmt.Errorf("creating rekor client: %w", err)
	}

	res, err := rc.Index.SearchIndex(
		rekorindex.NewSearchIndexParamsWithContext(ctx).
			WithQuery(&rekormodels.SearchIndex{Hash: "sha256:" + digestHex}),
	)
	if err != nil {
		return nil, fmt.Errorf("searching rekor index: %w", err)
	}

	var tlogs []*protorekor.TransparencyLogEntry
	for _, uuid := range res.Payload {
		entry, err := rc.Entries.GetLogEntryByUUID(
			rekorentries.NewGetLogEntryByUUIDParamsWithContext(ctx).WithEntryUUID(uuid),
		)
		if err != nil {
			logrus.Debugf("fetching rekor entry %s: %v", uuid, err)
			continue
		}
		for _, anon := range entry.Payload {
			tlog, err := tle.GenerateTransparencyLogEntry(anon)
			if err != nil {
				logrus.Debugf("building tlog entry from %s: %v", uuid, err)
				continue
			}
			tlogs = append(tlogs, tlog)
		}
	}
	return tlogs, nil
}

// buildDetachedBundle assembles a sigstore bundle from the parts of a detached
// keyless signature so it can be verified through the standard bundle path.
func buildDetachedBundle(certDER, sigBytes, digest []byte, tlog *protorekor.TransparencyLogEntry) *sigstore.Bundle {
	return &sigstore.Bundle{
		MediaType: detachedBundleMediaType,
		VerificationMaterial: &sigstore.VerificationMaterial{
			Content: &sigstore.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: certDER},
			},
			TlogEntries: []*protorekor.TransparencyLogEntry{tlog},
		},
		Content: &sigstore.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    digest,
				},
				Signature: sigBytes,
			},
		},
	}
}

// decodeCertificatePEM returns the DER bytes of a certificate. It accepts a raw
// PEM certificate as well as a base64-wrapped PEM (some release pipelines
// publish the certificate base64-encoded).
func decodeCertificatePEM(data []byte) ([]byte, error) {
	pemData := data
	if block, _ := pem.Decode(data); block == nil {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); err == nil {
			pemData = decoded
		}
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM certificate block found")
	}
	return block.Bytes, nil
}

// decodeSignature returns the raw signature bytes. cosign writes detached
// signatures base64-encoded; data that is not valid base64 is assumed to be raw.
func decodeSignature(data []byte) []byte {
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); err == nil {
		return decoded
	}
	return data
}
