// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/hasher"
	"github.com/carabiner-dev/signer"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/signer/options"
	sigstore "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/carabiner-dev/collector/envelope"
	"github.com/carabiner-dev/collector/predicate/generic"
	"github.com/carabiner-dev/collector/statement/intoto"
)

// SignaturePredicateType is the predicate type for virtual signature attestations.
const SignaturePredicateType = attestation.PredicateType("https://carabiner.dev/ampel/signature/v1")

// defaultSignatureExtensions lists recognized signature file extensions.
// Longest suffixes come first to handle multi-part extensions correctly.
var defaultSignatureExtensions = []string{".sigstore.json", ".sig", ".gpg", ".asc"}

// getSignatureExtension returns the matching signature extension suffix
// for a path, or empty string if none matches. Checks longest suffixes
// first to handle multi-part extensions correctly.
func getSignatureExtension(path string, extensions []string) string {
	for _, ext := range extensions {
		if strings.HasSuffix(path, ext) {
			return ext
		}
	}
	return ""
}

// isSignaturePairFile returns true if the file has a recognized signature
// extension AND the companion artifact file exists in the filesystem.
func (c *Collector) isSignaturePairFile(path string) bool {
	ext := getSignatureExtension(path, c.SignatureExtensions)
	if ext == "" {
		return false
	}
	artifactPath := strings.TrimSuffix(path, ext)
	_, err := fs.Stat(c.FS, artifactPath)
	return err == nil
}

// processSignaturePairs identifies signature pairs from the collected file
// list and processes them. For each pair, it first tries to parse the
// signature file as a normal attestation. If that succeeds, it uses the
// parsed attestation. Otherwise, it attempts verification and generates
// a virtual attestation.
func (c *Collector) processSignaturePairs(allFiles []string, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	// Build a set for O(1) lookup
	fileSet := make(map[string]struct{}, len(allFiles))
	for _, f := range allFiles {
		fileSet[f] = struct{}{}
	}

	var ret []attestation.Envelope

	for _, path := range allFiles {
		ext := getSignatureExtension(path, c.SignatureExtensions)
		if ext == "" {
			continue
		}

		artifactPath := strings.TrimSuffix(path, ext)
		if _, ok := fileSet[artifactPath]; !ok {
			continue
		}

		// Read the signature file
		sigData, err := fs.ReadFile(c.FS, path)
		if err != nil {
			logrus.Debugf("reading signature file %s: %v", path, err)
			continue
		}

		// Try to parse as a normal attestation (DSSE/bundle)
		parsed, err := envelope.Parsers.Parse(bytes.NewReader(sigData))
		if err == nil && len(parsed) > 0 {
			if opts.Query != nil {
				parsed = opts.Query.Run(parsed)
			}
			ret = append(ret, parsed...)
			continue
		}

		// Parsing failed — try to verify as a raw signature and generate
		// a virtual attestation
		verification, err := c.verifySignature(artifactPath, sigData)
		if err != nil {
			logrus.Debugf("verifying signature for %s: %v", artifactPath, err)
			continue
		}

		env, err := c.buildVirtualAttestation(artifactPath, verification)
		if err != nil {
			logrus.Debugf("building virtual attestation for %s: %v", artifactPath, err)
			continue
		}

		envs := []attestation.Envelope{env}
		if opts.Query != nil {
			envs = opts.Query.Run(envs)
		}
		ret = append(ret, envs...)
	}

	return ret, nil
}

// verifySignature attempts to verify a detached signature. It first tries
// sigstore bundle verification, then falls back to known key verification.
func (c *Collector) verifySignature(artifactPath string, sigData []byte) (*sapi.Verification, error) {
	// Try sigstore bundle verification first
	verification, err := c.verifySigstoreSignature(artifactPath, sigData)
	if err == nil {
		return verification, nil
	}
	logrus.Debugf("sigstore verification failed for %s: %v", artifactPath, err)

	// Fallback: try known keys
	return c.verifyWithKeys(artifactPath, sigData)
}

// verifySigstoreSignature tries to parse sigData as a sigstore bundle
// and verify it against the artifact.
func (c *Collector) verifySigstoreSignature(artifactPath string, sigData []byte) (*sapi.Verification, error) {
	var bundle sigstore.Bundle
	if err := protojson.Unmarshal(sigData, &bundle); err != nil {
		return nil, fmt.Errorf("parsing sigstore bundle: %w", err)
	}

	// If it has a messageSignature, verify the digest matches the artifact
	if ms := bundle.GetMessageSignature(); ms != nil {
		if err := c.verifyMessageDigest(artifactPath, ms); err != nil {
			return nil, fmt.Errorf("digest mismatch: %w", err)
		}
	}

	// Verify the bundle
	verifier := signer.NewVerifier()
	verifier.Options.SkipIdentityCheck = true

	if _, err := verifier.VerifyParsedBundle(
		&sgbundle.Bundle{Bundle: &bundle},
		options.WithSkipIdentityCheck(true),
	); err != nil {
		return nil, fmt.Errorf("verifying sigstore bundle: %w", err)
	}

	// Extract identity from certificate
	return c.extractSigstoreIdentity(&bundle)
}

// verifyMessageDigest checks that the bundle's message digest matches the
// companion artifact's hash.
func (c *Collector) verifyMessageDigest(artifactPath string, ms *protocommon.MessageSignature) error {
	md := ms.GetMessageDigest()
	if md == nil {
		return nil // No digest to check
	}

	artifactData, err := fs.ReadFile(c.FS, artifactPath)
	if err != nil {
		return fmt.Errorf("reading artifact: %w", err)
	}

	hsets, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(artifactData)})
	if err != nil {
		return fmt.Errorf("hashing artifact: %w", err)
	}

	rds := hsets.ToResourceDescriptors()
	if len(rds) == 0 {
		return fmt.Errorf("no hash computed for artifact")
	}

	// Map the sigstore hash algorithm to a digest string for comparison
	algName := strings.ToLower(strings.TrimPrefix(md.GetAlgorithm().String(), "HASH_ALGORITHM_"))
	bundleDigest := fmt.Sprintf("%x", md.GetDigest())

	rd := rds[0]
	if artifactDigest, ok := rd.Digest[algName]; ok {
		if artifactDigest != bundleDigest {
			return fmt.Errorf("digest mismatch: bundle=%s artifact=%s", bundleDigest, artifactDigest)
		}
		return nil
	}

	return fmt.Errorf("hash algorithm %s not found in artifact digests", algName)
}

// extractSigstoreIdentity extracts the signing identity from the sigstore
// bundle's certificate.
func (c *Collector) extractSigstoreIdentity(bundle *sigstore.Bundle) (*sapi.Verification, error) {
	if bundle.GetVerificationMaterial() == nil {
		return nil, fmt.Errorf("no verification material in bundle")
	}

	var cert *protocommon.X509Certificate
	if c := bundle.GetVerificationMaterial().GetCertificate(); c != nil {
		cert = c
	}
	if chain := bundle.GetVerificationMaterial().GetX509CertificateChain(); cert == nil && chain != nil && len(chain.GetCertificates()) > 0 {
		cert = chain.GetCertificates()[0]
	}
	if cert == nil {
		return nil, fmt.Errorf("no certificate found in bundle")
	}

	x509cert, err := x509.ParseCertificate(cert.GetRawBytes())
	if err != nil {
		return nil, fmt.Errorf("parsing cert: %w", err)
	}

	summary, err := certificate.SummarizeCertificate(x509cert)
	if err != nil {
		return nil, fmt.Errorf("summarizing cert: %w", err)
	}

	return &sapi.Verification{
		Signature: &sapi.SignatureVerification{
			Date:     timestamppb.Now(),
			Verified: true,
			Identities: []*sapi.Identity{
				{
					Sigstore: &sapi.IdentitySigstore{
						Issuer:   summary.Issuer,
						Identity: summary.SubjectAlternativeName,
					},
				},
			},
		},
	}, nil
}

// verifyWithKeys attempts to verify the raw signature against the artifact
// using the collector's configured keys.
func (c *Collector) verifyWithKeys(artifactPath string, sigData []byte) (*sapi.Verification, error) {
	if len(c.Keys) == 0 {
		return nil, fmt.Errorf("no keys configured for verification")
	}

	artifactContent, err := fs.ReadFile(c.FS, artifactPath)
	if err != nil {
		return nil, fmt.Errorf("reading artifact: %w", err)
	}

	verifier := key.NewVerifier()
	var identities []*sapi.Identity

	for _, pkp := range c.Keys {
		verified, err := verifier.VerifyMessage(pkp, artifactContent, sigData)
		if err != nil {
			logrus.Debugf("key verification error: %v", err)
			continue
		}
		if !verified {
			continue
		}

		pub, err := pkp.PublicKey()
		if err != nil {
			continue
		}

		identities = append(identities, &sapi.Identity{
			Key: &sapi.IdentityKey{
				Id:   pub.ID(),
				Type: string(pub.Scheme),
				Data: pub.Data,
			},
		})
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("no key verified the signature")
	}

	return &sapi.Verification{
		Signature: &sapi.SignatureVerification{
			Date:       timestamppb.Now(),
			Verified:   true,
			Identities: identities,
		},
	}, nil
}

// buildVirtualAttestation creates a virtual attestation envelope for a
// verified detached signature.
func (c *Collector) buildVirtualAttestation(artifactPath string, verification *sapi.Verification) (attestation.Envelope, error) {
	artifactData, err := fs.ReadFile(c.FS, artifactPath)
	if err != nil {
		return nil, fmt.Errorf("reading artifact: %w", err)
	}

	hsets, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(artifactData)})
	if err != nil {
		return nil, fmt.Errorf("hashing artifact: %w", err)
	}

	rds := hsets.ToResourceDescriptors()
	if len(rds) == 0 {
		return nil, fmt.Errorf("no hash computed for artifact")
	}

	rd := rds[0]
	rd.Name = filepath.Base(artifactPath)

	pred := &generic.Predicate{
		Type:         SignaturePredicateType,
		Data:         []byte("{}"),
		Verification: verification,
	}

	stmt := intoto.NewStatement(
		intoto.WithPredicate(pred),
		intoto.WithSubject(rd),
	)

	return &virtualEnvelope{statement: stmt}, nil
}

// virtualEnvelope implements attestation.Envelope for virtual signature
// attestations. Unlike bare.Envelope, it delegates GetVerification
// through the statement chain.
type virtualEnvelope struct {
	statement attestation.Statement
}

var _ attestation.Envelope = (*virtualEnvelope)(nil)

func (e *virtualEnvelope) GetStatement() attestation.Statement {
	return e.statement
}

func (e *virtualEnvelope) GetPredicate() attestation.Predicate {
	if s := e.GetStatement(); s != nil {
		return s.GetPredicate()
	}
	return nil
}

func (e *virtualEnvelope) GetVerification() attestation.Verification {
	if s := e.GetStatement(); s != nil {
		return s.GetVerification()
	}
	return nil
}

func (e *virtualEnvelope) GetSignatures() []attestation.Signature {
	return nil
}

func (e *virtualEnvelope) GetCertificate() attestation.Certificate {
	return nil
}

func (e *virtualEnvelope) Verify(_ ...any) error {
	return nil
}
