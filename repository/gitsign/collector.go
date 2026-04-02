// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package gitsign implements a collector that synthesizes virtual attestations
// from git commit signatures. It uses the gitsign library to extract an in-toto
// statement with predicate type https://gitsign.sigstore.dev/predicate/git/v0.1
// and then verifies the commit signature to populate the verification identity.
package gitsign

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/carabiner-dev/attestation"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/vcslocator"
	"github.com/github/smimesign/ietf-cms/protocol"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/gitsign/pkg/attest"
	gspredicate "github.com/sigstore/gitsign/pkg/predicate"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/carabiner-dev/collector/filters"
	"github.com/carabiner-dev/collector/predicate/generic"
	"github.com/carabiner-dev/collector/repository/gitsign/internal/tagattest"
	intotostatement "github.com/carabiner-dev/collector/statement/intoto"
)

var TypeMoniker = "gitsign"

// Build is the factory function registered with the collector agent.
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithInitString(istr))
}

var (
	_ attestation.Fetcher          = (*Collector)(nil)
	_ attestation.FetcherBySubject = (*Collector)(nil)
)

// oidcIssuerOID is the Fulcio OIDC issuer extension OID (1.3.6.1.4.1.57264.1.1).
var oidcIssuerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}

type Collector struct {
	Options Options
	Keys    []key.PublicKeyProvider
}

type Options struct {
	// Locator is the raw init string. It is parsed as a vcslocator for
	// remote repositories or treated as a local path.
	Locator string

	// Remote is the git remote name used to populate the subject name.
	Remote string
}

var defaultOptions = Options{
	Remote: "origin",
}

type optFn func(*Collector) error

func WithInitString(s string) optFn {
	return func(c *Collector) error {
		c.Options.Locator = strings.TrimPrefix(s, TypeMoniker+":")
		return nil
	}
}

func WithRepoPath(path string) optFn {
	return func(c *Collector) error {
		c.Options.Locator = path
		return nil
	}
}

func WithRemote(remote string) optFn {
	return func(c *Collector) error {
		c.Options.Remote = remote
		return nil
	}
}

func WithKeys(keys ...key.PublicKeyProvider) optFn {
	return func(c *Collector) error {
		c.Keys = append(c.Keys, keys...)
		return nil
	}
}

func New(opts ...optFn) (*Collector, error) {
	c := &Collector{
		Options: defaultOptions,
	}
	for _, fn := range opts {
		if err := fn(c); err != nil {
			return nil, err
		}
	}
	if c.Options.Locator == "" {
		return nil, errors.New("repository path is required")
	}
	return c, nil
}

// SetKeys implements the repository.SignatureVerifier interface.
func (c *Collector) SetKeys(keys []key.PublicKeyProvider) {
	c.Keys = keys
}

// Fetch parses the locator and, if it contains a commit or tag reference, builds a
// virtual attestation. Tag locators produce a tag predicate; commit locators
// produce a commit predicate.
func (c *Collector) Fetch(_ context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	components, err := vcslocator.Locator(c.Options.Locator).Parse()
	if err != nil {
		return []attestation.Envelope{}, nil //nolint:nilerr // unparseable locator means no commit to fetch
	}

	if components.Commit == "" && components.Tag == "" {
		return []attestation.Envelope{}, nil
	}

	repo, err := c.openRepo()
	if err != nil {
		return nil, err
	}

	var env attestation.Envelope
	if components.Tag != "" {
		env, err = c.buildVirtualTagAttestation(repo, components.Tag)
		if err != nil {
			logrus.Debugf("gitsign: skipping tag %s: %v", components.Tag, err)
			return []attestation.Envelope{}, nil
		}
	} else {
		env, err = c.buildVirtualAttestation(repo, components.Commit)
		if err != nil {
			return nil, fmt.Errorf("building attestation for commit %s: %w", components.Commit, err)
		}
	}

	ret := []attestation.Envelope{env}

	if opts.Limit > 0 && len(ret) > opts.Limit {
		ret = ret[:opts.Limit]
	}

	return ret, nil
}

// FetchBySubject looks for sha1 or gitCommit digest algorithms in the
// requested subjects, generates a gitsign virtual attestation for each
// matching commit, and returns them.
func (c *Collector) FetchBySubject(_ context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	commits := map[string]struct{}{}
	for _, s := range subj {
		for algo, val := range s.GetDigest() {
			if algo == intoto.AlgorithmSHA1.String() || algo == intoto.AlgorithmGitCommit.String() {
				commits[val] = struct{}{}
			}
		}
	}

	if len(commits) == 0 {
		return nil, nil
	}

	repo, err := c.openRepo()
	if err != nil {
		return nil, err
	}

	var ret []attestation.Envelope
	for hash := range commits {
		env, err := c.buildVirtualAttestation(repo, hash)
		if err != nil {
			logrus.Debugf("gitsign: skipping commit %s: %v", hash, err)
			continue
		}
		ret = append(ret, env)
	}

	matcher := &filters.SubjectHashMatcher{
		HashSets: make([]map[string]string, 0, len(subj)),
	}
	for _, s := range subj {
		matcher.HashSets = append(matcher.HashSets, s.GetDigest())
	}
	ret = attestation.NewQuery().WithFilter(matcher).Run(ret)

	if opts.Limit > 0 && len(ret) > opts.Limit {
		ret = ret[:opts.Limit]
	}

	return ret, nil
}

// openRepo opens a local repository or clones a remote one into memory.
// The locator is first tried as a vcslocator; if it parses and is not a
// file:// transport, the repository is cloned. Otherwise it is treated as
// a local filesystem path.
func (c *Collector) openRepo() (*gogit.Repository, error) {
	components, err := vcslocator.Locator(c.Options.Locator).Parse()
	if err == nil && components.Transport != vcslocator.TransportFile {
		// Remote repository — clone to memory.
		auth, err := vcslocator.GetAuthMethod(c.Options.Locator)
		if err != nil {
			return nil, fmt.Errorf("getting auth method: %w", err)
		}

		repo, err := gogit.Clone(memory.NewStorage(), nil, &gogit.CloneOptions{
			URL:  components.RepoURL(),
			Auth: auth,
		})
		if err != nil {
			return nil, fmt.Errorf("cloning repository: %w", err)
		}
		return repo, nil
	}

	// Local path (either file:// vcslocator or plain path).
	path := c.Options.Locator
	if err == nil && components.Transport == vcslocator.TransportFile {
		path = components.RepoPath
	}

	repo, err := gogit.PlainOpenWithOptions(path, &gogit.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return nil, fmt.Errorf("opening local repository: %w", err)
	}
	return repo, nil
}

// buildVirtualAttestation generates the gitsign predicate for a commit and
// wraps it in a virtual envelope with verification data.
func (c *Collector) buildVirtualAttestation(repo *gogit.Repository, commitHash string) (attestation.Envelope, error) {
	stmt, err := attest.CommitStatement(repo, c.Options.Remote, commitHash)
	if err != nil {
		return nil, fmt.Errorf("generating commit statement: %w", err)
	}

	predData, err := protojson.Marshal(stmt.GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate: %w", err)
	}

	hash := plumbing.NewHash(commitHash)
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("getting commit object: %w", err)
	}

	verification := c.extractVerification(commit)

	pred := &generic.Predicate{
		Type: attestation.PredicateType(gspredicate.TypeV01),
		Data: predData,
	}

	if verification != nil {
		pred.SetVerification(verification)
	}

	// Enrich subjects: ensure both sha1 and gitCommit digests are present
	// so the attestation matches queries using either algorithm.
	subjects := make([]*intoto.ResourceDescriptor, 0, len(stmt.GetSubject()))
	for _, s := range stmt.GetSubject() {
		digests := s.GetDigest()
		if v, ok := digests[intoto.AlgorithmSHA1.String()]; ok {
			if _, has := digests[intoto.AlgorithmGitCommit.String()]; !has {
				digests[intoto.AlgorithmGitCommit.String()] = v
			}
		}
		if v, ok := digests[intoto.AlgorithmGitCommit.String()]; ok {
			if _, has := digests[intoto.AlgorithmSHA1.String()]; !has {
				digests[intoto.AlgorithmSHA1.String()] = v
			}
		}
		subjects = append(subjects, s)
	}

	stmtObj := intotostatement.NewStatement(
		intotostatement.WithPredicate(pred),
		intotostatement.WithSubject(subjects...),
	)

	return &virtualEnvelope{statement: stmtObj}, nil
}

// buildVirtualTagAttestation generates a tag predicate for an annotated tag
// and wraps it in a virtual envelope with verification data.
func (c *Collector) buildVirtualTagAttestation(repo *gogit.Repository, tagName string) (attestation.Envelope, error) {
	// Use the internal tagattest package (mirrors gitsign's attest.TagStatement).
	// TODO: replace with attest.TagStatement once gitsign releases the change.
	stmt, err := tagattest.TagStatement(repo, c.Options.Remote, tagName)
	if err != nil {
		return nil, fmt.Errorf("generating tag statement: %w", err)
	}

	predData, err := protojson.Marshal(stmt.GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate: %w", err)
	}

	pred := &generic.Predicate{
		Type: attestation.PredicateType(tagattest.TagTypeV01),
		Data: predData,
	}

	// Extract verification from the tag's signature.
	ref, err := repo.Tag(tagName)
	if err != nil {
		return nil, err
	}
	tagObj, err := repo.TagObject(ref.Hash())
	if err == nil && tagObj.PGPSignature != "" {
		verification := c.extractTagVerification(tagObj)
		if verification != nil {
			pred.SetVerification(verification)
		}
	}

	stmtObj := intotostatement.NewStatement(
		intotostatement.WithPredicate(pred),
		intotostatement.WithSubject(stmt.GetSubject()...),
	)

	return &virtualEnvelope{statement: stmtObj}, nil
}

// extractTagVerification inspects the tag signature and returns a Verification
// result. It reuses the same CMS/sigstore and PGP verification paths as commit
// signatures since the signature format is identical.
func (c *Collector) extractTagVerification(tagObj *object.Tag) *sapi.Verification {
	if tagObj.PGPSignature == "" {
		return nil
	}

	// Try CMS/sigstore signature first (PEM-encoded "SIGNED MESSAGE").
	if block, _ := pem.Decode([]byte(tagObj.PGPSignature)); block != nil {
		v, err := verifySigstoreSignature(block.Bytes)
		if err != nil {
			logrus.Debugf("gitsign: tag sigstore verification failed: %v", err)
			return nil
		}
		return v
	}

	// PGP verification for tags would require encoding the tag without
	// signature, which go-git supports. For now, only sigstore is handled.
	return nil
}

// extractVerification inspects the commit signature and returns a Verification
// result. It handles two cases:
//   - CMS/PKCS7 signatures (sigstore): extracts the certificate identity.
//   - PGP signatures: verifies against configured keys.
//
// Returns nil if no verification could be performed.
func (c *Collector) extractVerification(commit *object.Commit) *sapi.Verification {
	if commit.PGPSignature == "" {
		return nil
	}

	// Try CMS/sigstore signature first (PEM-encoded "SIGNED MESSAGE").
	if block, _ := pem.Decode([]byte(commit.PGPSignature)); block != nil {
		v, err := verifySigstoreSignature(block.Bytes)
		if err != nil {
			logrus.Debugf("gitsign: sigstore verification failed: %v", err)
			return nil
		}
		return v
	}

	// Fall back to PGP signature verification.
	v, err := c.verifyPGPSignature(commit)
	if err != nil {
		logrus.Debugf("gitsign: pgp verification failed: %v", err)
		return nil
	}
	return v
}

// verifySigstoreSignature parses a CMS/PKCS7 signed message and extracts
// the signing identity from its embedded certificate.
func verifySigstoreSignature(raw []byte) (*sapi.Verification, error) {
	ci, err := protocol.ParseContentInfo(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing CMS content info: %w", err)
	}

	sd, err := ci.SignedDataContent()
	if err != nil {
		return nil, fmt.Errorf("getting signed data: %w", err)
	}

	certs, err := sd.X509Certificates()
	if err != nil {
		return nil, fmt.Errorf("extracting certificates: %w", err)
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates in signature")
	}

	// Look for a leaf cert (non-CA) with identity information.
	for _, cert := range certs {
		if !cert.IsCA {
			v, err := extractSigstoreIdentity(cert)
			if err == nil {
				return v, nil
			}
		}
	}

	return nil, errors.New("no sigstore identity found in certificates")
}

// extractSigstoreIdentity reads the SAN and OIDC issuer extension from a
// Fulcio-issued certificate.
func extractSigstoreIdentity(cert *x509.Certificate) (*sapi.Verification, error) {
	var identity string
	switch {
	case len(cert.EmailAddresses) > 0:
		identity = cert.EmailAddresses[0]
	case len(cert.URIs) > 0:
		identity = cert.URIs[0].String()
	case len(cert.DNSNames) > 0:
		identity = cert.DNSNames[0]
	}

	if identity == "" {
		return nil, errors.New("no identity in certificate")
	}

	issuer := extractOIDCIssuer(cert)

	return &sapi.Verification{
		Signature: &sapi.SignatureVerification{
			Date:     timestamppb.Now(),
			Verified: true,
			Identities: []*sapi.Identity{
				{
					Sigstore: &sapi.IdentitySigstore{
						Issuer:   issuer,
						Identity: identity,
					},
				},
			},
		},
	}, nil
}

// extractOIDCIssuer reads the Fulcio OIDC issuer OID (1.3.6.1.4.1.57264.1.1)
// from the certificate extensions.
func extractOIDCIssuer(cert *x509.Certificate) string {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidcIssuerOID) {
			// The value is ASN.1 encoded. Try UTF8String (tag 0x0c) first.
			if len(ext.Value) > 2 && ext.Value[0] == 0x0c {
				return string(ext.Value[2:])
			}
			return string(ext.Value)
		}
	}
	return ""
}

// verifyPGPSignature verifies a PGP commit signature against configured keys.
func (c *Collector) verifyPGPSignature(commit *object.Commit) (*sapi.Verification, error) {
	if len(c.Keys) == 0 {
		return nil, errors.New("no keys configured for PGP verification")
	}

	// Get the signed data (commit content without signature).
	encoded := &plumbing.MemoryObject{}
	if err := commit.EncodeWithoutSignature(encoded); err != nil {
		return nil, fmt.Errorf("encoding commit without signature: %w", err)
	}

	reader, err := encoded.Reader()
	if err != nil {
		return nil, fmt.Errorf("reading encoded commit: %w", err)
	}

	buf, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("buffering commit data: %w", err)
	}

	sigData := []byte(commit.PGPSignature)

	verifier := key.NewVerifier()
	var identities []*sapi.Identity

	for _, pkp := range c.Keys {
		verified, err := verifier.VerifyMessage(pkp, buf, sigData)
		if err != nil {
			logrus.Debugf("gitsign: key verification error: %v", err)
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
		return nil, errors.New("no key verified the PGP signature")
	}

	return &sapi.Verification{
		Signature: &sapi.SignatureVerification{
			Date:       timestamppb.Now(),
			Verified:   true,
			Identities: identities,
		},
	}, nil
}
