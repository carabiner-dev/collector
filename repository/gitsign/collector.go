// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package gitsign implements a collector that synthesizes virtual attestations
// from git commit signatures. It uses the gitsign library to extract an in-toto
// statement with predicate type https://gitsign.sigstore.dev/predicate/git/v0.1
// and then verifies the commit signature to populate the verification identity.
package gitsign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/carabiner-dev/attestation"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/key"
	signersigstore "github.com/carabiner-dev/signer/sigstore"
	"github.com/carabiner-dev/vcslocator"
	cms "github.com/github/smimesign/ietf-cms"
	"github.com/github/smimesign/ietf-cms/protocol"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/gitsign/pkg/attest"
	gspredicate "github.com/sigstore/gitsign/pkg/predicate"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	rekortypes "github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/carabiner-dev/collector/filters"
	"github.com/carabiner-dev/collector/predicate/generic"
	intotostatement "github.com/carabiner-dev/collector/statement/intoto"
)

var TypeMoniker = "gitsign"

// Build is the factory function registered with the collector agent.
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithInitString(istr))
}

var (
	_ attestation.Fetcher                = (*Collector)(nil)
	_ attestation.FetcherBySubject       = (*Collector)(nil)
	_ attestation.FetcherByPredicateType = (*Collector)(nil)
)

// oidRekorTransparencyLogEntry is the OID under which gitsign embeds a serialized
// Rekor TransparencyLogEntry proto in the CMS unsigned attributes when signing in
// offline mode (see gitsign internal/rekor/oid). Its presence is what distinguishes
// an offline-verifiable commit from an online-mode one.
var oidRekorTransparencyLogEntry = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 3, 1}

type Collector struct {
	Options Options
	Keys    []key.PublicKeyProvider

	// trustedRoot caches the resolved sigstore trust root so it is loaded once and
	// reused across every commit/tag verification.
	trustedRootOnce sync.Once
	trustedRoot     *root.TrustedRoot
	trustedRootErr  error
}

// trusted resolves and caches the sigstore public-good trust root from the
// signer library (an embedded snapshot with a TUF-refresh fallback), loaded
// once and reused across every commit/tag verification.
func (c *Collector) trusted() (*root.TrustedRoot, error) {
	c.trustedRootOnce.Do(func() {
		c.trustedRoot, c.trustedRootErr = signersigstore.TrustedRoot()
	})
	return c.trustedRoot, c.trustedRootErr
}

// defaultRekorURL is the sigstore public-good transparency log, queried for the
// online-mode Rekor lookup when a signature carries no embedded entry.
const defaultRekorURL = "https://rekor.sigstore.dev"

type Options struct {
	// Locator is the raw init string. It is parsed as a vcslocator for
	// remote repositories or treated as a local path.
	Locator string

	// Remote is the git remote name used to populate the subject name.
	Remote string

	// RekorURL is the transparency log queried when verifying online-mode
	// signatures (those without an embedded Rekor entry). Defaults to the
	// sigstore public-good instance.
	RekorURL string
}

var defaultOptions = Options{
	Remote:   "origin",
	RekorURL: defaultRekorURL,
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

// WithRekorURL sets the transparency log used for the online-mode Rekor lookup.
func WithRekorURL(url string) optFn {
	return func(c *Collector) error {
		c.Options.RekorURL = url
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
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
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
		env, err = c.buildVirtualTagAttestation(ctx, repo, components.Tag)
		if err != nil {
			logrus.Debugf("gitsign: skipping tag %s: %v", components.Tag, err)
			return []attestation.Envelope{}, nil
		}
	} else {
		env, err = c.buildVirtualAttestation(ctx, repo, components.Commit)
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

// FetchByPredicateType returns attestations only if the requested predicate
// types include a gitsign type. This avoids unnecessary work when the caller
// is looking for unrelated predicate types.
func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, types []attestation.PredicateType) ([]attestation.Envelope, error) {
	match := false
	for _, t := range types {
		if t == attestation.PredicateType(gspredicate.TypeV01) || t == attestation.PredicateType(gspredicate.TagTypeV01) {
			match = true
			break
		}
	}
	if !match {
		return nil, nil
	}

	envs, err := c.Fetch(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Filter to only the requested predicate types.
	typeSet := make(map[attestation.PredicateType]struct{}, len(types))
	for _, t := range types {
		typeSet[t] = struct{}{}
	}

	ret := make([]attestation.Envelope, 0, len(envs))
	for _, env := range envs {
		if p := env.GetPredicate(); p != nil {
			if _, ok := typeSet[p.GetType()]; ok {
				ret = append(ret, env)
			}
		}
	}

	return ret, nil
}

// FetchBySubject looks for sha1 or gitCommit digest algorithms in the
// requested subjects, generates a gitsign virtual attestation for each
// matching commit, and returns them.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
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
		env, err := c.buildVirtualAttestation(ctx, repo, hash)
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
		path, err = vcslocator.Locator(c.Options.Locator).LocalPath()
		if err != nil {
			return nil, fmt.Errorf("resolving local path: %w", err)
		}
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
func (c *Collector) buildVirtualAttestation(ctx context.Context, repo *gogit.Repository, commitHash string) (attestation.Envelope, error) {
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

	verification := c.extractVerification(ctx, commit)

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
func (c *Collector) buildVirtualTagAttestation(ctx context.Context, repo *gogit.Repository, tagName string) (attestation.Envelope, error) {
	stmt, err := attest.TagStatement(repo, c.Options.Remote, tagName)
	if err != nil {
		return nil, fmt.Errorf("generating tag statement: %w", err)
	}

	predData, err := protojson.Marshal(stmt.GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate: %w", err)
	}

	pred := &generic.Predicate{
		Type: attestation.PredicateType(gspredicate.TagTypeV01),
		Data: predData,
	}

	// Extract verification from the tag's signature.
	ref, err := repo.Tag(tagName)
	if err != nil {
		return nil, err
	}
	tagObj, err := repo.TagObject(ref.Hash())
	if err == nil && tagObj.PGPSignature != "" {
		verification := c.extractTagVerification(ctx, tagObj)
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
func (c *Collector) extractTagVerification(ctx context.Context, tagObj *object.Tag) *sapi.Verification {
	if tagObj.PGPSignature == "" {
		return nil
	}

	// Try CMS/sigstore signature first (PEM-encoded "SIGNED MESSAGE").
	if block, _ := pem.Decode([]byte(tagObj.PGPSignature)); block != nil {
		signedData, err := encodeWithoutSignature(tagObj)
		if err != nil {
			logrus.Debugf("gitsign: encoding tag without signature: %v", err)
			return nil
		}
		v, err := c.verifySigstoreSignature(ctx, signedData, block.Bytes)
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
func (c *Collector) extractVerification(ctx context.Context, commit *object.Commit) *sapi.Verification {
	if commit.PGPSignature == "" {
		return nil
	}

	// Try CMS/sigstore signature first (PEM-encoded "SIGNED MESSAGE").
	if block, _ := pem.Decode([]byte(commit.PGPSignature)); block != nil {
		signedData, err := encodeWithoutSignature(commit)
		if err != nil {
			logrus.Debugf("gitsign: encoding commit without signature: %v", err)
			return nil
		}
		v, err := c.verifySigstoreSignature(ctx, signedData, block.Bytes)
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

// signedObject is implemented by go-git commits and tags; it yields the exact
// bytes the CMS signature was computed over.
type signedObject interface {
	EncodeWithoutSignature(plumbing.EncodedObject) error
}

// encodeWithoutSignature returns the canonical bytes the detached CMS signature
// covers (the commit/tag object serialized without its signature header).
func encodeWithoutSignature(obj signedObject) ([]byte, error) {
	enc := &plumbing.MemoryObject{}
	if err := obj.EncodeWithoutSignature(enc); err != nil {
		return nil, fmt.Errorf("encoding object without signature: %w", err)
	}
	reader, err := enc.Reader()
	if err != nil {
		return nil, fmt.Errorf("reading encoded object: %w", err)
	}
	return io.ReadAll(reader)
}

// verifySigstoreSignature performs full, cosign-free cryptographic verification of
// a gitsign CMS/PKCS7 signature. It handles both gitsign signing modes:
//   - Offline mode: the signature embeds the Rekor transparency log entry, verified
//     entirely against the embedded trust root with zero network.
//   - Online mode: the signature carries no embedded entry, so the entry is looked
//     up in Rekor and then verified through the exact same offline path. The network
//     is used only to fetch the entry; its inclusion proof and SET are still checked
//     against the embedded trust root. A lookup that finds nothing, errors, or yields
//     no matching entry fails closed (nil, error).
//
// When it returns a non-nil Verification with Verified:true, ALL of the following
// held, using only the embedded trust root for the cryptographic checks:
//  1. The CMS signature covers signedData and the leaf chains to a Fulcio CA.
//  2. The Rekor entry is included in the transparency log (inclusion proof + SET),
//     which also fixes the integrated (signing) time.
//  3. The leaf certificate was valid at signing time and carries a valid SCT.
func (c *Collector) verifySigstoreSignature(ctx context.Context, signedData, cmsRaw []byte) (*sapi.Verification, error) {
	// Parse the CMS with the protocol package to reach the raw SignerInfo (its
	// signature, signed attributes and the unsigned Rekor-entry attribute).
	ci, err := protocol.ParseContentInfo(cmsRaw)
	if err != nil {
		return nil, fmt.Errorf("parsing CMS content info: %w", err)
	}
	psd, err := ci.SignedDataContent()
	if err != nil {
		return nil, fmt.Errorf("getting signed data: %w", err)
	}
	if len(psd.SignerInfos) == 0 {
		return nil, errors.New("no signer info in CMS signature")
	}
	si := psd.SignerInfos[0]

	certs, err := psd.X509Certificates()
	if err != nil {
		return nil, fmt.Errorf("extracting certificates: %w", err)
	}
	leaf, err := si.FindCertificate(certs)
	if err != nil {
		return nil, fmt.Errorf("finding signer certificate: %w", err)
	}

	trustedRoot, err := c.trusted()
	if err != nil {
		return nil, fmt.Errorf("loading trust root: %w", err)
	}

	// Step 1: the CMS signature cryptographically covers signedData (via the
	// messageDigest signed attribute) and the leaf chains to Fulcio.
	if err := verifyCMSSignature(signedData, cmsRaw, leaf, trustedRoot); err != nil {
		return nil, fmt.Errorf("verifying CMS signature: %w", err)
	}

	// The Rekor hashedrekord records the SHA-256 of the DER-encoded CMS signed
	// attributes (exactly what gitsign hashes), signed by si.Signature. Recompute
	// that digest so the synthetic bundle matches what was logged.
	signedAttrs, err := si.SignedAttrs.MarshaledForVerification()
	if err != nil {
		return nil, fmt.Errorf("marshaling CMS signed attributes: %w", err)
	}
	digest := sha256.Sum256(signedAttrs)

	// Obtain the Rekor TransparencyLogEntry: from the embedded attribute (offline
	// mode) or, if absent, by looking it up in Rekor (online mode). Either way the
	// entry is verified below through the same offline path.
	entryProto, ok, err := extractTlogEntry(&si)
	if err != nil {
		return nil, fmt.Errorf("extracting embedded transparency log entry: %w", err)
	}
	if !ok {
		logrus.Debug("gitsign: signature has no embedded Rekor entry; looking it up online")
		entryProto, err = c.lookupTlogEntry(ctx, leaf, si.Signature, digest[:])
		if err != nil {
			return nil, fmt.Errorf("looking up transparency log entry: %w", err)
		}
	}

	return c.verifyEntry(ctx, leaf, si.Signature, digest[:], entryProto, trustedRoot)
}

// verifyEntry runs the shared verification path for a Rekor TransparencyLogEntry,
// regardless of whether it came from the embedded CMS attribute (offline mode) or a
// Rekor lookup (online mode). It rebuilds the hashedrekord bundle from the signature
// pieces, verifies transparency-log inclusion, then the leaf certificate validity and
// SCT — all against the embedded trust root with no network access — and finally
// summarizes the authenticated identity.
func (c *Collector) verifyEntry(ctx context.Context, leaf *x509.Certificate, signature, digest []byte, entryProto *rekorpb.TransparencyLogEntry, trustedRoot *root.TrustedRoot) (*sapi.Verification, error) {
	entity, err := buildTlogBundle(ctx, leaf, signature, digest, entryProto)
	if err != nil {
		return nil, fmt.Errorf("assembling verification bundle: %w", err)
	}

	// Step 2: transparency-log inclusion (offline). This also cross-checks the entry
	// against the bundle (signature, key and hashedrekord digest) and yields the
	// trusted integrated (signing) time from the inclusion promise / SET.
	timestamps, err := sgverify.VerifyTlogEntry(entity, trustedRoot, 1, true)
	if err != nil {
		return nil, fmt.Errorf("verifying transparency log entry: %w", err)
	}
	if len(timestamps) == 0 {
		return nil, errors.New("transparency log entry produced no trusted timestamp")
	}
	integratedTime := timestamps[0].Time

	// Step 3: leaf certificate validity at signing time + SCT.
	chains, err := sgverify.VerifyLeafCertificate(integratedTime, leaf, trustedRoot)
	if err != nil {
		return nil, fmt.Errorf("verifying leaf certificate: %w", err)
	}
	if err := sgverify.VerifySignedCertificateTimestamp(chains, 1, trustedRoot); err != nil {
		return nil, fmt.Errorf("verifying signed certificate timestamp: %w", err)
	}

	// Identity: the collector reports authenticated identity only; allowlist
	// matching is the caller's (AMPEL's) responsibility.
	summary, err := certificate.SummarizeCertificate(leaf)
	if err != nil {
		return nil, fmt.Errorf("summarizing certificate: %w", err)
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

// lookupTlogEntry performs the online-mode Rekor lookup: it reconstructs the exact
// hashedrekord body that gitsign would have logged for this signature, searches the
// transparency log by the artifact digest to obtain candidate entry UUIDs, fetches
// each candidate (with its inclusion proof and SET), and returns the one whose
// canonical body byte-matches ours converted to a TransparencyLogEntry proto. Byte
// equality is the honest match criterion: it is exactly what the inclusion proof
// commits to, so a non-matching entry could not pass the subsequent VerifyTlogEntry.
// It fails closed if the lookup errors or no candidate matches.
func (c *Collector) lookupTlogEntry(ctx context.Context, leaf *x509.Certificate, signature, digest []byte) (*rekorpb.TransparencyLogEntry, error) {
	ourBody, err := canonicalHashedRekordBody(ctx, leaf, signature, digest)
	if err != nil {
		return nil, fmt.Errorf("reconstructing hashedrekord body: %w", err)
	}

	rekorURL := c.Options.RekorURL
	if rekorURL == "" {
		rekorURL = defaultRekorURL
	}
	client, err := rekorclient.GetRekorClient(rekorURL)
	if err != nil {
		return nil, fmt.Errorf("creating rekor client: %w", err)
	}

	// Search the log index by the artifact digest (the hashedrekord data.hash).
	searchParams := index.NewSearchIndexParams().
		WithContext(ctx).
		WithQuery(&models.SearchIndex{Hash: "sha256:" + hex.EncodeToString(digest)})
	searchResp, err := client.Index.SearchIndex(searchParams)
	if err != nil {
		return nil, fmt.Errorf("searching rekor index: %w", err)
	}
	uuids := searchResp.GetPayload()
	if len(uuids) == 0 {
		return nil, errors.New("no rekor entry found for signature")
	}

	for _, uuid := range uuids {
		getParams := entries.NewGetLogEntryByUUIDParams().
			WithContext(ctx).
			WithEntryUUID(uuid)
		entryResp, err := client.Entries.GetLogEntryByUUID(getParams)
		if err != nil {
			logrus.Debugf("gitsign: fetching rekor entry %s: %v", uuid, err)
			continue
		}
		for _, anon := range entryResp.GetPayload() {
			body, ok := decodeEntryBody(anon)
			if !ok || !bytes.Equal(body, ourBody) {
				continue
			}
			tle, err := logEntryToProto(&anon, body)
			if err != nil {
				return nil, fmt.Errorf("converting rekor entry: %w", err)
			}
			return tle, nil
		}
	}
	return nil, errors.New("no matching rekor entry for signature")
}

// decodeEntryBody base64-decodes the canonical body carried by a fetched Rekor entry.
func decodeEntryBody(anon models.LogEntryAnon) ([]byte, bool) {
	s, ok := anon.Body.(string)
	if !ok {
		return nil, false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// logEntryToProto converts a Rekor models.LogEntryAnon (as returned by
// GetLogEntryByUUID, with its inclusion proof and SET) into the *rekorpb.
// TransparencyLogEntry that VerifyTlogEntry consumes offline. It is hand-rolled
// rather than using sigstore-go's tlog.NewEntry because NewEntry reuses the entry's
// global log index for the inclusion proof's log index; those differ on a sharded log
// (as in the gitsign fixture: entry index 22784639 vs proof leaf index 18621208),
// which would break inclusion verification. Here the two indices are kept distinct.
func logEntryToProto(anon *models.LogEntryAnon, body []byte) (*rekorpb.TransparencyLogEntry, error) {
	if anon.LogID == nil || anon.LogIndex == nil || anon.IntegratedTime == nil {
		return nil, errors.New("rekor log entry missing required fields")
	}
	if anon.Verification == nil {
		return nil, errors.New("rekor log entry missing verification material")
	}
	set := []byte(anon.Verification.SignedEntryTimestamp)
	if len(set) == 0 {
		return nil, errors.New("rekor log entry missing signed entry timestamp")
	}
	ip := anon.Verification.InclusionProof
	if ip == nil || ip.LogIndex == nil || ip.RootHash == nil || ip.TreeSize == nil || ip.Checkpoint == nil {
		return nil, errors.New("rekor log entry missing inclusion proof")
	}

	logID, err := hex.DecodeString(*anon.LogID)
	if err != nil {
		return nil, fmt.Errorf("decoding rekor log ID: %w", err)
	}
	rootHash, err := hex.DecodeString(*ip.RootHash)
	if err != nil {
		return nil, fmt.Errorf("decoding inclusion proof root hash: %w", err)
	}
	hashes := make([][]byte, len(ip.Hashes))
	for i, h := range ip.Hashes {
		hashes[i], err = hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("decoding inclusion proof hash: %w", err)
		}
	}

	return &rekorpb.TransparencyLogEntry{
		LogIndex: *anon.LogIndex,
		LogId:    &protocommon.LogId{KeyId: logID},
		KindVersion: &rekorpb.KindVersion{
			Kind:    hashedrekord.KIND,
			Version: hashedrekord_v001.APIVERSION,
		},
		IntegratedTime:   *anon.IntegratedTime,
		InclusionPromise: &rekorpb.InclusionPromise{SignedEntryTimestamp: set},
		InclusionProof: &rekorpb.InclusionProof{
			LogIndex:   *ip.LogIndex,
			RootHash:   rootHash,
			TreeSize:   *ip.TreeSize,
			Hashes:     hashes,
			Checkpoint: &rekorpb.Checkpoint{Envelope: *ip.Checkpoint},
		},
		CanonicalizedBody: body,
	}, nil
}

// extractTlogEntry pulls the serialized Rekor TransparencyLogEntry proto out of the
// CMS unsigned attributes (offline mode). It returns ok=false when the attribute is
// absent (online mode); a malformed attribute is an error.
func extractTlogEntry(si *protocol.SignerInfo) (*rekorpb.TransparencyLogEntry, bool, error) {
	if !si.UnsignedAttrs.HasAttribute(oidRekorTransparencyLogEntry) {
		return nil, false, nil
	}
	rv, err := si.UnsignedAttrs.GetOnlyAttributeValueBytes(oidRekorTransparencyLogEntry)
	if err != nil {
		return nil, false, fmt.Errorf("reading tlog attribute: %w", err)
	}
	var protoBytes []byte
	if _, err := asn1.Unmarshal(rv.FullBytes, &protoBytes); err != nil {
		return nil, false, fmt.Errorf("asn1-decoding tlog attribute: %w", err)
	}
	pb := new(rekorpb.TransparencyLogEntry)
	if err := proto.Unmarshal(protoBytes, pb); err != nil {
		return nil, false, fmt.Errorf("unmarshaling TransparencyLogEntry: %w", err)
	}
	return pb, true, nil
}

// verifyCMSSignature checks that the detached CMS signature covers signedData and
// that the signer certificate chains to a Fulcio CA in the trust root. It mirrors
// gitsign's own pkg/git.CertVerifier, including the "cosign hack" of pinning the
// verification time to the leaf's NotBefore (the transparency log establishes the
// real signing time separately).
func verifyCMSSignature(signedData, cmsRaw []byte, leaf *x509.Certificate, trustedRoot *root.TrustedRoot) error {
	sd, err := cms.ParseSignedData(cmsRaw)
	if err != nil {
		return fmt.Errorf("parsing CMS: %w", err)
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for _, ca := range trustedRoot.FulcioCertificateAuthorities() {
		fca, ok := ca.(*root.FulcioCertificateAuthority)
		if !ok {
			continue
		}
		if fca.Root != nil {
			roots.AddCert(fca.Root)
		}
		for _, intermediate := range fca.Intermediates {
			intermediates.AddCert(intermediate)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// cosign hack: ignore the current time and pin to the cert's validity
		// window; the tlog inclusion proof establishes the true signing time.
		CurrentTime: leaf.NotBefore.Add(1 * time.Minute),
	}
	if _, err := sd.VerifyDetached(signedData, opts); err != nil {
		return fmt.Errorf("verifying detached signature: %w", err)
	}
	return nil
}

// canonicalHashedRekordBody reconstructs the exact canonical Rekor hashedrekord body
// gitsign logs for a signature: data.hash = the given digest (SHA-256 of the CMS
// signed attributes), signature = si.Signature, public key = the leaf cert PEM. Both
// the offline bundle assembly and the online lookup rely on this being byte-identical
// to what Rekor stored. CanonicalizeEntry additionally verifies that the signature
// validates over the digest with the leaf's public key, so a body that does not
// correspond to the leaf + signature cannot be reconstructed.
func canonicalHashedRekordBody(ctx context.Context, leaf *x509.Certificate, signature, digest []byte) ([]byte, error) {
	certPEM, err := cryptoutils.MarshalCertificateToPEM(leaf)
	if err != nil {
		return nil, fmt.Errorf("marshaling certificate to PEM: %w", err)
	}

	rekorEntry := &hashedrekord_v001.V001Entry{
		HashedRekordObj: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: conv.Pointer("sha256"),
					Value:     conv.Pointer(hex.EncodeToString(digest)),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: strfmt.Base64(signature),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(certPEM),
				},
			},
		},
	}
	body, err := rekortypes.CanonicalizeEntry(ctx, rekorEntry)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing rekor entry: %w", err)
	}
	return body, nil
}

// buildTlogBundle synthesizes the sigstore-go SignedEntity that VerifyTlogEntry
// consumes. It clones the TransparencyLogEntry (embedded or looked up) and attaches
// the canonical hashedrekord body rebuilt from the signature pieces, matching gitsign
// internal/rekor/oid.ToLogEntry.
//
// The bundle's MessageSignature carries the SAME digest and signature that the
// hashedrekord records, so VerifyTlogEntry's equality checks (entry.Signature ==
// bundle signature, key match, hashedrekord digest == message digest) are satisfied
// honestly: rebuilding the body with any other digest/signature would fail the
// inclusion-proof/SET check, and a bundle digest that diverged from the entry would
// fail the explicit equality check.
func buildTlogBundle(ctx context.Context, leaf *x509.Certificate, signature, digest []byte, entryProto *rekorpb.TransparencyLogEntry) (*sgbundle.Bundle, error) {
	body, err := canonicalHashedRekordBody(ctx, leaf, signature, digest)
	if err != nil {
		return nil, err
	}

	entry, ok := proto.Clone(entryProto).(*rekorpb.TransparencyLogEntry)
	if !ok {
		return nil, errors.New("cloning transparency log entry")
	}
	entry.CanonicalizedBody = body

	// v0.1 bundles require an inclusion promise; v0.2+ require an inclusion proof.
	// Pick the media type that matches what the embedded entry actually carries.
	mediaType := "application/vnd.dev.sigstore.bundle.v0.1+json"
	if entry.GetInclusionProof() != nil {
		mediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	}

	pb := &protobundle.Bundle{
		MediaType: mediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: leaf.Raw},
			},
			TlogEntries: []*rekorpb.TransparencyLogEntry{entry},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    digest,
				},
				Signature: signature,
			},
		},
	}
	return sgbundle.NewBundle(pb)
}

// verifyPGPSignature verifies a PGP commit signature against configured keys.
func (c *Collector) verifyPGPSignature(commit *object.Commit) (*sapi.Verification, error) {
	if len(c.Keys) == 0 {
		return nil, errors.New("no keys configured for PGP verification")
	}

	// Get the signed data (commit content without signature).
	buf, err := encodeWithoutSignature(commit)
	if err != nil {
		return nil, err
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
