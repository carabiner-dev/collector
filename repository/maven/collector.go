// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package maven implements an attestation collector that fetches attestations
// from Maven repository directory listings. It looks for PGP signatures (.asc),
// JSONL attestation bundles, and unsigned SBOMs (.spdx.json, .cdx.json).
package maven

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/hasher"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/key"
	"google.golang.org/protobuf/types/known/timestamppb"
	"sigs.k8s.io/release-utils/http"

	"github.com/carabiner-dev/collector/envelope"
	"github.com/carabiner-dev/collector/filters"
	"github.com/carabiner-dev/collector/internal/readlimit"
	"github.com/carabiner-dev/collector/predicate/generic"
	"github.com/carabiner-dev/collector/repository/filesystem"
	"github.com/carabiner-dev/collector/statement/intoto"
)

var TypeMoniker = "maven"

// Build is the factory function used to register the collector.
// The init string is a maven purl, e.g. "pkg:maven/com.aliyun/foo@1.0".
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithPackageURL(istr))
}

var (
	_ attestation.Fetcher                = (*Collector)(nil)
	_ attestation.FetcherBySubject       = (*Collector)(nil)
	_ attestation.FetcherByPredicateType = (*Collector)(nil)
)

// Collector fetches attestations from a Maven repository directory listing.
type Collector struct {
	Options Options
	Keys    []key.PublicKeyProvider
}

// New creates a new Maven collector.
func New(funcs ...optFn) (*Collector, error) {
	c := &Collector{
		Options: defaultOptions,
	}
	for _, fn := range funcs {
		if err := fn(c); err != nil {
			return nil, err
		}
	}
	if err := c.Options.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}
	return c, nil
}

// SetKeys sets the verification keys on the collector.
func (c *Collector) SetKeys(keys []key.PublicKeyProvider) {
	c.Keys = keys
}

// Fetch retrieves attestations from the Maven repository directory.
func (c *Collector) Fetch(_ context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	dirURL := c.Options.directoryURL()

	// Fetch the directory listing HTML.
	agent := http.NewAgent().WithFailOnHTTPError(true)
	listingData, err := agent.Get(dirURL)
	if err != nil {
		return nil, fmt.Errorf("fetching directory listing from %s: %w", dirURL, err)
	}

	files := parseDirectoryListing(string(listingData))
	if len(files) == 0 {
		return nil, nil
	}

	baseName := c.Options.artifactBaseName()
	var ret []attestation.Envelope

	// 1. Look for the main jar's .asc signature.
	ascEnvs, err := c.fetchSignature(agent, dirURL, baseName, files, opts)
	if err != nil {
		return nil, err
	}
	ret = append(ret, ascEnvs...)

	// 2. Look for a .jsonl attestation bundle matching the main jar.
	jsonlEnvs, err := c.fetchJSONLAttestations(agent, dirURL, baseName, files, opts)
	if err != nil {
		return nil, err
	}
	ret = append(ret, jsonlEnvs...)

	// 3. Look for unsigned SBOMs (.spdx.json, .cdx.json).
	sbomEnvs, err := c.fetchSBOMs(agent, dirURL, baseName, files, opts)
	if err != nil {
		return nil, err
	}
	ret = append(ret, sbomEnvs...)

	if opts.Query != nil {
		ret = opts.Query.Run(ret)
	}

	if opts.Limit > 0 && len(ret) > opts.Limit {
		ret = ret[:opts.Limit]
	}

	return ret, nil
}

// FetchBySubject handles collecting by subject hash.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	all, err := c.Fetch(ctx, opts)
	if err != nil {
		return nil, err
	}

	m := make([]map[string]string, 0, len(subj))
	for _, s := range subj {
		m = append(m, s.GetDigest())
	}

	return attestation.NewQuery().WithFilter(&filters.SubjectHashMatcher{
		HashSets: m,
	}).Run(all), nil
}

// FetchByPredicateType handles collecting by predicate type.
func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	all, err := c.Fetch(ctx, opts)
	if err != nil {
		return nil, err
	}

	m := map[attestation.PredicateType]struct{}{}
	for _, pt := range pts {
		m[pt] = struct{}{}
	}

	return attestation.NewQuery().WithFilter(&filters.PredicateTypeMatcher{
		PredicateTypes: m,
	}).Run(all), nil
}

// fetchSignature looks for the main jar's .asc file in the listing,
// fetches both the jar and its signature, and verifies using loaded keys.
// Returns nil without error if the artifacts are not listed or no keys are configured.
func (c *Collector) fetchSignature(agent *http.Agent, dirURL, baseName string, files []string, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	jarFile := baseName + ".jar"
	ascFile := jarFile + ".asc"

	if !slices.Contains(files, ascFile) || !slices.Contains(files, jarFile) || len(c.Keys) == 0 {
		return nil, nil
	}

	maxSize := readlimit.Resolve(opts.MaxReadSize)

	// Fetch the jar and its signature in parallel.
	urls := []string{dirURL + jarFile, dirURL + ascFile}
	datas, errs := agent.GetGroup(urls)

	for i, e := range errs {
		if e != nil {
			return nil, fmt.Errorf("fetching %s: %w", urls[i], e)
		}
	}

	jarData, sigData := datas[0], datas[1]

	if int64(len(jarData)) > maxSize {
		return nil, fmt.Errorf("jar %s exceeds max read size (%d bytes)", jarFile, maxSize)
	}

	// Verify signature using loaded keys. Verification failure is not
	// a fetch error — the signature simply didn't match any loaded key.
	verification, verifyErr := verifyWithKeys(c.Keys, jarData, sigData)
	if verifyErr != nil {
		return nil, nil //nolint:nilerr // verification failure is not a fetch error
	}

	env, err := buildVirtualAttestation(jarFile, jarData, verification)
	if err != nil {
		return nil, fmt.Errorf("building signature attestation for %s: %w", jarFile, err)
	}

	return []attestation.Envelope{env}, nil
}

// fetchJSONLAttestations looks for a .jsonl file matching the main jar
// and parses it for attestation envelopes. Returns nil without error if not listed.
func (c *Collector) fetchJSONLAttestations(agent *http.Agent, dirURL, baseName string, files []string, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	jsonlFile := baseName + ".jsonl"
	if !slices.Contains(files, jsonlFile) {
		return nil, nil
	}

	maxSize := readlimit.Resolve(opts.MaxReadSize)
	data, err := agent.Get(dirURL + jsonlFile)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", jsonlFile, err)
	}

	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("JSONL file %s exceeds max read size (%d bytes)", jsonlFile, maxSize)
	}

	return envelope.NewJSONL().Parse(data)
}

// fetchSBOMs looks for unsigned SBOM files with .spdx.json or .cdx.json extensions.
// Returns nil without error if none are listed.
func (c *Collector) fetchSBOMs(agent *http.Agent, dirURL, baseName string, files []string, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	maxSize := readlimit.Resolve(opts.MaxReadSize)
	var ret []attestation.Envelope

	for _, suffix := range []string{".spdx.json", ".cdx.json"} {
		sbomFile := baseName + suffix
		if !slices.Contains(files, sbomFile) {
			continue
		}

		data, err := agent.Get(dirURL + sbomFile)
		if err != nil {
			return nil, fmt.Errorf("fetching SBOM %s: %w", sbomFile, err)
		}

		if int64(len(data)) > maxSize {
			return nil, fmt.Errorf("SBOM %s exceeds max read size (%d bytes)", sbomFile, maxSize)
		}

		envs, err := envelope.Parsers.Parse(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("parsing SBOM %s: %w", sbomFile, err)
		}

		ret = append(ret, envs...)
	}

	return ret, nil
}

// verifyWithKeys attempts to verify a raw signature against artifact data
// using the provided keys.
func verifyWithKeys(keys []key.PublicKeyProvider, artifactData, sigData []byte) (*sapi.Verification, error) {
	verifier := key.NewVerifier()
	var identities []*sapi.Identity

	for _, pkp := range keys {
		verified, err := verifier.VerifyMessage(pkp, artifactData, sigData)
		if err != nil {
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

// buildVirtualAttestation creates a predicate-less virtual attestation
// for a verified signature, hashing the artifact to form the subject.
func buildVirtualAttestation(artifactName string, artifactData []byte, verification *sapi.Verification) (attestation.Envelope, error) {
	hsets, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(artifactData)})
	if err != nil {
		return nil, fmt.Errorf("hashing artifact: %w", err)
	}

	rds := hsets.ToResourceDescriptors()
	if len(rds) == 0 {
		return nil, fmt.Errorf("no hash computed for artifact")
	}

	rd := rds[0]
	rd.Name = artifactName

	pred := &generic.Predicate{
		Type:         filesystem.SignaturePredicateType,
		Data:         []byte("{}"),
		Verification: verification,
	}

	stmt := intoto.NewStatement(
		intoto.WithPredicate(pred),
		intoto.WithSubject(rd),
	)

	return &virtualEnvelope{statement: stmt}, nil
}

// parseDirectoryListing extracts filenames from an HTML directory listing
// as served by Maven Central and Apache Nexus repositories.
// It looks for href attributes in anchor tags.
func parseDirectoryListing(html string) []string {
	var files []string
	rest := html
	for {
		idx := strings.Index(rest, "href=\"")
		if idx == -1 {
			break
		}
		rest = rest[idx+len("href=\""):]
		end := strings.Index(rest, "\"")
		if end == -1 {
			break
		}
		href := rest[:end]
		rest = rest[end:]

		// Skip parent directory links and absolute URLs.
		if href == ".." || href == "../" || strings.HasPrefix(href, "/") || strings.Contains(href, "://") {
			continue
		}

		// Strip trailing slash (directories).
		href = strings.TrimRight(href, "/")
		if href == "" {
			continue
		}

		files = append(files, href)
	}
	return files
}

// virtualEnvelope implements attestation.Envelope for virtual signature
// attestations, matching the pattern used by the filesystem collector.
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
