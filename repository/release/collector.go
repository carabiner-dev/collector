// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"fmt"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/ghrfs"
	"github.com/carabiner-dev/signer/key"

	"github.com/carabiner-dev/collector/filters"
	"github.com/carabiner-dev/collector/repository/filesystem"
)

var _ attestation.Fetcher = (*Collector)(nil)

var TypeMoniker = "release"

// Implement the factory function
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithReleaseURL(istr))
}

func New(funcs ...optFn) (*Collector, error) {
	c := &Collector{
		Options:        defaultOptions,
		apiBaseURL:     defaultAPIBaseURL,
		uploadsBaseURL: defaultUploadsBaseURL,
	}
	for _, fn := range funcs {
		if err := fn(c); err != nil {
			return nil, err
		}
	}

	if err := c.Options.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}

	fs, err := ghrfs.New(
		ghrfs.FromURL(
			fmt.Sprintf("%s/releases/tag/%s", c.Options.RepoURL, c.Options.Tag),
		),
		ghrfs.WithToken(c.Options.Token),
		ghrfs.WithRetries(c.Options.Retries),
		ghrfs.WithCache(true),
		ghrfs.WithCacheExtensions(
			[]string{"jsonl", "json", "pub", "sig", "crt", "key", "pub", "pem", "spdx", "cdx", "bundle", "asc", "gpg"},
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating GHRFS from: %w", err)
	}

	fscollector, err := filesystem.New(
		filesystem.WithFS(fs),
		filesystem.WithKey(c.Keys...),
	)
	if err != nil {
		return nil, fmt.Errorf("creating filesystem collector driver: %w", err)
	}
	c.Driver = fscollector

	return c, nil
}

type Collector struct {
	Options Options
	Keys    []key.PublicKeyProvider
	Driver  attestation.Fetcher

	// GitHub REST hosts used when uploading attestations (Store). They default
	// to the public GitHub endpoints and are overridable in tests.
	apiBaseURL     string
	uploadsBaseURL string
}

// SetKeys sets the verification keys on the release collector and propagates
// them to the inner driver if it supports key acceptance.
func (c *Collector) SetKeys(keys []key.PublicKeyProvider) {
	c.Keys = keys
	type keyAcceptor interface {
		SetKeys([]key.PublicKeyProvider)
	}
	if ka, ok := c.Driver.(keyAcceptor); ok {
		ka.SetKeys(keys)
	}
}

// Fetch queries the repository and retrieves any attestations matching the query.
// Attestations are read from the release assets and, for immutable releases,
// from the attestation GitHub generates for the release itself.
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	atts, err := c.Driver.Fetch(ctx, opts)
	if err != nil {
		return nil, err
	}
	if opts.Limit > 0 && len(atts) >= opts.Limit {
		return atts[:opts.Limit], nil
	}

	relAtts, err := c.fetchReleaseAttestations(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("reading release attestations: %w", err)
	}
	if opts.Query != nil {
		relAtts = opts.Query.Run(relAtts)
	}
	atts = append(atts, relAtts...)
	if opts.Limit > 0 && len(atts) > opts.Limit {
		atts = atts[:opts.Limit]
	}
	return atts, nil
}

// FetchBySubject retrieves the release attestations matching the subjects.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	sets := make([]map[string]string, 0, len(subj))
	for _, s := range subj {
		sets = append(sets, s.GetDigest())
	}
	return c.Fetch(ctx, withFilter(opts, &filters.SubjectHashMatcher{HashSets: sets}))
}

// FetchByPredicateType retrieves the release attestations of the given types.
func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	m := make(map[attestation.PredicateType]struct{}, len(pts))
	for _, pt := range pts {
		m[pt] = struct{}{}
	}
	return c.Fetch(ctx, withFilter(opts, &filters.PredicateTypeMatcher{PredicateTypes: m}))
}

// withFilter returns a copy of opts with the filter appended to its query, so
// that both the release assets and the release attestations are filtered
// before the fetch limit is applied.
func withFilter(opts attestation.FetchOptions, f attestation.Filter) attestation.FetchOptions {
	if opts.Query == nil {
		opts.Query = &attestation.Query{Filters: []attestation.Filter{f}}
		return opts
	}
	q := *opts.Query
	q.Filters = append(append([]attestation.Filter{}, q.Filters...), f)
	opts.Query = &q
	return opts
}
