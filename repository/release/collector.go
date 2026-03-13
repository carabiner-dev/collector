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

	fs, err := ghrfs.New(
		ghrfs.FromURL(
			fmt.Sprintf("%s/releases/tag/%s", c.Options.RepoURL, c.Options.Tag),
		),
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

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return c.Driver.Fetch(ctx, opts)
}

// FetchBySubject handles collecting by subject hash. If the driver implements
// the FetcherBySubject interface we'll use it
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	if fr, ok := c.Driver.(attestation.FetcherBySubject); ok {
		return fr.FetchBySubject(ctx, opts, subj)
	}
	m := []map[string]string{}
	for _, s := range subj {
		m = append(m, s.GetDigest())
	}

	q := attestation.NewQuery().WithFilter(&filters.SubjectHashMatcher{
		HashSets: m,
	})

	atts, err := c.Driver.Fetch(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("retrieving attestations from driver: %w", err)
	}

	return q.Run(atts), nil
}

// FetchByPredicateType fe
func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	if fr, ok := c.Driver.(attestation.FetcherByPredicateType); ok {
		return fr.FetchByPredicateType(ctx, opts, pts)
	}
	m := map[attestation.PredicateType]struct{}{}
	for _, predType := range pts {
		m[predType] = struct{}{}
	}
	q := attestation.NewQuery().WithFilter(&filters.PredicateTypeMatcher{
		PredicateTypes: m,
	})

	atts, err := c.Driver.Fetch(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("fetching attestations from driver: %w", err)
	}
	return q.Run(atts), nil
}
