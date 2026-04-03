// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package sbomfs implements an attestation collector backed by sbomfs,
// storing and retrieving attestations as properties on SBOM document nodes.
package sbomfs

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/carabiner-dev/attestation"
	sbomfslib "github.com/carabiner-dev/sbomfs"
	"github.com/carabiner-dev/signer/key"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/mod"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"

	"github.com/carabiner-dev/collector/filters"
	"github.com/carabiner-dev/collector/repository/filesystem"
)

var TypeMoniker = "sbomfs"

var Build = func(istr string) (attestation.Repository, error) {
	return New(WithPath(istr))
}

var (
	_ attestation.Fetcher = (*Collector)(nil)
	_ attestation.Storer  = (*Collector)(nil)
)

type Collector struct {
	Options Options
	Keys    []key.PublicKeyProvider
	doc     *sbom.Document
	fs      *sbomfslib.FS
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

	// Read the SBOM document from the path.
	r := reader.New()
	doc, err := r.ParseFile(c.Options.Path)
	if err != nil {
		return nil, fmt.Errorf("reading SBOM document: %w", err)
	}

	c.doc = doc
	c.fs = sbomfslib.New(doc)

	return c, nil
}

// SetKeys sets the verification keys on the collector and propagates
// them to the inner driver if it supports key acceptance.
func (c *Collector) SetKeys(keys []key.PublicKeyProvider) {
	c.Keys = keys
}

// Fetch queries the sbomfs and retrieves any attestations stored as properties.
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	driver, err := filesystem.New(
		filesystem.WithFS(c.fs),
		filesystem.WithKey(c.Keys...),
	)
	if err != nil {
		return nil, fmt.Errorf("creating filesystem collector driver: %w", err)
	}

	return driver.Fetch(ctx, opts)
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

// Store writes attestation envelopes as individual files in the sbomfs
// and persists the modified SBOM document back to disk in its original format.
func (c *Collector) Store(_ context.Context, _ attestation.StoreOptions, envelopes []attestation.Envelope) error {
	// Get existing file count to generate unique names.
	entries, err := c.fs.ReadDir(".")
	if err != nil {
		return fmt.Errorf("reading sbomfs directory: %w", err)
	}
	idx := len(entries)

	for i, env := range envelopes {
		data, err := json.Marshal(env)
		if err != nil {
			return fmt.Errorf("marshaling envelope %d: %w", i, err)
		}

		fname := fmt.Sprintf("attestation-%04d.json", idx+i)

		// Use the envelope's predicate type to build a more descriptive name.
		if s := env.GetStatement(); s != nil {
			if pt := string(s.GetPredicateType()); pt != "" {
				fname = fmt.Sprintf("attestation-%04d.%s.json", idx+i, sanitizePredicateType(pt))
			}
		}

		if err := c.fs.WriteFile(fname, data); err != nil {
			return fmt.Errorf("writing attestation %d to sbomfs: %w", i, err)
		}
	}

	// Write the SBOM document back to disk in its original format.
	if err := c.writeDocument(); err != nil {
		return fmt.Errorf("writing SBOM document: %w", err)
	}

	return nil
}

// writeDocument persists the SBOM document back to disk in its original format.
func (c *Collector) writeDocument() error {
	format := c.originalFormat()
	w := writer.New(
		writer.WithFormat(format),
		writer.WithSerializeOptions(&native.SerializeOptions{
			Mods: map[mod.Mod]struct{}{
				mod.SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS: {},
			},
		}),
	)
	if err := w.WriteFile(c.doc, c.Options.Path); err != nil {
		return fmt.Errorf("writing SBOM to %s: %w", c.Options.Path, err)
	}
	return nil
}

// originalFormat returns the format the document was originally parsed from.
func (c *Collector) originalFormat() formats.Format {
	if c.doc.GetMetadata() != nil && c.doc.GetMetadata().GetSourceData() != nil && c.doc.GetMetadata().GetSourceData().GetFormat() != "" {
		return formats.Format(c.doc.GetMetadata().GetSourceData().GetFormat())
	}
	// Default to SPDX 2.3 JSON if we can't determine the original format.
	return formats.SPDX23JSON
}
