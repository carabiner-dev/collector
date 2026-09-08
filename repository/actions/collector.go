// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package actions implements a collector that reads attestations from the
// artifacts of a GitHub Actions workflow run.
//
// Every artifact whose name carries one of the configured extensions is
// downloaded (GitHub always delivers artifacts as zip archives) and its
// contents are parsed by the filesystem collector, so every format and sidecar
// signature that collector understands is supported. Zip files found inside an
// artifact are expanded and scanned the same way.
package actions

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/signer/key"
	"github.com/sirupsen/logrus"

	"github.com/carabiner-dev/collector/filters"
	"github.com/carabiner-dev/collector/internal/creds"
	"github.com/carabiner-dev/collector/internal/readlimit"
	"github.com/carabiner-dev/collector/repository/filesystem"
)

var TypeMoniker = "actions"

// Build is the factory function registered with the collector agent.
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithRunURL(istr))
}

var (
	_ attestation.Fetcher                = (*Collector)(nil)
	_ attestation.FetcherBySubject       = (*Collector)(nil)
	_ attestation.FetcherByPredicateType = (*Collector)(nil)
)

// maxZipDepth bounds how deeply nested zip files are expanded. The artifact
// archive itself is level 1.
const maxZipDepth = 3

type Collector struct {
	Options Options
	Keys    []key.PublicKeyProvider

	// apiBaseURL is the GitHub REST endpoint derived from Options.Host. It is
	// overridable in tests.
	apiBaseURL string
}

func New(funcs ...optFn) (*Collector, error) {
	c := &Collector{Options: defaultOptions}
	for _, fn := range funcs {
		if err := fn(c); err != nil {
			return nil, err
		}
	}
	if c.Options.Extensions == nil {
		c.Options.Extensions = slices.Clone(defaultExtensions)
	}
	if err := c.Options.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}
	if c.apiBaseURL == "" {
		c.apiBaseURL = apiBaseURL(c.Options.Host)
	}
	return c, nil
}

// SetKeys sets the keys used to verify detached signatures found next to the
// attestations in the artifacts.
func (c *Collector) SetKeys(keys []key.PublicKeyProvider) {
	c.Keys = keys
}

// Fetch downloads the run's matching artifacts and returns the attestations
// found in them.
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	token := creds.Token(c.Options.Token, creds.GitHubEnvVars...)
	if token == "" {
		return nil, errors.New(
			"a token is required to read workflow run artifacts; set it with " +
				"WithToken or via the GITHUB_TOKEN environment variable",
		)
	}

	artifacts, err := c.listArtifacts(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("listing artifacts of run %d: %w", c.Options.RunID, err)
	}

	maxSize := readlimit.Resolve(opts.MaxReadSize)
	ret := []attestation.Envelope{}
	for _, a := range artifacts {
		if !c.wanted(a) {
			continue
		}
		if a.SizeInBytes > maxSize {
			return nil, fmt.Errorf("artifact %q (%d bytes) exceeds max read size (%d bytes)", a.Name, a.SizeInBytes, maxSize)
		}
		data, err := c.downloadArtifact(ctx, token, a.ID, maxSize)
		if err != nil {
			return nil, fmt.Errorf("downloading artifact %q: %w", a.Name, err)
		}
		envs, err := c.readZip(ctx, remaining(opts, len(ret)), data, maxSize, 1)
		if err != nil {
			return nil, fmt.Errorf("reading artifact %q: %w", a.Name, err)
		}
		ret = append(ret, envs...)
		if limitReached(opts, len(ret)) {
			return ret[:opts.Limit], nil
		}
	}
	return ret, nil
}

// FetchBySubject returns the attestations whose subjects match any of the
// digests in subj.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	sets := make([]map[string]string, 0, len(subj))
	for _, s := range subj {
		sets = append(sets, s.GetDigest())
	}
	return c.Fetch(ctx, withFilter(opts, &filters.SubjectHashMatcher{HashSets: sets}))
}

// FetchByPredicateType returns the attestations whose predicate type is one
// of pts.
func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	types := make(map[attestation.PredicateType]struct{}, len(pts))
	for _, pt := range pts {
		types[pt] = struct{}{}
	}
	return c.Fetch(ctx, withFilter(opts, &filters.PredicateTypeMatcher{PredicateTypes: types}))
}

// withFilter returns a copy of opts whose query also applies f. The caller's
// query is left untouched.
func withFilter(opts attestation.FetchOptions, f attestation.Filter) attestation.FetchOptions {
	var set attestation.FilterSet
	if opts.Query != nil {
		set = slices.Clone(opts.Query.Filters)
	}
	opts.Query = &attestation.Query{Filters: append(set, f)}
	return opts
}

// remaining returns opts with the limit reduced by the attestations already
// collected, so nested reads stop as early as possible.
func remaining(opts attestation.FetchOptions, collected int) attestation.FetchOptions {
	if opts.Limit > 0 {
		opts.Limit -= collected
	}
	return opts
}

func limitReached(opts attestation.FetchOptions, collected int) bool {
	return opts.Limit > 0 && collected >= opts.Limit
}

// wanted reports whether an artifact should be downloaded: it must not have
// expired and its name must carry one of the configured extensions.
func (c *Collector) wanted(a artifact) bool {
	switch {
	case a.Expired:
		logrus.Debugf("skipping expired artifact %q", a.Name)
		return false
	case !hasExtension(a.Name, c.Options.Extensions):
		logrus.Debugf("skipping artifact %q: extension not in %v", a.Name, c.Options.Extensions)
		return false
	default:
		return true
	}
}

// readZip parses the attestations in a zip archive with the filesystem
// collector and, when zip is a configured extension, expands the zip files
// found inside it up to maxZipDepth levels deep. depth is the nesting level of
// the archive being read, the artifact archive itself being 1.
func (c *Collector) readZip(ctx context.Context, opts attestation.FetchOptions, data []byte, maxSize int64, depth int) ([]attestation.Envelope, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("opening zip archive: %w", err)
	}

	fsc, err := filesystem.New(filesystem.WithFS(zr), filesystem.WithKey(c.Keys...))
	if err != nil {
		return nil, fmt.Errorf("creating filesystem collector: %w", err)
	}
	fsc.Extensions = c.Options.fileExtensions()

	ret, err := fsc.Fetch(ctx, opts)
	if err != nil {
		return nil, err
	}
	if limitReached(opts, len(ret)) || !c.Options.expandZips() || depth >= maxZipDepth {
		return ret, nil
	}

	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !hasExtension(f.Name, []string{zipExtension}) {
			continue
		}
		logrus.Debugf("expanding nested archive %s", f.Name)
		nested, err := readZipEntry(f, maxSize)
		if err != nil {
			return nil, fmt.Errorf("reading nested archive %s: %w", f.Name, err)
		}
		envs, err := c.readZip(ctx, remaining(opts, len(ret)), nested, maxSize, depth+1)
		if err != nil {
			return nil, fmt.Errorf("reading nested archive %s: %w", f.Name, err)
		}
		ret = append(ret, envs...)
		if limitReached(opts, len(ret)) {
			return ret[:opts.Limit], nil
		}
	}
	return ret, nil
}

// readZipEntry returns the decompressed contents of a zip entry, refusing
// anything larger than maxSize. The limit is enforced while inflating, so the
// size recorded in the archive header is never trusted.
func readZipEntry(f *zip.File, maxSize int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close() //nolint:errcheck

	data, err := io.ReadAll(io.LimitReader(rc, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("%s exceeds max read size (%d bytes)", f.Name, maxSize)
	}
	return data, nil
}
