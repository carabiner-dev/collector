// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package note

import (
	"context"
	"fmt"

	"github.com/carabiner-dev/attestation"
	intoto "github.com/in-toto/attestation/go/v1"

	"github.com/carabiner-dev/collector/filters"
)

var (
	TypeMonikerDynamic                              = "dnote"
	_                  attestation.Fetcher          = (*Dynamic)(nil)
	_                  attestation.FetcherBySubject = (*Dynamic)(nil)
)

// Implement the factory function
var BuildDynamic = func(istr string) (attestation.Repository, error) {
	return NewDynamic(DynamicRepoURL(istr))
}

// Dynamic is a collector that works with any commit by dynamically creating a
// a fixed notes collector when trying to read a sha1 subject. Instead of
// beign preconfigured to read from a specific commit, dynamic creates a collector
// on the fly on every read request.
type Dynamic struct {
	Options Options
}

func NewDynamic(funcs ...optFn) (*Dynamic, error) {
	// Apply the functional options
	opts := defaultOptions
	for _, fn := range funcs {
		fn(&opts)
	}

	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}

	return &Dynamic{
		Options: opts,
	}, nil
}

// Fetch is a noop only to implement the main interface
func (c *Dynamic) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return []attestation.Envelope{}, nil
}

// FetchBySubject calls the attestation reader with a filter preconfigured
// with subject hashes.
func (c *Dynamic) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	all := []attestation.Envelope{}
	commits := map[string]struct{}{}

	matcher := &filters.SubjectHashMatcher{
		HashSets: []map[string]string{},
	}

	// Collect all possible commits from the subjects. Since we are dealing with
	// commits we do the gitCommin <> sha1 hack when one if missing.
	for _, s := range subj {
		digests := s.GetDigest()
		for algo, val := range s.GetDigest() {
			if algo == intoto.AlgorithmSHA1.String() {
				commits[val] = struct{}{}
				if _, ok := digests[intoto.AlgorithmGitCommit.String()]; !ok {
					digests[intoto.AlgorithmGitCommit.String()] = val
				}
			}
			if algo == intoto.AlgorithmGitCommit.String() {
				commits[val] = struct{}{}
				if _, ok := digests[intoto.AlgorithmGitCommit.String()]; !ok {
					digests[intoto.AlgorithmGitCommit.String()] = val
				}
			}
		}

		matcher.HashSets = append(matcher.HashSets, digests)
	}

	for commit := range commits {
		notesCollector, err := New(
			WithLocator(fmt.Sprintf("%s@%s", c.Options.DynamicRepoURL, commit)),
			WithHttpAuth(c.Options.HttpUsername, c.Options.HttpPassword),
		)
		if err != nil {
			return nil, fmt.Errorf("building collector for commit %s: %w", commit, err)
		}

		cAtts, err := notesCollector.Fetch(ctx, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, cAtts...)
	}

	return attestation.NewQuery().WithFilter(matcher).Run(all), nil
}
