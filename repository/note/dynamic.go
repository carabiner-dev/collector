// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package note

import (
	"context"
	"errors"
	"fmt"

	"github.com/carabiner-dev/attestation"
	intoto "github.com/in-toto/attestation/go/v1"

	"github.com/carabiner-dev/collector/filters"
	"github.com/carabiner-dev/collector/repository"
)

var (
	TypeMonikerDynamic                              = "dnote"
	_                  attestation.Fetcher          = (*Dynamic)(nil)
	_                  attestation.FetcherBySubject = (*Dynamic)(nil)
	_                  attestation.Storer           = (*Dynamic)(nil)
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

// Store implements the attestation.Storer interface. It inspects all envelopes
// to extract sha1/gitCommit subjects, groups them by commit, and stores each
// group using a dedicated notes collector. If any envelope lacks a sha1 or
// gitCommit subject, an error is returned before any writes occur.
func (c *Dynamic) Store(ctx context.Context, opts attestation.StoreOptions, envelopes []attestation.Envelope) error {
	serr := repository.NewStoreError()

	// First pass: group the envelopes by commit digest, remembering their
	// position to report failures. Envelopes without a commit subject
	// cannot be stored as notes and are skipped.
	commitEnvelopes := map[string][]attestation.Envelope{}
	commitIndexes := map[string][]int{}
	for i, env := range envelopes {
		commits := extractCommitDigests(env)
		if len(commits) == 0 {
			serr.Failed[i] = errors.New("envelope has no sha1 or gitCommit subject")
			continue
		}
		for _, commit := range commits {
			commitEnvelopes[commit] = append(commitEnvelopes[commit], env)
			commitIndexes[commit] = append(commitIndexes[commit], i)
		}
	}

	// Second pass: store attestations per commit. An envelope that fails
	// under any of its commits counts as failed.
	for commit, envs := range commitEnvelopes {
		indexes := commitIndexes[commit]
		notesCollector, err := New(
			WithLocator(fmt.Sprintf("%s@%s", c.Options.DynamicRepoURL, commit)),
			WithHttpAuth(c.Options.HttpUsername, c.Options.HttpPassword),
			WithPush(*c.Options.Push),
		)
		if err != nil {
			failIndexes(serr, indexes, fmt.Errorf("building collector for commit %s: %w", commit, err))
			continue
		}

		err = notesCollector.Store(ctx, opts, envs)
		var sub *repository.StoreError
		switch {
		case err == nil:
		case errors.As(err, &sub):
			for j, ferr := range sub.Failed {
				serr.Failed[indexes[j]] = fmt.Errorf("storing attestation for commit %s: %w", commit, ferr)
			}
		default:
			failIndexes(serr, indexes, fmt.Errorf("storing attestations for commit %s: %w", commit, err))
		}
	}

	serr.Stored = len(envelopes) - len(serr.Failed)
	return serr.ErrorOrNil()
}

// failIndexes marks the envelopes at indexes as failed with err, keeping
// the error already recorded for an envelope that failed before.
func failIndexes(serr *repository.StoreError, indexes []int, err error) {
	for _, i := range indexes {
		if _, failed := serr.Failed[i]; !failed {
			serr.Failed[i] = err
		}
	}
}

// extractCommitDigests returns deduplicated commit hashes from an envelope's
// subjects by looking for sha1 and gitCommit digest algorithms.
func extractCommitDigests(env attestation.Envelope) []string {
	stmt := env.GetStatement()
	if stmt == nil {
		return nil
	}

	seen := map[string]struct{}{}
	for _, subj := range stmt.GetSubjects() {
		for algo, val := range subj.GetDigest() {
			if algo == intoto.AlgorithmSHA1.String() || algo == intoto.AlgorithmGitCommit.String() {
				seen[val] = struct{}{}
			}
		}
	}

	commits := make([]string, 0, len(seen))
	for c := range seen {
		commits = append(commits, c)
	}
	return commits
}
