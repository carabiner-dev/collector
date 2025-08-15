// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package jsonl implements an attestations collector that reads
// from files using the JSON Lines (jsonl) format.
package jsonl

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/carabiner-dev/attestation"
	cjsonl "github.com/carabiner-dev/jsonl"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/nozzle/throttler"

	"github.com/carabiner-dev/collector/envelope"
	"github.com/carabiner-dev/collector/filters"
)

var TypeMoniker = "jsonl"

// Implement the factory function
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithPath(istr))
}

var _ attestation.Fetcher = (*Collector)(nil)

func New(funcs ...optFn) (*Collector, error) {
	// Apply the functional options
	opts := defaultOptions
	for _, fn := range funcs {
		fn(&opts)
	}

	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}

	return &Collector{
		Options: opts,
	}, nil
}

type Collector struct {
	Options Options
}

// readAttestations
func (c *Collector) readAttestations(paths []string, filterset *attestation.FilterSet) ([]attestation.Envelope, error) {
	t := throttler.New(c.Options.MaxParallel, len(paths))
	ret := []attestation.Envelope{}
	mtx := sync.Mutex{}
	for _, path := range paths {
		go func() {
			moreAtts, err := parseJsonlFile(path, filterset)
			if err != nil {
				t.Done(err)
				return
			}
			mtx.Lock()
			ret = append(ret, moreAtts...)
			mtx.Unlock()
			t.Done(nil)
		}()
		t.Throttle()
	}
	if err := t.Err(); err != nil {
		return nil, err
	}
	return ret, nil
}

// parseJsonlFile uses the carabiner jsonl module to parse a jsonl bundle and
// get all the attestations in it.
func parseJsonlFile(path string, filterset *attestation.FilterSet) ([]attestation.Envelope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", path, err)
	}
	if filterset == nil {
		filterset = &attestation.FilterSet{}
	}
	ret := []attestation.Envelope{}

	for i, r := range cjsonl.IterateBundle(f) {
		if r == nil {
			continue
		}

		// Parse the JSON doc
		envelopes, err := envelope.Parsers.Parse(r)
		if err != nil {
			return nil, fmt.Errorf("parsing attestation %d in %q: %w", i, path, err)
		}

		// If the json did not return anything (not likely)
		if len(envelopes) == 0 {
			continue
		}

		// Complete the attestation source, we know that the envelope returns max 1
		// attestation per line
		if envelopes[0].GetStatement() != nil &&
			envelopes[0].GetStatement().GetPredicate() != nil &&
			envelopes[0].GetStatement().GetPredicate().GetOrigin() != nil {
			rd := &intoto.ResourceDescriptor{
				Name:   fmt.Sprintf("jsonl:%s#%d", path, i),
				Uri:    fmt.Sprintf("jsonl:%s#%d", path, i),
				Digest: envelopes[0].GetStatement().GetPredicate().GetOrigin().GetDigest(),
			}
			envelopes[0].GetStatement().GetPredicate().SetOrigin(rd)
		}
		ret = append(ret, filterset.FilterList(envelopes)...)
	}

	return ret, nil
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return c.readAttestations(c.Options.Paths, &attestation.FilterSet{})
}

// FetchBySubject calls the attestation reader with a filter preconfigured
// with subject hashes.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	matcher := &filters.SubjectHashMatcher{
		HashSets: []map[string]string{},
	}

	for _, s := range subj {
		matcher.HashSets = append(matcher.HashSets, s.GetDigest())
	}

	atts, err := c.readAttestations(c.Options.Paths, &attestation.FilterSet{matcher})
	if err != nil {
		return nil, fmt.Errorf("reading attestation: %w", err)
	}

	return atts, err
}

func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	return nil, attestation.ErrFetcherMethodNotImplemented
}
