// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package stash

import (
	"context"
	"fmt"
	"testing"

	"github.com/carabiner-dev/attestation"
	stashclient "github.com/carabiner-dev/stash/pkg/client"
	ita "github.com/in-toto/attestation/go/v1"
)

const (
	testOrg    = "acme"
	testAtt    = "att-1"
	testCommit = "abc"
)

// fakeStash implements the two StashClient methods the collector uses and
// records the filters of every list call. Attestations are keyed by id; the
// index maps a "algo=value" digest (or "pt=<type>" predicate) filter to the
// ids it matches.
type fakeStash struct {
	stashclient.StashClient

	listed []*stashclient.Filters
	index  map[string][]string
	raw    map[string][]byte
}

// key renders a filter into the index key used by the fake.
func filterKey(f *stashclient.Filters) string {
	for algo, value := range f.SubjectDigest {
		return algo + "=" + value
	}
	if f.PredicateType != "" {
		return "pt=" + f.PredicateType
	}
	return "all"
}

func (f *fakeStash) ListAttestations(_ context.Context, _, _ string, filters *stashclient.Filters, _ *stashclient.Cursor) (*stashclient.AttestationList, error) {
	f.listed = append(f.listed, filters)
	list := &stashclient.AttestationList{}
	for _, id := range f.index[filterKey(filters)] {
		list.Attestations = append(list.Attestations, &stashclient.Attestation{ID: id})
	}
	return list, nil
}

func (f *fakeStash) GetAttestationRaw(_ context.Context, _, _, id string) ([]byte, error) {
	raw, ok := f.raw[id]
	if !ok {
		return nil, fmt.Errorf("no attestation %q", id)
	}
	return raw, nil
}

// bareStatement returns a minimal in-toto statement the bare parser accepts.
func bareStatement(predicateType string) []byte {
	return []byte(fmt.Sprintf(
		`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"s","digest":{"gitCommit":"abc"}}],"predicateType":%q,"predicate":{}}`,
		predicateType))
}

// digestSubject builds an attestation.Subject carrying the given digests.
func digestSubject(digests map[string]string) attestation.Subject {
	return &ita.ResourceDescriptor{Digest: digests}
}

func TestWithInit(t *testing.T) {
	for init, want := range map[string][2]string{
		"stash:acme":         {testOrg, ""},
		"stash:acme/widgets": {testOrg, "widgets"},
		"acme/widgets":       {testOrg, "widgets"},
	} {
		opts := Options{}
		WithInit(init)(&opts)
		if opts.Org != want[0] || opts.Namespace != want[1] {
			t.Fatalf("WithInit(%q) = %q/%q, want %q/%q", init, opts.Org, opts.Namespace, want[0], want[1])
		}
	}
}

func TestNewRequiresOrg(t *testing.T) {
	if _, err := New(); err == nil {
		t.Fatal("expected an error without an organization")
	}
}

// TestFetchBySubjectFansOutDigests is the core regression test: stash
// compares digest filters conjunctively, so a subject with two digests must
// become two single-digest queries, and an attestation matching both must be
// fetched exactly once.
func TestFetchBySubjectFansOutDigests(t *testing.T) {
	fake := &fakeStash{
		index: map[string][]string{
			"sha1=" + testCommit:      {testAtt},
			"gitCommit=" + testCommit: {testAtt, "att-2"},
		},
		raw: map[string][]byte{
			testAtt: bareStatement("https://example.com/one"),
			"att-2": bareStatement("https://example.com/two"),
		},
	}
	c, err := New(WithOrg(testOrg), WithClient(fake))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	envs, err := c.FetchBySubject(context.Background(), attestation.FetchOptions{},
		[]attestation.Subject{digestSubject(map[string]string{"sha1": testCommit, "gitCommit": testCommit})})
	if err != nil {
		t.Fatalf("FetchBySubject: %v", err)
	}
	if len(fake.listed) != 2 {
		t.Fatalf("issued %d list calls, want 2 (one per digest)", len(fake.listed))
	}
	for _, f := range fake.listed {
		if len(f.SubjectDigest) != 1 {
			t.Fatalf("a query carried %d digests, want exactly 1 (stash ANDs them)", len(f.SubjectDigest))
		}
	}
	// att-1 matched both queries but must be fetched/parsed once.
	if len(envs) != 2 {
		t.Fatalf("fetched %d envelopes, want 2 (deduplicated)", len(envs))
	}
}

func TestFetchByPredicateTypeAndSubject(t *testing.T) {
	fake := &fakeStash{
		index: map[string][]string{
			"gitCommit=" + testCommit: {testAtt},
		},
		raw: map[string][]byte{
			testAtt: bareStatement("https://example.com/one"),
		},
	}
	c, err := New(WithOrg(testOrg), WithNamespace("widgets"), WithClient(fake))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	envs, err := c.FetchByPredicateTypeAndSubject(context.Background(), attestation.FetchOptions{},
		[]attestation.PredicateType{"https://example.com/one"},
		[]attestation.Subject{digestSubject(map[string]string{"gitCommit": testCommit})})
	if err != nil {
		t.Fatalf("FetchByPredicateTypeAndSubject: %v", err)
	}
	if len(fake.listed) != 1 {
		t.Fatalf("issued %d list calls, want 1", len(fake.listed))
	}
	if got := fake.listed[0].PredicateType; got != "https://example.com/one" {
		t.Fatalf("query predicate type = %q", got)
	}
	if len(envs) != 1 {
		t.Fatalf("fetched %d envelopes, want 1", len(envs))
	}
}

func TestSubjectFiltersSkipsEmptySubjects(t *testing.T) {
	filters := subjectFilters("", []attestation.Subject{
		digestSubject(nil), // nothing filterable: must not match everything
		&ita.ResourceDescriptor{Name: "named"},
	})
	if len(filters) != 1 {
		t.Fatalf("built %d filters, want 1 (the named subject)", len(filters))
	}
	if filters[0].SubjectName != "named" {
		t.Fatalf("filter subject name = %q", filters[0].SubjectName)
	}
}
