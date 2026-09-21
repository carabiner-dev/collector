// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"errors"
	"testing"

	"github.com/carabiner-dev/attestation"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/envelope/bare"
)

var _ attestation.Fetcher = (*fakeFetcher)(nil)

type fakeFetcher struct {
	fetchFunc                func(context.Context, attestation.FetchOptions) ([]attestation.Envelope, error)
	fetchBySubjectFunc       func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error)
	fetchByPredicateTypeFunc func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error)
}

func (ff *fakeFetcher) Fetch(ctx context.Context, fo attestation.FetchOptions) ([]attestation.Envelope, error) {
	return ff.fetchFunc(ctx, fo)
}

func (ff *fakeFetcher) FetchBySubject(ctx context.Context, fo attestation.FetchOptions, subs []attestation.Subject) ([]attestation.Envelope, error) {
	return ff.fetchBySubjectFunc(ctx, fo, subs)
}

func (ff *fakeFetcher) FetchByPredicateType(ctx context.Context, fo attestation.FetchOptions, pt []attestation.PredicateType) ([]attestation.Envelope, error) {
	return ff.fetchByPredicateTypeFunc(ctx, fo, pt)
}

func TestFetch(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		fn      []func(context.Context, attestation.FetchOptions) ([]attestation.Envelope, error)
		expect  int
		mustErr bool
	}{
		{
			name: "single-repo-single-return",
			fn: []func(context.Context, attestation.FetchOptions) ([]attestation.Envelope, error){
				func(_ context.Context, _ attestation.FetchOptions) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
			},
			expect: 1,
		},
		{
			name: "dual-repo-single-return",
			fn: []func(context.Context, attestation.FetchOptions) ([]attestation.Envelope, error){
				func(_ context.Context, _ attestation.FetchOptions) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
				func(_ context.Context, _ attestation.FetchOptions) ([]attestation.Envelope, error) {
					return []attestation.Envelope{}, nil
				},
			},
			expect: 1,
		},
		{
			name: "single-repo-dual-return",
			fn: []func(context.Context, attestation.FetchOptions) ([]attestation.Envelope, error){
				func(_ context.Context, _ attestation.FetchOptions) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{}, &bare.Envelope{},
					}, nil
				},
			},
			expect: 2,
		},
		{
			name: "dual-repo-dual-return",
			fn: []func(context.Context, attestation.FetchOptions) ([]attestation.Envelope, error){
				func(_ context.Context, _ attestation.FetchOptions) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
				func(_ context.Context, _ attestation.FetchOptions) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
			},
			expect: 2,
		},
		{
			name: "dual-repo-one-errs",
			fn: []func(context.Context, attestation.FetchOptions) ([]attestation.Envelope, error){
				func(_ context.Context, _ attestation.FetchOptions) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
				func(_ context.Context, _ attestation.FetchOptions) ([]attestation.Envelope, error) {
					return nil, errors.New("synth error")
				},
			},
			mustErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			agent, err := New()
			require.NoError(t, err)
			for _, fn := range tc.fn {
				ff := &fakeFetcher{
					fetchFunc: fn,
				}
				agent.Repositories = append(agent.Repositories, ff)
			}

			res, err := agent.Fetch(t.Context())
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Len(t, res, tc.expect)
		})
	}
}

func TestFetchAttestationsBySubject(t *testing.T) {
	t.Parallel()

	//nolint:dupl
	for _, tc := range []struct {
		name    string
		fn      []func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error)
		expect  int
		mustErr bool
	}{
		{
			name: "single-repo-single-return",
			fn: []func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error){
				func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
			},
			expect: 1,
		},
		{
			name: "dual-repo-single-return",
			fn: []func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error){
				func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
				func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error) {
					return []attestation.Envelope{}, nil
				},
			},
			expect: 1,
		},
		{
			name: "single-repo-dual-return",
			fn: []func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error){
				func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{}, &bare.Envelope{},
					}, nil
				},
			},
			expect: 2,
		},
		{
			name: "dual-repo-dual-return",
			fn: []func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error){
				func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
				func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
			},
			expect: 2,
		},
		{
			name: "dual-repo-one-errs",
			fn: []func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error){
				func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
				func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error) {
					return nil, errors.New("synth error")
				},
			},
			mustErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			agent, err := New()
			require.NoError(t, err)
			for _, fn := range tc.fn {
				ff := &fakeFetcher{
					fetchBySubjectFunc: fn,
				}
				agent.Repositories = append(agent.Repositories, ff)
			}

			subs := []attestation.Subject{}

			res, err := agent.FetchAttestationsBySubject(t.Context(), subs)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Len(t, res, tc.expect)
		})
	}
}

func TestFetchAttestationsByPredicateType(t *testing.T) {
	t.Parallel()

	//nolint:dupl
	for _, tc := range []struct {
		name    string
		fn      []func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error)
		expect  int
		mustErr bool
	}{
		{
			name: "single-repo-single-return",
			fn: []func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error){
				func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
			},
			expect: 1,
		},
		{
			name: "dual-repo-single-return",
			fn: []func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error){
				func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
				func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error) {
					return []attestation.Envelope{}, nil
				},
			},
			expect: 1,
		},
		{
			name: "single-repo-dual-return",
			fn: []func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error){
				func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{}, &bare.Envelope{},
					}, nil
				},
			},
			expect: 2,
		},
		{
			name: "dual-repo-dual-return",
			fn: []func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error){
				func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
				func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
			},
			expect: 2,
		},
		{
			name: "dual-repo-one-errs",
			fn: []func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error){
				func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error) {
					return []attestation.Envelope{
						&bare.Envelope{},
					}, nil
				},
				func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error) {
					return nil, errors.New("synth error")
				},
			},
			mustErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			agent, err := New()
			require.NoError(t, err)
			for _, fn := range tc.fn {
				ff := &fakeFetcher{
					fetchByPredicateTypeFunc: fn,
				}
				agent.Repositories = append(agent.Repositories, ff)
			}

			res, err := agent.FetchAttestationsByPredicateType(t.Context(), []attestation.PredicateType{"test"})
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Len(t, res, tc.expect)
		})
	}
}

// fakeStorer records the store calls it gets and fails with err when set.
type fakeStorer struct {
	err   error
	calls int
}

func (f *fakeStorer) Store(_ context.Context, _ attestation.StoreOptions, _ []attestation.Envelope) error {
	f.calls++
	return f.err
}

func TestStoreReachesEveryRepository(t *testing.T) {
	t.Parallel()
	failing := &fakeStorer{err: errors.New("boom")}
	working := &fakeStorer{}

	agent, err := New()
	require.NoError(t, err)
	require.NoError(t, agent.AddRepository(failing, working))

	err = agent.Store(t.Context(), nil)
	require.ErrorContains(t, err, "boom")
	require.Equal(t, 1, failing.calls)
	require.Equal(t, 1, working.calls, "a failing repository must not stop the others")
}

// TestFetchSkipsDriversOnCancelledContext proves the agent does not start a
// driver fetch once the caller's context is done: every fetch entry point
// returns the context error and no driver is called.
func TestFetchSkipsDriversOnCancelledContext(t *testing.T) {
	t.Parallel()

	calls := 0
	record := func() {
		calls++
	}
	fetcher := &fakeFetcher{
		fetchFunc: func(context.Context, attestation.FetchOptions) ([]attestation.Envelope, error) {
			record()
			return nil, nil
		},
		fetchBySubjectFunc: func(context.Context, attestation.FetchOptions, []attestation.Subject) ([]attestation.Envelope, error) {
			record()
			return nil, nil
		},
		fetchByPredicateTypeFunc: func(context.Context, attestation.FetchOptions, []attestation.PredicateType) ([]attestation.Envelope, error) {
			record()
			return nil, nil
		},
	}

	agent, err := New()
	require.NoError(t, err)
	require.NoError(t, agent.AddRepository(fetcher))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = agent.Fetch(ctx)
	require.ErrorIs(t, err, context.Canceled)

	_, err = agent.FetchAttestationsBySubject(ctx, []attestation.Subject{
		&intoto.ResourceDescriptor{Name: "x", Digest: map[string]string{"sha256": "abc"}},
	})
	require.ErrorIs(t, err, context.Canceled)

	_, err = agent.FetchAttestationsByPredicateType(ctx, []attestation.PredicateType{"https://example.com/p"})
	require.ErrorIs(t, err, context.Canceled)

	require.Equal(t, 0, calls, "no driver may be called once the context is done")
}

// TestStoreStopsOnCancelledContext proves Store checks the context between
// repositories: with a cancelled context no repository is written and the
// context error is returned.
func TestStoreStopsOnCancelledContext(t *testing.T) {
	t.Parallel()

	first := &fakeStorer{}
	second := &fakeStorer{}

	agent, err := New()
	require.NoError(t, err)
	require.NoError(t, agent.AddRepository(first, second))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err = agent.Store(ctx, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 0, first.calls)
	require.Equal(t, 0, second.calls)
}
