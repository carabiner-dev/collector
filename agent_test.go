// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"errors"
	"testing"

	"github.com/carabiner-dev/attestation"
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
