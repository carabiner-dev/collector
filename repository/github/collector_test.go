// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/github"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/envelope"
	"github.com/carabiner-dev/collector/repository"
)

// failingCaller answers every request with an empty 200 except the ones
// whose ordinal is listed in failOn, which fail with the given error.
type failingCaller struct {
	calls  int
	failOn map[int]error
}

func (fc *failingCaller) RequestWithContext(_ context.Context, _, _ string, _ io.Reader) (*http.Response, error) {
	i := fc.calls
	fc.calls++
	if err, ok := fc.failOn[i]; ok {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("{}")),
	}, nil
}

func TestStore(t *testing.T) {
	t.Parallel()
	envs, err := envelope.Parsers.ParseFiles([]string{
		"../../envelope/bundle/testdata/bundle-provenance.json",
		"../../envelope/bundle/testdata/bundle-publish.json",
		"../../envelope/bundle/testdata/bundle-provenance.json",
	})
	require.NoError(t, err)
	require.Len(t, envs, 3)

	rejected := errors.New("HTTP Error 422 sending request: invalid statement")
	for _, tc := range []struct {
		name         string
		failOn       map[int]error
		expectStored int
		expectFailed []int
	}{
		{"all-stored", nil, 3, nil},
		{"one-rejected", map[int]error{1: rejected}, 2, []int{1}},
		{"all-rejected", map[int]error{0: rejected, 1: rejected, 2: rejected}, 0, []int{0, 1, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			caller := &failingCaller{failOn: tc.failOn}
			client, err := github.NewClient(github.WithCaller(caller), github.WithEnsureToken(false))
			require.NoError(t, err)
			collector := &Collector{Options: Options{Owner: "org", Repo: "repo"}, client: client}

			err = collector.Store(t.Context(), attestation.StoreOptions{}, envs)
			require.Equal(t, len(envs), caller.calls, "every envelope must be attempted")
			if tc.expectFailed == nil {
				require.NoError(t, err)
				return
			}

			var serr *repository.StoreError
			require.ErrorAs(t, err, &serr)
			require.Equal(t, tc.expectStored, serr.Stored)
			require.Len(t, serr.Failed, len(tc.expectFailed))
			for _, i := range tc.expectFailed {
				require.ErrorIs(t, serr.Failed[i], rejected)
			}
			require.Equal(t, tc.expectStored == 0, serr.AllFailed())
		})
	}
}

func TestFetchFromUrl(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		srcData      string
		synterr      error
		expectedAtts int
	}{
		{"normal", "testdata/output.json", nil, 2},
		{"err", "", errors.New("bad boi"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create the mocked client
			client, err := github.NewClient(
				github.WithCaller(
					&github.FileCaller{
						SourcePath: tc.srcData,
						Error:      tc.synterr,
					},
				),
				github.WithEnsureToken(false),
			)
			require.NoError(t, err)

			collector := &Collector{
				Options: Options{},
				client:  client,
			}

			// Call the fetch
			res, _, err := collector.fetchFromUrl(
				t.Context(),
				"users/carabiner-dev/attestations/sha256:2775bba8b2170bef2f91b79d4f179fd87724ffee32b4a20b8304856fd3bf4b8f",
				0,
			)
			if tc.synterr != nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, res, tc.expectedAtts)
		})
	}
}

func TestWithRepo(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		sut          string
		expectedOrg  string
		expectedRepo string
		start        *Options
	}{
		{"slug", "protobom/cel", "protobom", "cel", &Options{}},
		{"repo", "cel", "", "cel", &Options{}},
		{"blank", "", "", "", &Options{}},
		{"no-overwrite", "cel", "protobom", "cel", &Options{Owner: "protobom"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := WithRepo(tc.sut)
			f(tc.start)
			require.Equal(t, tc.expectedOrg, tc.start.Owner)
			require.Equal(t, tc.expectedRepo, tc.start.Repo)
		})
	}
}
