// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package note

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/vcslocator"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

func TestExtractCommitBundle(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		locator string
		notNil  bool
		mustErr bool
	}{
		{
			name:    "sharded",
			locator: "slsa-framework/slsa-source-poc@28a0276dde459992f3d8bbb4cb41cd34313a99ff",
			notNil:  true,
			mustErr: false,
		},
		{
			name:    "files",
			locator: "puerco/lab@fc3b05868b9d0378c7333122d1f1f80b51b08416",
			notNil:  true,
			mustErr: false,
		},
		{
			name:    "nodata",
			locator: "puerco/lab@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			notNil:  false,
			mustErr: false,
		},
		{
			name:    "error",
			locator: "puerco/lab-other-repo-that-does-not-exist@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			mustErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := Collector{
				Options: Options{Locator: tc.locator},
			}
			reader, err := c.extractCommitBundle()
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			data, err := io.ReadAll(reader)
			require.NoError(t, err)
			if tc.notNil {
				require.NotEmpty(t, data)
			} else {
				require.Empty(t, data)
			}
		})
	}
}

// TestFetchWithoutNotes reads attestations from a local repository before
// it has a notes reference, then for a commit without a note once the
// reference exists. Neither is an error, both are just empty.
func TestFetchWithoutNotes(t *testing.T) {
	t.Parallel()
	repoPath := filepath.Join(t.TempDir(), "repo")
	repo, err := git.PlainInit(repoPath, false)
	require.NoError(t, err)
	wt, err := repo.Worktree()
	require.NoError(t, err)

	commit := func(name string) string {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(repoPath, name), []byte(name), 0o600))
		_, err := wt.Add(name)
		require.NoError(t, err)
		hash, err := wt.Commit(name, &git.CommitOptions{
			Author: &object.Signature{Name: "Carabiner Test Robot", Email: "bot@carabiner.dev"},
		})
		require.NoError(t, err)
		return hash.String()
	}
	first := commit("first.txt")
	second := commit("second.txt")

	collectorFor := func(sha string) *Collector {
		t.Helper()
		c, err := New(WithLocator(string(vcslocator.NewFromPath(repoPath))+"@"+sha), WithPush(false))
		require.NoError(t, err)
		return c
	}

	// No notes reference in the repository yet
	_, err = repo.Reference(plumbing.ReferenceName("refs/notes/commits"), true)
	require.ErrorIs(t, err, plumbing.ErrReferenceNotFound)
	fetched, err := collectorFor(first).Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, fetched)

	// Store the first note, which creates the reference
	require.NoError(t, collectorFor(first).Store(
		t.Context(), attestation.StoreOptions{}, []attestation.Envelope{createTestAttestation(t)},
	))
	fetched, err = collectorFor(first).Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, fetched, 1)

	// The reference exists but the second commit has no note
	fetched, err = collectorFor(second).Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, fetched)
}

func TestNoteMissing(t *testing.T) {
	t.Parallel()
	notExist := fmt.Errorf("opening path 0: %w", fs.ErrNotExist)
	refMissing := fmt.Errorf("reading %q: %w", "git+https://example.com/repo@refs/notes/commits", vcslocator.ErrRefNotFound)
	other := errors.New("connection refused")
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"nil":                     {nil, false},
		"unrelated":               {fmt.Errorf("cloning: %w", other), false},
		"ref missing":             {fmt.Errorf("error cloning repositories: %w", &vcslocator.ErrorList{Errors: []error{refMissing, refMissing}}), true},
		"ref missing unwrapped":   {refMissing, true},
		"both files missing":      {&vcslocator.ErrorList{Errors: []error{notExist, notExist}}, true},
		"one file missing":        {&vcslocator.ErrorList{Errors: []error{notExist, nil}}, true},
		"one missing one failing": {&vcslocator.ErrorList{Errors: []error{notExist, other}}, false},
		"empty list":              {&vcslocator.ErrorList{Errors: []error{nil, nil}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, noteMissing(tc.err))
		})
	}
}
