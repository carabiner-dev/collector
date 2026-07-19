// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gitsign

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/stretchr/testify/require"
)

// TestWithTokenSetsBasicAuth checks that WithToken installs GitHub's
// x-access-token basic-auth, which is how a base-repo installation token
// authenticates the fetch.
func TestWithTokenSetsBasicAuth(t *testing.T) {
	c, err := New(WithRepoPath("git+https://example.com/o/r"), WithToken("tok"))
	require.NoError(t, err)
	ba, ok := c.Options.Auth.(*githttp.BasicAuth)
	require.True(t, ok, "WithToken must set a *http.BasicAuth")
	require.Equal(t, "x-access-token", ba.Username)
	require.Equal(t, "tok", ba.Password)
}

// TestWithRefAndDepth checks the ref/depth options are recorded.
func TestWithRefAndDepth(t *testing.T) {
	c, err := New(WithRepoPath("x"), WithRef("refs/pull/7/head"), WithDepth(1))
	require.NoError(t, err)
	require.Equal(t, "refs/pull/7/head", c.Options.Ref)
	require.Equal(t, 1, c.Options.Depth)
}

// TestFetchRef_PullRef proves fetchRef retrieves a commit reachable only from a
// non-branch ref (refs/pull/N/head) — the case a default-branch clone misses —
// entirely offline, from a local source repository.
func TestFetchRef_PullRef(t *testing.T) {
	dir := t.TempDir()
	src, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)
	wt, err := src.Worktree()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "f.txt"), []byte("hi"), 0o600))
	_, err = wt.Add("f.txt")
	require.NoError(t, err)
	h, err := wt.Commit("c", &gogit.CommitOptions{
		Author: &object.Signature{Name: "t", Email: "t@example.com", When: time.Unix(1700000000, 0)},
	})
	require.NoError(t, err)

	// Publish the commit under a pull ref (not refs/heads/*), mimicking a PR head.
	require.NoError(t, src.Storer.SetReference(
		plumbing.NewHashReference("refs/pull/1/head", h)))

	repo, err := fetchRef(dir, "origin", "refs/pull/1/head", nil, 0)
	require.NoError(t, err)
	_, err = repo.CommitObject(h)
	require.NoError(t, err, "the pull-ref commit must be present after fetchRef")
}

// TestFetchRef_MissingRef fails closed when the ref does not exist.
func TestFetchRef_MissingRef(t *testing.T) {
	dir := t.TempDir()
	_, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)

	_, err = fetchRef(dir, "origin", "refs/pull/999/head", nil, 0)
	require.Error(t, err, "fetching a non-existent ref must fail")
}
