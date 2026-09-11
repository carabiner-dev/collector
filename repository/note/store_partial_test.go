// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package note

import (
	"context"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/vcslocator"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/internal/envtest"
	"github.com/carabiner-dev/collector/repository"
)

func TestStoreSkipsFailingEnvelopes(t *testing.T) {
	repoPath, commits := initTestRepo(t, 1)
	locator := string(vcslocator.NewFromPath(repoPath)) + "@" + commits[0]
	collector, err := New(WithLocator(locator), WithPush(false))
	require.NoError(t, err)

	// When no envelope can be serialized, no note is written
	err = collector.Store(context.Background(), attestation.StoreOptions{}, []attestation.Envelope{envtest.Unserializable{}})
	var serr *repository.StoreError
	require.ErrorAs(t, err, &serr)
	require.True(t, serr.AllFailed())
	repo, err := git.PlainOpen(repoPath)
	require.NoError(t, err)
	_, err = repo.Reference(plumbing.ReferenceName("refs/notes/commits"), true)
	require.Error(t, err, "no notes ref must be created when nothing was stored")

	// A failing envelope does not stop the others
	err = collector.Store(context.Background(), attestation.StoreOptions{}, []attestation.Envelope{
		envtest.Unserializable{}, createTestAttestation(t),
	})
	require.ErrorAs(t, err, &serr)
	require.Equal(t, 1, serr.Stored)
	require.Len(t, serr.Failed, 1)
	require.ErrorIs(t, serr.Failed[0], envtest.ErrUnserializable)

	fetched, err := collector.Fetch(context.Background(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, fetched, 1)
}

func TestDynamicStoreSkipsEnvelopesWithoutCommit(t *testing.T) {
	repoPath, commits := initTestRepo(t, 1)
	dc, err := NewDynamic(DynamicRepoURL(string(vcslocator.NewFromPath(repoPath))), WithPush(false))
	require.NoError(t, err)

	withCommit := createTestAttestationForCommit(t, commits[0])
	err = dc.Store(context.Background(), attestation.StoreOptions{}, []attestation.Envelope{
		createTestAttestation(t), // sha256 subjects only
		withCommit,
		envtest.Unserializable{},
	})
	var serr *repository.StoreError
	require.ErrorAs(t, err, &serr)
	require.Equal(t, 1, serr.Stored)
	require.Len(t, serr.Failed, 2)
	require.ErrorContains(t, serr.Failed[0], "no sha1 or gitCommit subject")
	require.ErrorContains(t, serr.Failed[2], "no sha1 or gitCommit subject")

	fetched, err := dc.FetchBySubject(context.Background(), attestation.FetchOptions{}, withCommit.GetStatement().GetSubjects())
	require.NoError(t, err)
	require.Len(t, fetched, 1)
}
