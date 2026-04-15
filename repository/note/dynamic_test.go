// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package note

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/carabiner-dev/attestation"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/envelope/dsse"
	"github.com/carabiner-dev/collector/internal/testutil"
)

// createTestAttestationForCommit creates a DSSE envelope with a gitCommit subject
// pointing to the given commit hash.
func createTestAttestationForCommit(t *testing.T, commitHash string) attestation.Envelope {
	t.Helper()

	statement := fmt.Sprintf(
		`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"git:%s","digest":{"gitCommit":"%s","sha1":"%s"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{}}`,
		commitHash, commitHash, commitHash,
	)

	payload := base64.StdEncoding.EncodeToString([]byte(statement))
	envelopeJSON, err := json.Marshal(map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     payload,
		"signatures":  []map[string]string{{"sig": "dGVzdHNpZw=="}},
	})
	require.NoError(t, err)

	parser := &dsse.Parser{}
	env, err := parser.ParseStream(bytes.NewReader(envelopeJSON))
	require.NoError(t, err)
	require.Len(t, env, 1)
	return env[0]
}

// initTestRepo creates a temporary git repo with the given number of commits
// and returns the repo path and commit hashes.
func initTestRepo(t *testing.T, numCommits int) (repoPath string, commits []string) {
	t.Helper()

	repoPath = filepath.Join(t.TempDir(), "test-repo")
	repo, err := git.PlainInit(repoPath, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	commits = make([]string, 0, numCommits)
	for i := range numCommits {
		testFile := filepath.Join(repoPath, fmt.Sprintf("file%d.txt", i))
		err = os.WriteFile(testFile, fmt.Appendf(nil, "content %d", i), 0o600)
		require.NoError(t, err)

		_, err = wt.Add(fmt.Sprintf("file%d.txt", i))
		require.NoError(t, err)

		hash, err := wt.Commit(fmt.Sprintf("Commit %d", i), &git.CommitOptions{
			Author: &object.Signature{
				Name:  "Carabiner Test Robot",
				Email: "bot@carabiner.com",
			},
		})
		require.NoError(t, err)
		commits = append(commits, hash.String())
	}

	return repoPath, commits
}

func TestDynamicStoreAndFetch(t *testing.T) {
	repoPath, commits := initTestRepo(t, 1)
	commitHash := commits[0]

	// Create a dynamic collector pointing at the local repo
	dc, err := NewDynamic(DynamicRepoURL(testutil.FileLocator(repoPath)), WithPush(false))
	require.NoError(t, err)

	env := createTestAttestationForCommit(t, commitHash)

	// Store the attestation
	err = dc.Store(context.Background(), attestation.StoreOptions{}, []attestation.Envelope{env})
	require.NoError(t, err)

	// Read it back through the same dynamic collector
	subj := env.GetStatement().GetSubjects()
	fetched, err := dc.FetchBySubject(context.Background(), attestation.FetchOptions{}, subj)
	require.NoError(t, err)
	require.Len(t, fetched, 1)
}

func TestDynamicStoreMultipleCommits(t *testing.T) {
	repoPath, commits := initTestRepo(t, 3)

	dc, err := NewDynamic(DynamicRepoURL(testutil.FileLocator(repoPath)), WithPush(false))
	require.NoError(t, err)

	// Create one attestation per commit and store them all in a single call
	envelopes := make([]attestation.Envelope, 0, len(commits))
	for _, hash := range commits {
		envelopes = append(envelopes, createTestAttestationForCommit(t, hash))
	}

	err = dc.Store(context.Background(), attestation.StoreOptions{}, envelopes)
	require.NoError(t, err)

	// Verify each commit's attestation can be fetched independently
	for i, hash := range commits {
		env := createTestAttestationForCommit(t, hash)
		subj := env.GetStatement().GetSubjects()
		fetched, err := dc.FetchBySubject(context.Background(), attestation.FetchOptions{}, subj)
		require.NoError(t, err)
		require.Len(t, fetched, 1, "commit %d (%s) should have one attestation", i, hash)
	}
}

func TestDynamicStoreRejectsNonCommitSubject(t *testing.T) {
	repoPath, _ := initTestRepo(t, 1)

	dc, err := NewDynamic(DynamicRepoURL(testutil.FileLocator(repoPath)), WithPush(false))
	require.NoError(t, err)

	// Use the standard test attestation which has only sha256 subjects
	env := createTestAttestation(t)

	err = dc.Store(context.Background(), attestation.StoreOptions{}, []attestation.Envelope{env})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no sha1 or gitCommit subject")
}
