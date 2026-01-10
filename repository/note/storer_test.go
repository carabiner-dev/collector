// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package note

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/carabiner-dev/attestation"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/envelope/dsse"
)

func TestStoreWithLocalRepo(t *testing.T) {
	// Create a temporary directory for the test repository
	tmpDir := t.TempDir()
	repoPath := filepath.Join(tmpDir, "test-repo")

	// Initialize a git repository
	repo, err := git.PlainInit(repoPath, false)
	require.NoError(t, err)

	// Create a test commit
	wt, err := repo.Worktree()
	require.NoError(t, err)

	// Create a test file
	testFile := filepath.Join(repoPath, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0o600)
	require.NoError(t, err)

	// Add and commit the file
	_, err = wt.Add("test.txt")
	require.NoError(t, err)

	commitHash, err := wt.Commit("Initial commit", &git.CommitOptions{})
	require.NoError(t, err)

	// Create a test attestation
	testAttestation := createTestAttestation(t)

	// Create a collector with the test repository
	locator := "file://" + repoPath + "@" + commitHash.String()
	collector, err := New(WithLocator(locator), WithPush(false))
	require.NoError(t, err)

	// Store the attestation
	err = collector.Store(context.Background(), attestation.StoreOptions{}, []attestation.Envelope{testAttestation})
	require.NoError(t, err)

	// Verify the note was created
	notesRef, err := repo.Reference(plumbing.ReferenceName("refs/notes/commits"), true)
	require.NoError(t, err)
	require.NotEqual(t, plumbing.ZeroHash, notesRef.Hash())

	// Fetch the attestation back
	fetched, err := collector.Fetch(context.Background(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, fetched, 1)
}

func TestStoreAppendToExisting(t *testing.T) {
	// Create a temporary directory for the test repository
	tmpDir := t.TempDir()
	repoPath := filepath.Join(tmpDir, "test-repo")

	// Initialize a git repository
	repo, err := git.PlainInit(repoPath, false)
	require.NoError(t, err)

	// Create a test commit
	wt, err := repo.Worktree()
	require.NoError(t, err)

	// Create a test file
	testFile := filepath.Join(repoPath, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0o600)
	require.NoError(t, err)

	// Add and commit the file
	_, err = wt.Add("test.txt")
	require.NoError(t, err)

	commitHash, err := wt.Commit("Initial commit", &git.CommitOptions{})
	require.NoError(t, err)

	// Create test attestations
	testAttestation1 := createTestAttestation(t)
	testAttestation2 := createTestAttestation(t)

	// Create a collector with the test repository
	locator := "file://" + repoPath + "@" + commitHash.String()
	collector, err := New(WithLocator(locator), WithPush(false))
	require.NoError(t, err)

	// Store the first attestation
	err = collector.Store(context.Background(), attestation.StoreOptions{}, []attestation.Envelope{testAttestation1})
	require.NoError(t, err)

	// Store the second attestation (should append)
	err = collector.Store(context.Background(), attestation.StoreOptions{}, []attestation.Envelope{testAttestation2})
	require.NoError(t, err)

	// Fetch the attestations back
	fetched, err := collector.Fetch(context.Background(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, fetched, 2, "should have both attestations")
}

func TestStoreAndReadWithGitCommand(t *testing.T) {
	// Create a temporary directory for the test repository
	tmpDir := t.TempDir()
	repoPath := filepath.Join(tmpDir, "test-repo")

	// Initialize a git repository
	repo, err := git.PlainInit(repoPath, false)
	require.NoError(t, err)

	// Create a test commit
	wt, err := repo.Worktree()
	require.NoError(t, err)

	// Create a test file
	testFile := filepath.Join(repoPath, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0o600)
	require.NoError(t, err)

	// Add and commit the file
	_, err = wt.Add("test.txt")
	require.NoError(t, err)

	commitHash, err := wt.Commit("Initial commit", &git.CommitOptions{})
	require.NoError(t, err)

	// Create a test attestation
	testAttestation := createTestAttestation(t)

	// Create a collector with the test repository
	locator := "file://" + repoPath + "@" + commitHash.String()
	collector, err := New(WithLocator(locator), WithPush(false))
	require.NoError(t, err)

	// Store the attestation
	err = collector.Store(t.Context(), attestation.StoreOptions{}, []attestation.Envelope{testAttestation})
	require.NoError(t, err)

	// Now use real git command to read the note back
	cmd := exec.CommandContext(t.Context(), "git", "notes", "show", commitHash.String()) //nolint:gosec // This is always a hash
	cmd.Dir = repoPath
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "git notes show failed: %s", string(output))

	// Verify the output is valid JSONL
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	require.NotEmpty(t, lines, "git notes show returned no data")

	// Parse each line as JSON to verify it's valid
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var js json.RawMessage
		err := json.Unmarshal([]byte(line), &js)
		require.NoError(t, err, "line %d is not valid JSON: %s", i+1, line)
	}

	// Verify we can also read it back through the collector
	fetched, err := collector.Fetch(context.Background(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, fetched, 1, "should have one attestation")
}

// createTestAttestation creates a simple DSSE envelope for testing
func createTestAttestation(t *testing.T) attestation.Envelope {
	t.Helper()

	// Create a minimal DSSE envelope using the parser
	parser := &dsse.Parser{}
	envelopeJSON := []byte(`{
		"payloadType": "application/vnd.in-toto+json",
		"payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoidGVzdCIsImRpZ2VzdCI6eyJzaGEyNTYiOiJhYmMxMjMifX1dLCJwcmVkaWNhdGVUeXBlIjoiaHR0cHM6Ly9zbHNhLmRldi9wcm92ZW5hbmNlL3YxIiwicHJlZGljYXRlIjp7fX0=",
		"signatures": [
			{
				"sig": "dGVzdHNpZ25hdHVyZQ=="
			}
		]
	}`)

	env, err := parser.ParseStream(bytes.NewReader(envelopeJSON))
	require.NoError(t, err)
	require.Len(t, env, 1)

	return env[0]
}
