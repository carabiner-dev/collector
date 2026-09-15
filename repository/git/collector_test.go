// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"path/filepath"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/tar"

	"github.com/carabiner-dev/collector/repository/filesystem"
)

func TestClone(t *testing.T) {
	t.Parallel()

	// unpack test repository to tmp
	dir := t.TempDir()
	require.NoError(t, tar.Extract("testdata/repo.tar.gz", dir))
	logrus.Info(filepath.Join(dir, "repo"))
	for _, tc := range []struct {
		name        string
		init        string
		expectedNum int
		mustErr     bool
	}{
		{"root", filepath.Join(dir, "repo"), 3, false},
		{"subpath", filepath.Join(dir, "repo") + "#sboms", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(WithLocator(tc.init))
			require.NoError(t, err)

			err = c.clone()
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Check if the methods work
			res, err := c.Fetch(t.Context(), attestation.FetchOptions{})
			require.NoError(t, err)
			require.Len(t, res, tc.expectedNum)
		})
	}
}

func TestCloneExtensions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, tar.Extract("testdata/repo.tar.gz", dir))
	repo := filepath.Join(dir, "repo")

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		c, err := New(WithLocator(repo))
		require.NoError(t, err)
		require.NoError(t, c.clone())
		require.Equal(t, filesystem.DefaultExtensions, c.FSCollector.Extensions)
	})

	t.Run("custom", func(t *testing.T) {
		t.Parallel()
		c, err := New(WithLocator(repo), WithExtensions([]string{"spdx"}))
		require.NoError(t, err)
		require.NoError(t, c.clone())
		require.Equal(t, []string{"spdx"}, c.FSCollector.Extensions)

		// Only the spdx documents in the fixture are read now
		res, err := c.Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		for _, env := range res {
			require.Contains(t, string(env.GetStatement().GetPredicateType()), "spdx")
		}
	})
}
