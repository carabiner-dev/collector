// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/repository/filesystem"
)

func TestExtensions(t *testing.T) {
	t.Parallel()

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, filesystem.DefaultExtensions, attestationExtensions(nil))
		cache := cacheExtensions(nil)
		for _, ext := range filesystem.DefaultExtensions {
			require.Contains(t, cache, ext)
		}
		for _, ext := range sidecarExtensions {
			require.Contains(t, cache, ext)
		}
		require.Contains(t, cache, "hjson")
	})

	t.Run("configured", func(t *testing.T) {
		t.Parallel()
		exts := []string{"jsonl", "sig"}
		require.Equal(t, exts, attestationExtensions(exts))
		cache := cacheExtensions(exts)
		require.Contains(t, cache, "jsonl")
		require.NotContains(t, cache, "json", "configured extensions replace the defaults")
		require.Equal(t, 1, countOf(cache, "sig"), "sidecars already configured are not duplicated")
		require.Contains(t, cache, "pem")
	})

	t.Run("does-not-alias-inputs", func(t *testing.T) {
		t.Parallel()
		exts := []string{"json"}
		out := cacheExtensions(exts)
		out[0] = "changed"
		require.Equal(t, "json", exts[0])
		attestationExtensions(nil)[0] = "changed"
		require.Equal(t, "json", filesystem.DefaultExtensions[0])
	})

	// Building the collector loads the release from GitHub, so this part
	// runs only when a token is available, like TestNew.
	t.Run("reaches-the-driver", func(t *testing.T) {
		t.Parallel()
		if os.Getenv("GITHUB_TOKEN") == "" {
			t.Skip("no GITHUB_TOKEN set")
		}
		c, err := New(WithRepo("protobom/protobom"), WithTag("v0.5.2"), WithExtensions([]string{"jsonl"}))
		require.NoError(t, err)
		driver, ok := c.Driver.(*filesystem.Collector)
		require.True(t, ok, "the release collector delegates to the filesystem collector")
		require.Equal(t, []string{"jsonl"}, driver.Extensions)

		c, err = New(WithRepo("protobom/protobom"), WithTag("v0.5.2"))
		require.NoError(t, err)
		driver, ok = c.Driver.(*filesystem.Collector)
		require.True(t, ok)
		require.Equal(t, filesystem.DefaultExtensions, driver.Extensions)
	})
}

func countOf(list []string, s string) int {
	n := 0
	for _, e := range list {
		if e == s {
			n++
		}
	}
	return n
}
