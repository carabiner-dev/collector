// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package ossrebuild

import (
	"context"
	"testing"

	"github.com/carabiner-dev/attestation"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"
)

func TestBySubject(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name        string
		subjects    []attestation.Subject
		mustErr     bool
		expectedNum int
	}{
		{"one-package", []attestation.Subject{&intoto.ResourceDescriptor{Uri: "pkg:npm/read@1.0.7"}}, false, 2},
		{"two-packages", []attestation.Subject{
			&intoto.ResourceDescriptor{Uri: "pkg:npm/read@1.0.7"},
			&intoto.ResourceDescriptor{Uri: "pkg:npm/websocket@1.0.35"},
		}, false, 4},
		{"test-404-dont-fail", []attestation.Subject{&intoto.ResourceDescriptor{Uri: "pkg:npm/read@1.0.0"}}, false, 0},
		{"one-package-one-404", []attestation.Subject{
			&intoto.ResourceDescriptor{Uri: "pkg:npm/walk@2.3.15"}, // real
			&intoto.ResourceDescriptor{Uri: "pkg:npm/read@1.0.0"},  // 404
		}, false, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			collector, err := New()
			require.NoError(t, err)

			atts, err := collector.FetchBySubject(t.Context(), attestation.FetchOptions{}, tt.subjects)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, atts, tt.expectedNum)
		})
	}
}

func TestSubjectsToUrls(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		subjects []attestation.Subject
		expect   []string
	}{
		{
			"one",
			[]attestation.Subject{&intoto.ResourceDescriptor{Uri: "pkg:npm/binary-extensions@2.3.0"}},
			[]string{"https://storage.googleapis.com/google-rebuild-attestations/npm/binary-extensions/2.3.0/binary-extensions-2.3.0.tgz/rebuild.intoto.jsonl"},
		},
		{
			"existing",
			[]attestation.Subject{&intoto.ResourceDescriptor{Uri: "pkg:npm/yaml@2.4.2"}},
			[]string{"https://storage.googleapis.com/google-rebuild-attestations/npm/yaml/2.4.2/yaml-2.4.2.tgz/rebuild.intoto.jsonl"},
		},
		{
			"namespaced",
			[]attestation.Subject{&intoto.ResourceDescriptor{Uri: "pkg:npm/%40tanstack/vue-virtual@3.5.0"}},
			[]string{"https://storage.googleapis.com/google-rebuild-attestations/npm/@tanstack/vue-virtual/3.5.0/tanstack-vue-virtual-3.5.0.tgz/rebuild.intoto.jsonl"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			urls := subjectsToOssRebuildURLS(tt.subjects)
			require.Equal(t, tt.expect, urls)
		})
	}
}

// TestFetchBySubjectHonorsContext proves the context reaches the HTTP
// collector this driver delegates to: a pre-cancelled context must fail with
// context.Canceled rather than contacting the rebuild bucket.
func TestFetchBySubjectHonorsContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	c := &Collector{}
	_, err := c.FetchBySubject(ctx, attestation.FetchOptions{}, []attestation.Subject{
		&intoto.ResourceDescriptor{Uri: "pkg:npm/%40alloc/quick-lru@5.2.0"},
	})
	require.ErrorIs(t, err, context.Canceled)
}
