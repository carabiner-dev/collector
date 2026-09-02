// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package coci

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/envelope/bare"
	"github.com/carabiner-dev/collector/predicate/cyclonedx"
	"github.com/carabiner-dev/collector/predicate/spdx"
)

const (
	testSPDXDocument      = `{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-2.3","name":"sbom-test","dataLicense":"CC0-1.0","documentNamespace":"http://example.com/test","creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: test"]},"packages":[]}`
	testCycloneDXDocument = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[]}`
)

// pushSBOMImage attaches data as an SBOM layer at the cosign `.sbom` tag of
// the image at digest, the way `cosign attach sbom` and ko do it.
func pushSBOMImage(t *testing.T, ctx context.Context, repo, digest, mediaType string, data []byte) {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, static.NewLayer(data, types.MediaType(mediaType)))
	require.NoError(t, err)
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
	tag := fmt.Sprintf("%s:%s.sbom", repo, strings.Replace(digest, "sha256:", "sha256-", 1))
	require.NoError(t, crane.Push(img, tag, crane.WithContext(ctx), crane.Insecure))
}

func TestFetchSBOMLayers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		mediaType     string
		data          string
		predicateType attestation.PredicateType
	}{
		{"spdx", spdxJSONMediaType, testSPDXDocument, spdx.PredicateType},
		{"cyclonedx", cycloneDXJSONMediaType, testCycloneDXDocument, cyclonedx.PredicateType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			host := startTestRegistry(t)
			ctx := t.Context()

			repo := fmt.Sprintf("%s/test/coci/sbom", host)
			digest := pushEmptySubject(t, ctx, repo+":v1")
			pushSBOMImage(t, ctx, repo, digest, tc.mediaType, []byte(tc.data))

			c, err := New(WithReference(repo+":v1"), WithCraneOpts(crane.Insecure))
			require.NoError(t, err)

			atts, err := c.Fetch(ctx, attestation.FetchOptions{})
			require.NoError(t, err)
			require.Len(t, atts, 1)

			env := atts[0]
			require.IsType(t, &bare.Envelope{}, env)
			require.Nil(t, env.GetVerification())
			require.Equal(t, tc.predicateType, env.GetPredicate().GetType())
			require.JSONEq(t, tc.data, string(env.GetPredicate().GetData()))

			subjects := env.GetStatement().GetSubjects()
			require.Len(t, subjects, 1)
			require.Equal(t, strings.TrimPrefix(digest, "sha256:"), subjects[0].GetDigest()["sha256"])
		})
	}
}

func TestFetchSBOMLayersSkipsUnusableLayers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		mediaType string
		data      string
	}{
		{"unsupported media type", "application/vnd.syft+json", testSPDXDocument},
		{"not an sbom", spdxJSONMediaType, `{"hello":"world"}`},
		{"media type mismatch", cycloneDXJSONMediaType, testSPDXDocument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			host := startTestRegistry(t)
			ctx := t.Context()

			repo := fmt.Sprintf("%s/test/coci/sbom", host)
			digest := pushEmptySubject(t, ctx, repo+":v1")
			pushSBOMImage(t, ctx, repo, digest, tc.mediaType, []byte(tc.data))

			c, err := New(WithReference(repo+":v1"), WithCraneOpts(crane.Insecure))
			require.NoError(t, err)

			atts, err := c.Fetch(ctx, attestation.FetchOptions{})
			require.NoError(t, err)
			require.Empty(t, atts)
		})
	}
}

func TestFetchSBOMLayersMissingTag(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/nosbom", host)
	pushEmptySubject(t, ctx, repo+":v1")

	c, err := New(WithReference(repo+":v1"), WithCraneOpts(crane.Insecure))
	require.NoError(t, err)

	info, err := parseImageReference(ctx, repo+":v1", crane.Insecure)
	require.NoError(t, err)

	atts, err := c.fetchSBOMLayers(ctx, attestation.FetchOptions{}, info)
	require.NoError(t, err)
	require.Empty(t, atts)
}
