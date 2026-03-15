// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/olareg/olareg"
	olaregconfig "github.com/olareg/olareg/config"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient"
	rcconfig "github.com/regclient/regclient/config"
	rcdesc "github.com/regclient/regclient/types/descriptor"
	rcmanifest "github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"
	"github.com/stretchr/testify/require"
)

// startRegistry starts an in-memory OCI registry backed by olareg and returns
// the registry host (host:port) together with a regclient option that routes
// requests to it.
func startRegistry(t *testing.T) (string, regclient.Opt) {
	t.Helper()
	srv := olareg.New(olaregconfig.Config{
		Storage: olaregconfig.ConfigStorage{
			StoreType: olaregconfig.StoreMem,
		},
	})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() {
		ts.Close()
		if err := srv.Close(); err != nil {
			t.Logf("closing olareg: %v", err)
		}
	})

	tsURL, err := url.Parse(ts.URL)
	require.NoError(t, err)

	hostOpt := regclient.WithConfigHost(rcconfig.Host{
		Name:     tsURL.Host,
		Hostname: tsURL.Host,
		TLS:      rcconfig.TLSDisabled,
	})
	return tsURL.Host, hostOpt
}

// pushBlob uploads raw bytes as a blob and returns a descriptor for it.
func pushBlob(t *testing.T, ctx context.Context, rc *regclient.RegClient, r *ref.Ref, mediaType string, data []byte) rcdesc.Descriptor {
	t.Helper()
	d := rcdesc.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(data),
		Size:      int64(len(data)),
	}
	_, err := rc.BlobPut(ctx, *r, d, bytes.NewReader(data))
	require.NoError(t, err)
	return d
}

// pushManifest marshals an OCI manifest, pushes it, and returns the digest.
func pushManifest(t *testing.T, ctx context.Context, rc *regclient.RegClient, r *ref.Ref, m *ocispec.Manifest) digest.Digest {
	t.Helper()
	data, err := json.Marshal(m)
	require.NoError(t, err)

	man, err := rcmanifest.New(rcmanifest.WithRaw(data))
	require.NoError(t, err)
	err = rc.ManifestPut(ctx, *r, man)
	require.NoError(t, err)
	return digest.FromBytes(data)
}

// pushSubjectImage pushes a minimal OCI image (empty config, no layers) and
// returns the manifest digest.
func pushSubjectImage(t *testing.T, ctx context.Context, rc *regclient.RegClient, r *ref.Ref) digest.Digest {
	t.Helper()
	configData := []byte("{}")
	configDesc := pushBlob(t, ctx, rc, r, ocispec.MediaTypeImageConfig, configData)
	m := &ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config: ocispec.Descriptor{
			MediaType: configDesc.MediaType,
			Digest:    configDesc.Digest,
			Size:      configDesc.Size,
		},
	}
	m.SchemaVersion = 2
	return pushManifest(t, ctx, rc, r, m)
}

// pushBundleReferrer pushes a sigstore bundle blob as a referrer artifact
// pointing at the given subject digest and returns the referrer manifest digest.
func pushBundleReferrer(t *testing.T, ctx context.Context, rc *regclient.RegClient, r *ref.Ref, subjectDigest digest.Digest, subjectSize int64, bundleData []byte) {
	t.Helper()
	bundleDesc := pushBlob(t, ctx, rc, r, sigstoreBundleArtifactType, bundleData)

	emptyConfig := []byte("{}")
	emptyConfigDesc := pushBlob(t, ctx, rc, r, sigstoreBundleArtifactType, emptyConfig)

	m := &ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config: ocispec.Descriptor{
			MediaType: emptyConfigDesc.MediaType,
			Digest:    emptyConfigDesc.Digest,
			Size:      emptyConfigDesc.Size,
		},
		Layers: []ocispec.Descriptor{{
			MediaType: bundleDesc.MediaType,
			Digest:    bundleDesc.Digest,
			Size:      bundleDesc.Size,
		}},
		Subject: &ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageManifest,
			Digest:    subjectDigest,
			Size:      subjectSize,
		},
	}
	m.SchemaVersion = 2
	m.ArtifactType = sigstoreBundleArtifactType

	data, err := json.Marshal(m)
	require.NoError(t, err)
	rr := r.SetDigest(digest.FromBytes(data).String())
	pushManifest(t, ctx, rc, &rr, m)
}

// subjectManifestSize returns the size of the marshalled subject manifest for
// a given digest (we just need the size for the referrer's Subject field).
func subjectManifestSize(t *testing.T, ctx context.Context, rc *regclient.RegClient, r *ref.Ref, d digest.Digest) int64 {
	t.Helper()
	mRef := r.SetDigest(d.String())
	m, err := rc.ManifestHead(ctx, mRef)
	require.NoError(t, err)
	return m.GetDescriptor().Size
}

func TestNew(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		opts    []optFn
		mustErr bool
	}{
		{"valid-tag", []optFn{WithReference("ghcr.io/foo/bar:v1")}, false},
		{"valid-digest", []optFn{WithReference("ghcr.io/foo/bar@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")}, false},
		{"invalid-ref", []optFn{WithReference("INVALID:::")}, true},
		{"no-reference", []optFn{}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(tt.opts...)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, c)
		})
	}
}

func TestBuild(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		init    string
		mustErr bool
	}{
		{"valid", "ghcr.io/foo/bar:latest", false},
		{"invalid", "INVALID:::", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repo, err := Build(tt.init)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, repo)
		})
	}
}

func TestWithRegClientOpts(t *testing.T) {
	t.Parallel()
	c, err := New(
		WithReference("ghcr.io/foo/bar:v1"),
		WithRegClientOpts(regclient.WithDockerCreds()),
	)
	require.NoError(t, err)
	require.NotNil(t, c)
	require.Len(t, c.Options.regOpts, 1)
}

func TestFetchNoReferrers(t *testing.T) {
	t.Parallel()
	host, hostOpt := startRegistry(t)

	ctx := t.Context()
	rc := regclient.New(hostOpt)

	repo := host + "/test/norefer"
	r, err := ref.New(repo + ":v1")
	require.NoError(t, err)

	pushSubjectImage(t, ctx, rc, &r)

	c, err := New(WithReference(repo+":v1"), WithRegClientOpts(hostOpt))
	require.NoError(t, err)

	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, atts)
}

func TestFetchWithBundle(t *testing.T) {
	t.Parallel()
	host, hostOpt := startRegistry(t)

	ctx := t.Context()
	rc := regclient.New(hostOpt)

	repo := host + "/test/withbundle"
	r, err := ref.New(repo + ":v1")
	require.NoError(t, err)

	subjectDigest := pushSubjectImage(t, ctx, rc, &r)
	subjectSize := subjectManifestSize(t, ctx, rc, &r, subjectDigest)

	bundleData, err := os.ReadFile("testdata/bundle-provenance.json")
	require.NoError(t, err)

	pushBundleReferrer(t, ctx, rc, &r, subjectDigest, subjectSize, bundleData)

	c, err := New(WithReference(repo+":v1"), WithRegClientOpts(hostOpt))
	require.NoError(t, err)

	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)
	require.NotNil(t, atts[0].GetStatement())
	require.NotNil(t, atts[0].GetPredicate())
	require.Equal(t, attestation.PredicateType("https://slsa.dev/provenance/v0.2"), atts[0].GetPredicate().GetType())
}

func TestFetchWithDigestRef(t *testing.T) {
	t.Parallel()
	host, hostOpt := startRegistry(t)

	ctx := t.Context()
	rc := regclient.New(hostOpt)

	repo := host + "/test/digestref"
	r, err := ref.New(repo + ":v1")
	require.NoError(t, err)

	subjectDigest := pushSubjectImage(t, ctx, rc, &r)
	subjectSize := subjectManifestSize(t, ctx, rc, &r, subjectDigest)

	bundleData, err := os.ReadFile("testdata/bundle-provenance.json")
	require.NoError(t, err)

	pushBundleReferrer(t, ctx, rc, &r, subjectDigest, subjectSize, bundleData)

	// Fetch using a digest reference (skips tag-to-digest resolution).
	digestRefStr := fmt.Sprintf("%s@%s", repo, subjectDigest)
	c, err := New(WithReference(digestRefStr), WithRegClientOpts(hostOpt))
	require.NoError(t, err)

	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)
}

func TestFetchWithLimit(t *testing.T) {
	t.Parallel()
	host, hostOpt := startRegistry(t)

	ctx := t.Context()
	rc := regclient.New(hostOpt)

	repo := host + "/test/limit"
	r, err := ref.New(repo + ":v1")
	require.NoError(t, err)

	subjectDigest := pushSubjectImage(t, ctx, rc, &r)
	subjectSize := subjectManifestSize(t, ctx, rc, &r, subjectDigest)

	bundleData, err := os.ReadFile("testdata/bundle-provenance.json")
	require.NoError(t, err)

	// Push two referrers.
	for range 2 {
		pushBundleReferrer(t, ctx, rc, &r, subjectDigest, subjectSize, bundleData)
	}

	// Fetch with Limit=1 should return at most 1.
	c, err := New(WithReference(repo+":v1"), WithRegClientOpts(hostOpt))
	require.NoError(t, err)

	atts, err := c.Fetch(ctx, attestation.FetchOptions{Limit: 1})
	require.NoError(t, err)
	require.Len(t, atts, 1)
}

func TestFetchSkipsUnparseableLayers(t *testing.T) {
	t.Parallel()
	host, hostOpt := startRegistry(t)

	ctx := t.Context()
	rc := regclient.New(hostOpt)

	repo := host + "/test/nonbundle"
	r, err := ref.New(repo + ":v1")
	require.NoError(t, err)

	subjectDigest := pushSubjectImage(t, ctx, rc, &r)
	subjectSize := subjectManifestSize(t, ctx, rc, &r, subjectDigest)

	// Push a referrer whose layer is NOT a valid sigstore bundle.
	garbageData := []byte(`{"not":"a-bundle"}`)
	garbageDesc := pushBlob(t, ctx, rc, &r, "application/octet-stream", garbageData)

	emptyConfig := []byte("{}")
	emptyConfigDesc := pushBlob(t, ctx, rc, &r, sigstoreBundleArtifactType, emptyConfig)

	m := &ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config: ocispec.Descriptor{
			MediaType: emptyConfigDesc.MediaType,
			Digest:    emptyConfigDesc.Digest,
			Size:      emptyConfigDesc.Size,
		},
		Layers: []ocispec.Descriptor{{
			MediaType: garbageDesc.MediaType,
			Digest:    garbageDesc.Digest,
			Size:      garbageDesc.Size,
		}},
		Subject: &ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageManifest,
			Digest:    subjectDigest,
			Size:      subjectSize,
		},
	}
	m.SchemaVersion = 2
	m.ArtifactType = sigstoreBundleArtifactType

	data, err := json.Marshal(m)
	require.NoError(t, err)
	rr := r.SetDigest(digest.FromBytes(data).String())
	pushManifest(t, ctx, rc, &rr, m)

	// Unparseable layer → zero attestations.
	c, err := New(WithReference(repo+":v1"), WithRegClientOpts(hostOpt))
	require.NoError(t, err)

	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, atts)
}
