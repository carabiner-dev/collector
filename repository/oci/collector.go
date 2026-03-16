// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"context"
	"fmt"
	"io"

	"github.com/carabiner-dev/attestation"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"
	"github.com/sirupsen/logrus"

	"github.com/carabiner-dev/collector/envelope/bundle"
	"github.com/carabiner-dev/collector/internal/readlimit"
)

const (
	TypeMoniker = "oci"
	// sigstoreBundleArtifactType is the artifact type for sigstore bundles
	// attached as OCI referrers by cosign v3.
	sigstoreBundleArtifactType = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

// Build is the factory function used to register this collector.
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithReference(istr))
}

var _ attestation.Fetcher = (*Collector)(nil)

// Collector fetches sigstore bundle attestations attached as OCI referrers.
type Collector struct {
	Options Options
}

// New creates a new OCI referrers collector.
func New(funcs ...optFn) (*Collector, error) {
	opts := defaultOptions
	for _, fn := range funcs {
		if err := fn(&opts); err != nil {
			return nil, err
		}
	}

	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}

	return &Collector{
		Options: opts,
	}, nil
}

// Fetch queries the OCI referrers for the configured image and returns any
// sigstore bundle attestations found.
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	r, err := ref.New(c.Options.Reference)
	if err != nil {
		return nil, fmt.Errorf("parsing reference: %w", err)
	}

	rcOpts := c.Options.regOpts
	if len(rcOpts) == 0 {
		rcOpts = []regclient.Opt{regclient.WithDockerCreds(), regclient.WithDockerCerts()}
	}
	rc := regclient.New(rcOpts...)

	// Resolve tag to digest so we can query referrers.
	if r.Digest == "" {
		m, err := rc.ManifestHead(ctx, r)
		if err != nil {
			return nil, fmt.Errorf("resolving reference digest: %w", err)
		}
		r = r.SetDigest(m.GetDescriptor().Digest.String())
	}

	// Fetch all referrers without filtering by artifact type. Some registries
	// (notably GHCR) do not propagate the manifest-level artifactType into the
	// referrer descriptor, so an API-level filter would miss valid entries.
	rl, err := rc.ReferrerList(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("listing referrers: %w", err)
	}

	var atts []attestation.Envelope
	parser := bundle.Parser{}

	for i := range rl.Descriptors {
		envs, err := c.fetchReferrer(ctx, rc, &r, &rl.Descriptors[i], &opts, &parser)
		if err != nil {
			logrus.Debugf("oci: skipping referrer %d: %v", i, err)
			continue
		}
		atts = append(atts, envs...)

		if opts.Limit > 0 && len(atts) >= opts.Limit {
			break
		}
	}

	return atts, nil
}

// fetchReferrer pulls the manifest for a single referrer descriptor and parses
// all of its layers as sigstore bundles.
func (c *Collector) fetchReferrer(
	ctx context.Context,
	rc *regclient.RegClient,
	subject *ref.Ref,
	desc *descriptor.Descriptor,
	opts *attestation.FetchOptions,
	parser *bundle.Parser,
) ([]attestation.Envelope, error) {
	// Build a reference to the referrer artifact by digest.
	rRef := subject.SetDigest(desc.Digest.String())

	m, err := rc.ManifestGet(ctx, rRef)
	if err != nil {
		return nil, fmt.Errorf("fetching referrer manifest: %w", err)
	}

	// Check if this referrer is a sigstore bundle. Some registries don't
	// propagate the manifest artifactType into the referrer descriptor, so
	// we check both the descriptor and the manifest itself.
	if !isSigstoreBundle(desc, m) {
		return nil, nil
	}

	mi, ok := m.(manifest.Imager)
	if !ok {
		return nil, fmt.Errorf("referrer manifest is not an image manifest")
	}

	layers, err := mi.GetLayers()
	if err != nil {
		return nil, fmt.Errorf("getting referrer layers: %w", err)
	}

	var atts []attestation.Envelope
	for j := range layers {
		blob, err := rc.BlobGet(ctx, rRef, layers[j])
		if err != nil {
			logrus.Debugf("oci: skipping layer %d: pulling blob: %v", j, err)
			continue
		}

		data, err := io.ReadAll(readlimit.Reader(blob, opts.MaxReadSize))
		if err := blob.Close(); err != nil {
			logrus.Debugf("oci: closing blob %d: %v", j, err)
		}
		if err != nil {
			logrus.Debugf("oci: skipping layer %d: reading blob: %v", j, err)
			continue
		}

		envs, err := parser.Parse(data)
		if err != nil {
			logrus.Debugf("oci: skipping layer %d: parsing bundle: %v", j, err)
			continue
		}

		atts = append(atts, envs...)
	}

	return atts, nil
}

// isSigstoreBundle returns true when the referrer looks like a sigstore bundle.
// It checks the descriptor-level artifactType first (which works on compliant
// registries) and falls back to inspecting the manifest's own artifactType and
// layer media types (needed for registries like GHCR that populate the
// descriptor artifactType from the config mediaType instead).
func isSigstoreBundle(desc *descriptor.Descriptor, m manifest.Manifest) bool {
	if desc.ArtifactType == sigstoreBundleArtifactType {
		return true
	}

	// Check layer media types as a fallback. When a registry does not
	// propagate artifactType correctly the layers still carry the bundle
	// media type.
	if mi, ok := m.(manifest.Imager); ok {
		if layers, err := mi.GetLayers(); err == nil {
			for i := range layers {
				if layers[i].MediaType == sigstoreBundleArtifactType {
					return true
				}
			}
		}
	}

	return false
}
