// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package coci

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/envelope"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	ggcr "github.com/google/go-containerregistry/pkg/v1"
)

var TypeMoniker = "coci"

// ImageInfo contains parsed information about a container image reference
type ImageInfo struct {
	OriginalRef string
	Registry    string
	Repository  string
	Tag         string
	Digest      string
	Identifier  string
	IsDigest    bool
}

func parseImageReference(ctx context.Context, ref string) (*ImageInfo, error) {
	parsedRef, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference: %w", err)
	}

	info := &ImageInfo{
		OriginalRef: ref,
		Registry:    parsedRef.Context().RegistryStr(),
		Repository:  parsedRef.Context().RepositoryStr(),
		Identifier:  parsedRef.Identifier(),
	}

	// Check if it's a tag or digest reference
	if tag, ok := parsedRef.(name.Tag); ok {
		info.Tag = tag.TagStr()
		info.IsDigest = false

		digest, err := crane.Digest(ref, crane.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("getting reference digest: %w", err)
		}
		info.Digest = digest

	} else if digest, ok := parsedRef.(name.Digest); ok {
		info.Digest = digest.DigestStr()
		info.IsDigest = true
	}

	return info, nil
}

// Implement the factory function
var Build = func(istr string) (attestation.Repository, error) {
	return New()
}

var _ attestation.Fetcher = (*Collector)(nil)

func New(funcs ...optFn) (*Collector, error) {
	// Apply the functional options
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

type optFn = func(*Options) error
type Options struct {
	Reference string
}

func (o *Options) Validate() error {
	return nil
}

var defaultOptions = Options{}

type Collector struct {
	Options Options
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	imageInfo, err := parseImageReference(ctx, c.Options.Reference)
	if err != nil {
		return nil, err
	}

	// Fetch the manifest of the attached attestations:
	manifestData, err := crane.Manifest(
		fmt.Sprintf(
			"%s/%s:%s.att",
			imageInfo.Registry, imageInfo.Repository,
			strings.Replace(imageInfo.Digest, "sha256:", "sha256-", 1),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("fetting attestations manifest: %w", err)
	}

	manifest, err := ggcr.ParseManifest(bytes.NewReader(manifestData))
	if err != nil {
		return nil, fmt.Errorf("parsing attestations manifest: %w", err)
	}
	atts := []attestation.Envelope{}
	// Cycle each layer and fetch the blobs
	for i, l := range manifest.Layers {
		// We can only parse DSSE for now
		if l.MediaType != "application/vnd.dsse.envelope.v1+json" {
			continue
		}

		attRef := imageInfo.Registry + "/" + imageInfo.Repository + "@" + l.Digest.String()
		layer, err := crane.PullLayer(attRef, crane.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("pulling layer data: %w", err)
		}
		blob, err := layer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("fetching blob data: %w", err)
		}
		defer blob.Close() //nolint:errcheck

		latts, err := envelope.Parsers.Parse(blob)
		if err != nil {
			return nil, fmt.Errorf("parsing attestations from layer %d of %s", i, c.Options.Reference)
		}
		atts = append(atts, latts...)
	}

	// TODO()puerco: And get the certificate
	return atts, nil
}
