// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package http implements an attestations collector that reads
// data from an https endpoint.
package ossrebuild

import (
	"context"
	"fmt"
	"strings"

	"github.com/carabiner-dev/attestation"
	gopurl "github.com/package-url/packageurl-go"

	"github.com/carabiner-dev/collector/repository/http"
)

var (
	_ attestation.Fetcher          = (*Collector)(nil)
	_ attestation.FetcherBySubject = (*Collector)(nil)
)

var TypeMoniker = "http"

// Implement the factory function
var Build = func(uriString string) (attestation.Repository, error) {
	return New()
}

// Ensure the collector variants implement the interfaces
var (
	_ attestation.Fetcher          = (*Collector)(nil)
	_ attestation.FetcherBySubject = (*Collector)(nil)
)

// New creates a new collector. The type of collector returned varies according
// to the specified URL templates.
func New() (*Collector, error) {
	return &Collector{}, nil
}

// Collector is the general collector that supports fetching from the OSS rebuild repo
type Collector struct{}

func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return nil, nil
}

func subjectsToOssRebuildURLS(subjects []attestation.Subject) []string {
	urls := []string{}
	for _, subject := range subjects {
		if !strings.Contains(subject.GetUri(), "pkg:") {
			continue
		}

		// Parse the package URL. For now we only support npm
		// pkg:npm/%40alloc/quick-lru@5.2.0
		purl, err := gopurl.FromString(subject.GetUri())
		if err != nil {
			// This is not a package URL, continue
			continue
		}

		switch purl.Type {
		case "npm":
			filename := purl.Name
			directory := purl.Name
			if purl.Namespace != "" {
				filename = strings.TrimPrefix(purl.Namespace, "@") + "-" + purl.Name
				directory = purl.Namespace + "/" + purl.Name
			}

			urls = append(urls,
				fmt.Sprintf(
					"https://storage.googleapis.com/google-rebuild-attestations/%s/%s/%s/%s-%s.tgz/rebuild.intoto.jsonl",
					purl.Type, directory, purl.Version, filename, purl.Version,
				))
		default:
			// Type not supported yet
			continue
		}
	}
	return urls
}

// FetchBySubject is the only method implemented. It fetches by getting a
// purl in the subject's URI
func (c *Collector) FetchBySubject(ctx context.Context, fo attestation.FetchOptions, subjects []attestation.Subject) ([]attestation.Envelope, error) {
	urls := subjectsToOssRebuildURLS(subjects)

	// Piggy back on the http collector to fetch
	hcollector, err := http.New(http.WithURL(urls...))
	if err != nil {
		return nil, err
	}

	return hcollector.Fetch(ctx, fo)
}
