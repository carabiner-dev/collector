// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package pypi

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	gopurl "github.com/package-url/packageurl-go"
)

// defaultIndexURL is the package index the collector reads from. Both the
// JSON API (/pypi/<project>/<version>/json) and the PEP 740 integrity API
// (/integrity/<project>/<version>/<file>/provenance) are served under it.
const defaultIndexURL = "https://pypi.org"

// fileNameQualifier is the purl qualifier that selects a single distribution
// file of a release (pkg:pypi/django@1.11.1?file_name=Django-1.11.1.tar.gz).
const fileNameQualifier = "file_name"

var defaultOptions = Options{
	IndexURL: defaultIndexURL,
}

type optFn = func(*Collector) error

// Options configures the PyPI collector.
type Options struct {
	// IndexURL is the base URL of the package index. Defaults to pypi.org.
	IndexURL string

	// PackageURL is the parsed package URL of the release (or single
	// distribution file) to read provenance for.
	PackageURL gopurl.PackageURL
}

// WithPackageURL sets the package URL from a purl string. An empty string
// is accepted and leaves the collector in "global" mode: no package is
// configured up-front and FetchBySubject resolves a purl per subject.
func WithPackageURL(purlStr string) optFn {
	return func(c *Collector) error {
		if purlStr == "" {
			return nil
		}
		purl, err := parsePurl(purlStr)
		if err != nil {
			return err
		}
		c.Options.PackageURL = purl
		return nil
	}
}

// WithIndexURL overrides the package index base URL.
func WithIndexURL(url string) optFn {
	return func(c *Collector) error {
		c.Options.IndexURL = strings.TrimRight(url, "/")
		return nil
	}
}

// Validate checks that the options are complete. A package URL is optional
// at configuration time: without one the collector runs in global mode.
func (o *Options) Validate() error {
	if o.IndexURL == "" {
		return errors.New("no index URL set")
	}
	if o.HasPackageURL() {
		return validatePurl(&o.PackageURL)
	}
	return nil
}

// HasPackageURL reports whether a package URL has been configured on the
// collector (i.e. it is not running in global mode).
func (o *Options) HasPackageURL() bool {
	return o.PackageURL.Name != ""
}

// parsePurl parses and validates a PyPI package URL, normalizing the
// project name the way the index expects it.
func parsePurl(purlStr string) (gopurl.PackageURL, error) {
	purl, err := gopurl.FromString(purlStr)
	if err != nil {
		return gopurl.PackageURL{}, fmt.Errorf("parsing package URL: %w", err)
	}
	if err := validatePurl(&purl); err != nil {
		return gopurl.PackageURL{}, err
	}
	purl.Name = normalizeName(purl.Name)
	return purl, nil
}

// validatePurl checks that a purl addresses a PyPI project and that a file
// name qualifier, when present, is accompanied by a version.
func validatePurl(purl *gopurl.PackageURL) error {
	if purl.Type != gopurl.TypePyPi {
		return fmt.Errorf("package URL type must be %q, got %q", gopurl.TypePyPi, purl.Type)
	}
	if purl.Name == "" {
		return errors.New("package URL has no project name")
	}
	if purl.Version == "" && purl.Qualifiers.Map()[fileNameQualifier] != "" {
		return fmt.Errorf("the %s qualifier requires a version", fileNameQualifier)
	}
	return nil
}

var nameSeparators = regexp.MustCompile(`[-_.]+`)

// normalizeName applies the PEP 503 project name normalization: runs of
// dashes, underscores and dots collapse to a single dash and the result is
// lowercased. This is the form the index APIs expect.
func normalizeName(name string) string {
	return strings.ToLower(nameSeparators.ReplaceAllString(name, "-"))
}
