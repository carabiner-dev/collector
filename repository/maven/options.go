// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"errors"
	"fmt"
	"strings"

	gopurl "github.com/package-url/packageurl-go"
)

const defaultBaseURL = "https://repo.maven.apache.org/maven2"

var defaultOptions = Options{
	BaseURL: defaultBaseURL,
}

type optFn = func(*Collector) error

// Options configures the Maven collector.
type Options struct {
	// BaseURL is the Maven repository base URL. Defaults to Maven Central.
	BaseURL string

	// PackageURL is the parsed package URL for the Maven artifact.
	PackageURL gopurl.PackageURL
}

// WithPackageURL sets the package URL from a purl string. An empty string
// is accepted and leaves the collector in "global" mode — no package is
// configured up-front and FetchBySubject will resolve a purl per subject.
func WithPackageURL(purlStr string) optFn {
	return func(c *Collector) error {
		if purlStr == "" {
			return nil
		}
		purl, err := gopurl.FromString(purlStr)
		if err != nil {
			return fmt.Errorf("parsing package URL: %w", err)
		}
		if err := validateMavenPurl(&purl); err != nil {
			return err
		}
		c.Options.PackageURL = purl

		// Check for a repository_url qualifier to override the base URL.
		if baseURL, ok := purl.Qualifiers.Map()["repository_url"]; ok && baseURL != "" {
			c.Options.BaseURL = strings.TrimRight(baseURL, "/")
		}

		return nil
	}
}

// WithBaseURL overrides the Maven repository base URL.
func WithBaseURL(url string) optFn {
	return func(c *Collector) error {
		c.Options.BaseURL = strings.TrimRight(url, "/")
		return nil
	}
}

// Validate checks that the options are complete. A package URL is optional
// at configuration time: without one the collector runs in global mode,
// resolving the purl per subject in FetchBySubject.
func (o *Options) Validate() error {
	if o.BaseURL == "" {
		return errors.New("no base URL set")
	}
	return nil
}

// HasPackageURL reports whether a package URL has been configured on the
// collector (i.e. it is not running in global mode).
func (o *Options) HasPackageURL() bool {
	return o.PackageURL.Name != ""
}

// validateMavenPurl ensures a parsed purl is a well-formed Maven purl.
func validateMavenPurl(purl *gopurl.PackageURL) error {
	if purl.Type != "maven" {
		return fmt.Errorf("unsupported package type %q, expected maven", purl.Type)
	}
	if purl.Namespace == "" || purl.Name == "" || purl.Version == "" {
		return fmt.Errorf("maven purl must include namespace, name, and version")
	}
	return nil
}

// baseURLForPurl picks the base Maven repository URL for a purl. A
// "repository_url" qualifier on the purl wins; otherwise the provided
// fallback is returned.
func baseURLForPurl(purl *gopurl.PackageURL, fallback string) string {
	if v, ok := purl.Qualifiers.Map()["repository_url"]; ok && v != "" {
		return strings.TrimRight(v, "/")
	}
	return fallback
}

// directoryURL returns the Maven repository directory URL for a purl.
// For example, pkg:maven/com.aliyun/alibabacloud-ga20191120@3.0.1 becomes:
// https://repo.maven.apache.org/maven2/com/aliyun/alibabacloud-ga20191120/3.0.1/
func directoryURL(purl *gopurl.PackageURL, baseURL string) string {
	namespacePath := strings.ReplaceAll(purl.Namespace, ".", "/")
	return fmt.Sprintf("%s/%s/%s/%s/",
		strings.TrimRight(baseURL, "/"), namespacePath, purl.Name, purl.Version,
	)
}

// artifactType returns the Maven packaging type from a purl's "type"
// qualifier, defaulting to "jar" per the purl-spec.
func artifactType(purl *gopurl.PackageURL) string {
	if t, ok := purl.Qualifiers.Map()["type"]; ok && t != "" {
		return t
	}
	return "jar"
}

// artifactClassifier returns the "classifier" qualifier from a purl, or
// the empty string when absent.
func artifactClassifier(purl *gopurl.PackageURL) string {
	return purl.Qualifiers.Map()["classifier"]
}

// Thin Options wrappers kept for backward compatibility with existing tests
// that use the configured PackageURL.
func (o *Options) directoryURL() string { return directoryURL(&o.PackageURL, o.BaseURL) }
func (o *Options) artifactType() string { return artifactType(&o.PackageURL) }
func (o *Options) artifactClassifier() string {
	return artifactClassifier(&o.PackageURL)
}

func (o *Options) artifactBaseName() string {
	return fmt.Sprintf("%s-%s", o.PackageURL.Name, o.PackageURL.Version)
}
