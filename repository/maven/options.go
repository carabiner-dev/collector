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

// WithPackageURL sets the package URL from a purl string.
func WithPackageURL(purlStr string) optFn {
	return func(c *Collector) error {
		purl, err := gopurl.FromString(purlStr)
		if err != nil {
			return fmt.Errorf("parsing package URL: %w", err)
		}
		if purl.Type != "maven" {
			return fmt.Errorf("unsupported package type %q, expected maven", purl.Type)
		}
		if purl.Namespace == "" || purl.Name == "" || purl.Version == "" {
			return fmt.Errorf("maven purl must include namespace, name, and version")
		}
		c.Options.PackageURL = purl
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

// Validate checks that the options are complete.
func (o *Options) Validate() error {
	if o.BaseURL == "" {
		return errors.New("no base URL set")
	}
	if o.PackageURL.Name == "" {
		return errors.New("no package URL set")
	}
	return nil
}

// directoryURL returns the Maven repository directory URL for the artifact.
// For example, pkg:maven/com.aliyun/alibabacloud-ga20191120@3.0.1 becomes:
// https://repo.maven.apache.org/maven2/com/aliyun/alibabacloud-ga20191120/3.0.1/
func (o *Options) directoryURL() string {
	// Convert namespace dots to path separators.
	namespacePath := strings.ReplaceAll(o.PackageURL.Namespace, ".", "/")
	return fmt.Sprintf("%s/%s/%s/%s/",
		o.BaseURL, namespacePath, o.PackageURL.Name, o.PackageURL.Version,
	)
}

// artifactBaseName returns the base name for the main artifact.
// For example: alibabacloud-ga20191120-3.0.1
func (o *Options) artifactBaseName() string {
	return fmt.Sprintf("%s-%s", o.PackageURL.Name, o.PackageURL.Version)
}
