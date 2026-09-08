// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/carabiner-dev/signer/key"
)

const (
	// runNamespace is the fixed path segment separating the repository from
	// the workflow run id in a locator. It is reserved so other things (for
	// example individual artifacts) can be addressed later without breaking
	// the format.
	runNamespace = "run"

	// zipExtension marks the artifacts and nested files that are expanded
	// instead of parsed.
	zipExtension = "zip"

	locatorFormat = "actions://<host>/<owner>/<repo>/run/<run-id>"
)

// defaultExtensions mirrors the filesystem collector's default extensions
// (see TestDefaultExtensions) plus zip, so zipped artifacts are expanded.
var defaultExtensions = []string{"json", "jsonl", "spdx", "cdx", "bundle", zipExtension}

var defaultOptions = Options{
	Retries: 5,
}

type optFn = func(*Collector) error

type Options struct {
	// Host is the GitHub host the run lives on: github.com, a GitHub
	// Enterprise Cloud data residency host (*.ghe.com) or a GitHub Enterprise
	// Server host. The REST API base URL is derived from it.
	Host string
	// Owner and Repo identify the repository the workflow run belongs to.
	Owner string
	Repo  string
	// RunID is the numeric id of the workflow run whose artifacts are read.
	RunID int64

	// Token authenticates GitHub API requests. Workflow run artifacts cannot
	// be downloaded anonymously, so a token is always required. When empty,
	// the GITHUB_TOKEN / GH_TOKEN environment variables are used as a
	// fallback.
	Token string

	// Extensions lists the file extensions (without the dot) of the artifacts
	// to download and of the files to parse inside them. Artifacts whose name
	// does not carry one of the extensions are skipped without downloading
	// them. When the list includes zip, artifacts named *.zip are downloaded
	// too and zip files found inside an artifact are expanded and scanned
	// with the same extensions. Defaults to the filesystem collector's
	// extensions plus zip.
	Extensions []string

	// Retries is the number of additional attempts (with exponential backoff)
	// made for each GitHub API request.
	Retries uint
}

// WithRunURL configures the collector from a workflow run locator:
//
//	actions://github.com/carabiner-labs/baseline-init/run/34180821665
//
// The host may be a GitHub Enterprise instance. The scheme is optional as the
// collector registry strips it before handing the string to Build.
func WithRunURL(locator string) optFn {
	return func(c *Collector) error {
		return parseRunURL(locator, &c.Options)
	}
}

// WithHost sets the GitHub host the run lives on (github.com, a *.ghe.com
// host or a GitHub Enterprise Server).
func WithHost(host string) optFn {
	return func(c *Collector) error {
		c.Options.Host = host
		return nil
	}
}

// WithRepo sets the repository the run belongs to as an owner/repo slug.
func WithRepo(slug string) optFn {
	return func(c *Collector) error {
		owner, repo, ok := strings.Cut(slug, "/")
		if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
			return fmt.Errorf("invalid repository %q, expected owner/repo", slug)
		}
		c.Options.Owner = owner
		c.Options.Repo = repo
		return nil
	}
}

// WithRunID sets the id of the workflow run whose artifacts are read.
func WithRunID(id int64) optFn {
	return func(c *Collector) error {
		c.Options.RunID = id
		return nil
	}
}

// WithToken sets the access token used to authenticate against GitHub. When
// unset, the GITHUB_TOKEN / GH_TOKEN environment variables are used as a
// fallback.
func WithToken(token string) optFn {
	return func(c *Collector) error {
		c.Options.Token = token
		return nil
	}
}

// WithExtensions sets the extensions of the artifacts to download and of the
// files to parse inside them. A leading dot is ignored. Include zip to expand
// zipped artifacts and nested zip files.
func WithExtensions(exts ...string) optFn {
	return func(c *Collector) error {
		c.Options.Extensions = make([]string, 0, len(exts))
		for _, e := range exts {
			c.Options.Extensions = append(c.Options.Extensions, strings.TrimPrefix(e, "."))
		}
		return nil
	}
}

// WithRetries sets how many times a GitHub API request is retried (with
// exponential backoff) before giving up. Zero disables retries.
func WithRetries(n uint) optFn {
	return func(c *Collector) error {
		c.Options.Retries = n
		return nil
	}
}

// WithKey adds keys used to verify detached signatures found next to the
// attestations in the artifacts.
func WithKey(keys ...key.PublicKeyProvider) optFn {
	return func(c *Collector) error {
		c.Keys = append(c.Keys, keys...)
		return nil
	}
}

// parseRunURL fills opts from a locator of the form
// actions://<host>/<owner>/<repo>/run/<run-id>.
func parseRunURL(locator string, opts *Options) error {
	s := locator
	if strings.HasPrefix(s, "//") {
		s = TypeMoniker + ":" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("parsing run locator %q: %w", locator, err)
	}
	if u.Scheme != TypeMoniker || u.Host == "" {
		return fmt.Errorf("invalid run locator %q, expected %s", locator, locatorFormat)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 4 || parts[0] == "" || parts[1] == "" || parts[2] != runNamespace {
		return fmt.Errorf("invalid run locator %q, expected %s", locator, locatorFormat)
	}
	id, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("invalid run id %q in %q, expected a positive integer", parts[3], locator)
	}
	opts.Host, opts.Owner, opts.Repo, opts.RunID = u.Host, parts[0], parts[1], id
	return nil
}

func (o *Options) Validate() error {
	errs := []error{}
	if o.Host == "" {
		errs = append(errs, errors.New("no GitHub host set"))
	}
	if o.Owner == "" || o.Repo == "" {
		errs = append(errs, errors.New("no repository set"))
	}
	if o.RunID <= 0 {
		errs = append(errs, errors.New("no workflow run id set"))
	}
	if len(o.Extensions) == 0 {
		errs = append(errs, errors.New("no artifact extensions set"))
	}
	return errors.Join(errs...)
}

// fileExtensions returns the extensions the filesystem collector parses inside
// an artifact: every configured extension except zip, which is expanded.
func (o *Options) fileExtensions() []string {
	return slices.DeleteFunc(slices.Clone(o.Extensions), func(e string) bool {
		return e == zipExtension
	})
}

// expandZips reports whether zip files found inside artifacts are expanded.
func (o *Options) expandZips() bool {
	return slices.Contains(o.Extensions, zipExtension)
}

// apiBaseURL derives the REST API base URL for a GitHub host following the
// gh CLI conventions: github.com is served by api.github.com, GitHub
// Enterprise Cloud data residency hosts (*.ghe.com) by api.<host> and GitHub
// Enterprise Server exposes the API under /api/v3.
func apiBaseURL(host string) string {
	h := strings.ToLower(host)
	switch {
	case h == "github.com" || h == "www.github.com" || h == "api.github.com":
		return "https://api.github.com"
	case strings.HasSuffix(h, ".ghe.com"):
		return "https://api." + h
	default:
		return "https://" + h + "/api/v3"
	}
}

// hasExtension reports whether name carries one of the extensions.
func hasExtension(name string, exts []string) bool {
	ext := strings.TrimPrefix(path.Ext(name), ".")
	return ext != "" && slices.Contains(exts, ext)
}
