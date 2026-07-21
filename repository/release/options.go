// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"errors"
	"strings"

	"github.com/carabiner-dev/github"
	"github.com/carabiner-dev/signer/key"
)

var defaultOptions = Options{
	Tag:     "latest",
	Retries: 5,
}

type optFn = func(*Collector) error

type Options struct {
	RepoURL string
	Tag     string
	// Token authenticates GitHub API requests. It is required to upload
	// attestations (Store) and to read from private releases. When empty, the
	// GITHUB_TOKEN / GH_TOKEN environment variables are used as a fallback.
	Token string
	// Retries is the number of additional attempts (with exponential backoff)
	// made for each release API request, both when reading a release (fetch)
	// and when uploading attestations (store).
	Retries uint
}

// WithInitURL is specially crafte
func WithReleaseURL(locator string) optFn {
	return func(c *Collector) error {
		repo, release, _ := strings.Cut(locator, "@")

		url, err := github.RepoFromString(repo)
		if err != nil {
			return err
		}
		c.Options.RepoURL = url

		if release != "" {
			c.Options.Tag = release
		}
		return nil
	}
}

func WithRepo(repo string) optFn {
	return func(c *Collector) error {
		url, err := github.RepoFromString(repo)
		if err != nil {
			return err
		}
		c.Options.RepoURL = url
		return nil
	}
}

func WithTag(tag string) optFn {
	return func(c *Collector) error {
		c.Options.Tag = tag
		return nil
	}
}

func WithKey(keys ...key.PublicKeyProvider) optFn {
	return func(c *Collector) error {
		c.Keys = append(c.Keys, keys...)
		return nil
	}
}

// WithToken sets the access token used to authenticate against GitHub. It is
// required to upload attestations to a release and to read from private
// releases. When unset, the GITHUB_TOKEN / GH_TOKEN environment variables are
// used as a fallback.
func WithToken(token string) optFn {
	return func(c *Collector) error {
		c.Options.Token = token
		return nil
	}
}

// WithRetries sets how many times a release request is retried (with
// exponential backoff) before giving up, for both fetch and store operations.
// Zero disables retries.
func WithRetries(n uint) optFn {
	return func(c *Collector) error {
		c.Options.Retries = n
		return nil
	}
}

func (o *Options) Validate() error {
	errs := []error{}
	if o.RepoURL == "" {
		errs = append(errs, errors.New("no repository URL set"))
	}
	return errors.Join(errs...)
}
