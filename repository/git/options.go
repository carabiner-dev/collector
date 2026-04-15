// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package jsonl implements an attestations collector that reads
// from files using the JSON Lines (jsonl) format.

package git

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/carabiner-dev/vcslocator"
)

type optFn = func(*Options) error

type Options struct {
	URL    string
	Path   string
	Ref    string
	Commit string
}

var defaultOptions = Options{}

func (o *Options) Validate() error {
	return nil
}

func WithLocator(init string) optFn {
	return func(opts *Options) error {
		// Detect plain local filesystem paths (including Windows paths like
		// C:\foo\bar) and rewrite them as file:// locators before URL parsing.
		// Without this, url.Parse treats the Windows drive letter as a scheme
		// and mangles the path.
		if isLocalPath(init) {
			head, tail := init, ""
			if i := strings.IndexAny(init, "@#"); i >= 0 {
				head, tail = init[:i], init[i:]
			}
			init = string(vcslocator.NewFromPath(head)) + tail
		}

		u, err := url.Parse(init)
		if err != nil {
			return fmt.Errorf("parsing url: %w", err)
		}
		path, branch, ok := strings.Cut(u.Path, "@")
		sch := u.Scheme
		if sch != "" {
			sch += "://"
		}
		opts.URL = sch + u.Hostname() + path
		if ok {
			opts.Ref = branch
		}
		opts.Path = u.Fragment
		return nil
	}
}

// isLocalPath reports whether s is a filesystem path rather than a URL. It
// treats anything without a recognized transport scheme as a local path.
func isLocalPath(s string) bool {
	for _, p := range []string{"http://", "https://", "ssh://", "file://", "git+http://", "git+https://", "git+ssh://", "git+file://"} {
		if strings.HasPrefix(s, p) {
			return false
		}
	}
	return true
}

func WithPath(path string) optFn {
	return func(opts *Options) error {
		opts.Path = path
		return nil
	}
}
