// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sbomfs

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/carabiner-dev/signer/key"
)

var defaultOptions = Options{}

type optFn = func(*Collector) error

type Options struct {
	Path string
}

func WithPath(path string) optFn {
	return func(c *Collector) error {
		c.Options.Path = path
		return nil
	}
}

func WithKey(keys ...key.PublicKeyProvider) optFn {
	return func(c *Collector) error {
		c.Keys = append(c.Keys, keys...)
		return nil
	}
}

func (o *Options) Validate() error {
	if o.Path == "" {
		return errors.New("no SBOM path set")
	}
	return nil
}

// sanitizePredicateType converts a predicate type URI into a safe filename
// component by extracting the last path segment and replacing unsafe characters.
func sanitizePredicateType(pt string) string {
	// Take the last segment of the URI path.
	base := filepath.Base(pt)
	// Replace characters that are not safe for filenames.
	r := strings.NewReplacer("/", "_", ":", "_", " ", "_")
	return r.Replace(base)
}
