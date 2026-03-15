// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"fmt"

	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/ref"
)

type (
	optFn   = func(*Options) error
	Options struct {
		Reference string
		regOpts   []regclient.Opt // optional regclient overrides (e.g. for testing)
	}
)

var defaultOptions = Options{}

// WithReference sets the OCI image reference for the collector.
func WithReference(r string) optFn {
	return func(o *Options) error {
		if _, err := ref.New(r); err != nil {
			return fmt.Errorf("invalid reference %q: %w", r, err)
		}
		o.Reference = r
		return nil
	}
}

// WithRegClientOpts sets custom regclient options (e.g. for testing).
func WithRegClientOpts(opts ...regclient.Opt) optFn {
	return func(o *Options) error {
		o.regOpts = opts
		return nil
	}
}

// Validate checks the options are complete.
func (o *Options) Validate() error {
	if o.Reference == "" {
		return fmt.Errorf("reference is required")
	}
	return nil
}
