// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package http implements an attestations collector that reads
// data from an https endpoint.
package http

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/carabiner-dev/attestation"
	"sigs.k8s.io/release-utils/http"

	"github.com/carabiner-dev/collector/envelope"
)

type optFn = func(*Options) error

// WithReadJSONL sets the options to assume the data read will be in linear
// json data.
func WithReadJSONL(doit bool) optFn {
	return func(opts *Options) error {
		opts.ReadJSONL = doit
		return nil
	}
}

// WithRetries fetches the number of retires to read
func WithRetries(num uint) optFn {
	return func(opts *Options) error {
		opts.Retries = num
		return nil
	}
}

// WithURL sets the URl to fetch the data
func WithURL(uriString string) optFn {
	return func(opts *Options) error {
		_, err := url.Parse(uriString)
		if err != nil {
			return err
		}
		opts.URL = uriString
		return nil
	}
}

var TypeMoniker = "http"

// Implement the factory function
var Build = func(uriString string) (attestation.Repository, error) {
	return New(WithURL(uriString))
}

var _ attestation.Fetcher = (*Collector)(nil)

type Collector struct {
	Options Options
}

type Options struct {
	URL       string
	Retries   uint
	ReadJSONL bool
}

var defaultOptions = Options{
	Retries:   3,
	ReadJSONL: true,
}

func New(funcs ...optFn) (*Collector, error) {
	opts := defaultOptions
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return nil, err
		}
	}
	return &Collector{
		Options: opts,
	}, nil
}

// Fetch fetches attestation data from the source
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	urlString := c.Options.URL
	if urlString == "" {
		return nil, fmt.Errorf("unable to do request, url empty")
	}
	a := http.NewAgent().WithRetries(c.Options.Retries).WithFailOnHTTPError(true)
	data, err := a.Get(urlString)
	if err != nil {
		if strings.Contains(err.Error(), "HTTP error 404") {
			return []attestation.Envelope{}, nil
		}
		return nil, fmt.Errorf("fetching http data: %w", err)
	}

	var attestations []attestation.Envelope
	// Parse the request output
	if c.Options.ReadJSONL {
		attestations, err = envelope.NewJSONL().Parse(data)
	} else {
		attestations, err = envelope.Parsers.Parse(bytes.NewReader(data))
	}
	if err != nil {
		return nil, fmt.Errorf("parsing attestation data: %w", err)
	}
	return attestations, err
}
