// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package collector

import "github.com/carabiner-dev/attestation"

var defaultOptions = Options{
	UserAgentString:  "carabiner-collector/v1",
	FailIfNoFetchers: false,
	UseCache:         true,
	ParallelFetches:  4,
	ParallelStores:   4,
	Fetch:            attestation.FetchOptions{},
	Store:            attestation.StoreOptions{},
}

// Options groups the configuration knob for the collector agent
type Options struct {
	UserAgentString string

	// FailIfNoFetchers Return an error when fetching if no repos are configured (instead of just nil)
	FailIfNoFetchers bool

	// Use cache controls if the agent uses the attestation cache
	UseCache bool

	ParallelFetches int
	ParallelStores  int
	Fetch           attestation.FetchOptions
	Store           attestation.StoreOptions
}

type InitFunction func(*Agent) error

func WithRepository(repo attestation.Repository) InitFunction {
	return func(agent *Agent) error {
		return agent.AddRepository(repo)
	}
}

func WithParallelFetches(threads int) InitFunction {
	return func(agent *Agent) error {
		agent.Options.ParallelFetches = threads
		return nil
	}
}

func WithParallelStores(threads int) InitFunction {
	return func(agent *Agent) error {
		agent.Options.ParallelStores = threads
		return nil
	}
}

// FetchOptionsFunc are functions to define options when fetching
type FetchOptionsFunc func(*attestation.FetchOptions)

// WithQuery passes a query to the options set
func WithQuery(q *attestation.Query) FetchOptionsFunc {
	return func(opts *attestation.FetchOptions) {
		opts.Query = q
	}
}

// WithLimit sets the maximum number of attestations to be returned by the agent
func WithLimit(n int) FetchOptionsFunc {
	return func(o *attestation.FetchOptions) {
		o.Limit = n
	}
}

// StoreOptionsFunc are functions to define options when fetching
type StoreOptionsFunc func(*attestation.StoreOptions)
