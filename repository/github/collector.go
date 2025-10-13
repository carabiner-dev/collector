// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package github implements a collector that reads from the GitHub attestations
// store.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/carabiner-dev/attestation"
	gh "github.com/carabiner-dev/github"
	ita "github.com/in-toto/attestation/go/v1"

	"github.com/carabiner-dev/collector/envelope/bundle"
)

const (
	// Endpoint to store attestation
	gitHubAttestationsUploadEndpoint = `repos/%s/%s/attestations`
	TypeMoniker                      = "github"
)

// Ensure the collector implements the interfaces
var (
	_ attestation.Fetcher          = (*Collector)(nil)
	_ attestation.FetcherBySubject = (*Collector)(nil)
	_ attestation.Storer           = (*Collector)(nil)
)

// Implement the factory function
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithRepo(istr))
}

type Collector struct {
	Options Options
	client  *gh.Client
}

type Options struct {
	Owner string
	Repo  string
}

type optFn = func(*Options)

func WithOwner(owner string) optFn {
	return func(opts *Options) {
		opts.Owner = owner
	}
}

func WithRepo(repo string) optFn {
	return func(opts *Options) {
		owner, r, sino := strings.Cut(repo, "/")
		if sino {
			opts.Owner = owner
			opts.Repo = r
		} else {
			opts.Repo = repo
		}
	}
}

var SupportedAlgorithms = []string{
	string(ita.AlgorithmSHA256), string(ita.AlgorithmSHA512),
}

// New returns a new collector
func New(funcs ...optFn) (*Collector, error) {
	// Apply the functional options
	opts := Options{}
	for _, fn := range funcs {
		fn(&opts)
	}

	c, err := gh.NewClient()
	if err != nil {
		return nil, err
	}
	return &Collector{
		Options: opts,
		client:  c,
	}, nil
}

type attResponse struct {
	Attestations []struct {
		Bundle       *bundle.Envelope `json:"bundle"`
		RepositoryID int64            `json:"repository_id"`
		BundleURL    string           `json:"bundle_url"`
	} `json:"attestations"`
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return nil, attestation.ErrFetcherMethodNotImplemented
}

// FetchBySubject is the only method supported as the GitHub api can only list
// attestations by subject.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	if c.Options.Owner == "" && c.Options.Repo == "" {
		return nil, fmt.Errorf("missing repository data")
	}

	// Build a list of subjects to query
	subjects := map[string]string{}
	for _, s := range subj {
		for algo, value := range s.GetDigest() {
			algo = strings.ToLower(algo)
			if !slices.Contains(SupportedAlgorithms, strings.ToLower(algo)) {
				continue
			}
			subjects[fmt.Sprintf("%s:%s", algo, value)] = s.GetName()
		}
	}
	ret := []attestation.Envelope{}
	// Get all the attestations up to Options.
	for digest := range subjects {
		url := fmt.Sprintf("users/%s/attestations/%s", c.Options.Owner, digest)
		if c.Options.Repo != "" {
			url = fmt.Sprintf("/repos/%s/%s/attestations/%s", c.Options.Owner, c.Options.Repo, digest)
		}

		envs, _, err := c.fetchFromUrl(ctx, url)
		// TODO(puerco): Keep fetching until limit
		if err != nil {
			return nil, fmt.Errorf("fetching attestations: %w", err)
		}
		ret = append(ret, envs...)
	}
	return ret, nil
}

// fetchFromUrl fetches a page of attestations from the GitHub api. At some point
// this will return true in the boolean if more requests are needed.
//
//nolint:unparam
func (c *Collector) fetchFromUrl(ctx context.Context, url string) ([]attestation.Envelope, bool, error) {
	ret := []attestation.Envelope{}

	// Call the API:
	resp, err := c.client.Call(ctx, http.MethodGet, url, nil)
	if err != nil {
		// If we get a 404 here, it means there are no attestations.
		// TODO(puerco): Use an HTTP error
		if strings.Contains(err.Error(), "HTTP Error 404") {
			return ret, false, nil
		}
		return nil, false, err
	}
	defer resp.Body.Close() //nolint:errcheck
	res := &attResponse{}

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(res); err != nil {
		return nil, false, fmt.Errorf("parsing response: %w", err)
	}

	for _, e := range res.Attestations {
		ret = append(ret, e.Bundle)
	}
	return ret, false, nil
}

type uploadRequestValueParsed struct {
	Bundle preParsedBundle `json:"bundle"`
}

type preParsedBundle []byte

func (ppb preParsedBundle) MarshalJSON() ([]byte, error) {
	return ppb, nil
}

// Store implements the attestations.Storer interface
func (c *Collector) Store(ctx context.Context, _ attestation.StoreOptions, envelopes []attestation.Envelope) error {
	// Cal the API to upload the bundle
	for _, env := range envelopes {
		envelopeData, err := json.Marshal(env)
		if err != nil {
			return fmt.Errorf("marshaling envelope data: %w", err)
		}

		payload := uploadRequestValueParsed{
			Bundle: preParsedBundle(envelopeData),
		}

		payloadData, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshaling payload: %w", err)
		}

		res, err := c.client.Call(
			ctx, http.MethodPost,
			fmt.Sprintf(gitHubAttestationsUploadEndpoint, c.Options.Owner, c.Options.Repo),
			bytes.NewReader(payloadData),
		)
		if err != nil {
			return fmt.Errorf("uploading attestation bundle: %w", err)
		}
		res.Body.Close() //nolint:errcheck,gosec
	}

	return nil
}
