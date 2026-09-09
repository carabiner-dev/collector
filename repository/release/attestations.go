// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/carabiner-dev/attestation"
	"github.com/cenkalti/backoff/v5"

	"github.com/carabiner-dev/collector/envelope/bundle"
	"github.com/carabiner-dev/collector/internal/creds"
)

// attestationsResponse mirrors the payload of the GitHub attestations API.
type attestationsResponse struct {
	Attestations []struct {
		Bundle *bundle.Envelope `json:"bundle"`
	} `json:"attestations"`
}

// fetchReleaseAttestations returns the attestations GitHub itself generates
// for an immutable release. These are not release assets: GitHub stores them
// in the repository's attestation store, keyed by the digest of the release's
// tag reference (the tag object for annotated tags, the commit otherwise),
// which is what `gh release verify` looks up. Releases that are not immutable
// have no such attestation, so nothing is returned for them.
func (c *Collector) fetchReleaseAttestations(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	owner, repo, err := c.ownerRepo()
	if err != nil {
		return nil, err
	}
	token := creds.Token(c.Options.Token, creds.GitHubEnvVars...)

	rel, err := c.fetchRelease(ctx, token, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("resolving release %q: %w", c.Options.Tag, err)
	}
	if !rel.Immutable {
		return nil, nil
	}

	sha, err := c.fetchTagRefSHA(ctx, token, owner, repo, rel.Tag)
	if err != nil {
		return nil, fmt.Errorf("resolving tag %q: %w", rel.Tag, err)
	}

	limit := opts.MaxReadSize
	if limit <= 0 {
		limit = maxResponseSize
	}
	endpoint := fmt.Sprintf(
		"%s/repos/%s/%s/attestations/%s:%s?per_page=100",
		c.apiBaseURL, owner, repo, digestAlgorithmFor(sha), sha,
	)
	body, err := withRetry(ctx, c.Options.Retries, func() ([]byte, error) {
		resp, err := c.ghRequest(ctx, http.MethodGet, endpoint, token, "", nil)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close() //nolint:errcheck
		// GitHub answers 404 when no attestations are attached to the digest.
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return readResponse(resp, limit)
	})
	if err != nil {
		return nil, fmt.Errorf("fetching release attestations: %w", err)
	}
	if body == nil {
		return nil, nil
	}

	res := &attestationsResponse{}
	if err := json.Unmarshal(body, res); err != nil {
		return nil, fmt.Errorf("decoding attestations response: %w", err)
	}
	envs := make([]attestation.Envelope, 0, len(res.Attestations))
	for _, a := range res.Attestations {
		if a.Bundle == nil {
			continue
		}
		envs = append(envs, a.Bundle)
	}
	return envs, nil
}

// fetchTagRefSHA returns the object SHA the tag reference points to.
func (c *Collector) fetchTagRefSHA(ctx context.Context, token, owner, repo, tag string) (string, error) {
	endpoint := fmt.Sprintf(
		"%s/repos/%s/%s/git/ref/tags/%s", c.apiBaseURL, owner, repo, url.PathEscape(tag),
	)
	body, err := withRetry(ctx, c.Options.Retries, func() ([]byte, error) {
		resp, err := c.ghRequest(ctx, http.MethodGet, endpoint, token, "", nil)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close() //nolint:errcheck
		return readResponse(resp, maxResponseSize)
	})
	if err != nil {
		return "", err
	}

	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := json.Unmarshal(body, &ref); err != nil {
		return "", fmt.Errorf("decoding ref response: %w", err)
	}
	if ref.Object.SHA == "" {
		return "", backoff.Permanent(errors.New("ref response has no object sha"))
	}
	return ref.Object.SHA, nil
}

// digestAlgorithmFor returns the algorithm name matching the length of a git
// object id: sha256 for SHA-256 repositories, sha1 otherwise.
func digestAlgorithmFor(sha string) string {
	if len(sha) == 64 {
		return "sha256"
	}
	return "sha1"
}
