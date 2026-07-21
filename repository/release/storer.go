// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/cenkalti/backoff/v5"

	"github.com/carabiner-dev/collector/internal/creds"
)

const (
	defaultAPIBaseURL     = "https://api.github.com"
	defaultUploadsBaseURL = "https://uploads.github.com"
	githubAPIVersion      = "2022-11-28"

	// maxResponseSize bounds how much of a GitHub API response is read into
	// memory when resolving a release.
	maxResponseSize = 4 << 20 // 4 MiB
)

var _ attestation.Storer = (*Collector)(nil)

// Store implements the attestation.Storer interface. Each envelope is uploaded
// to the GitHub release identified by the collector's repository and tag as an
// individual, content-addressed release asset named "attestation-<sha256>.json".
// Uploads are retried with exponential backoff (see WithRetries) and any asset
// already present on the release is left in place, making Store idempotent.
//
// A token is required (WithToken, or the GITHUB_TOKEN / GH_TOKEN environment
// variables); GitHub does not permit anonymous writes.
func (c *Collector) Store(ctx context.Context, _ attestation.StoreOptions, envelopes []attestation.Envelope) error {
	if len(envelopes) == 0 {
		return nil
	}

	owner, repo, err := c.ownerRepo()
	if err != nil {
		return err
	}

	token := creds.Token(c.Options.Token, creds.GitHubEnvVars...)
	if token == "" {
		return errors.New(
			"a token is required to upload attestations to a release; set it with " +
				"WithToken or via the GITHUB_TOKEN environment variable",
		)
	}

	releaseID, err := c.fetchReleaseID(ctx, token, owner, repo)
	if err != nil {
		return fmt.Errorf("resolving release %q: %w", c.Options.Tag, err)
	}

	for i, env := range envelopes {
		data, err := json.Marshal(env)
		if err != nil {
			return fmt.Errorf("marshaling envelope #%d: %w", i, err)
		}
		name := assetName(data)
		if err := c.uploadAsset(ctx, token, owner, repo, releaseID, name, data); err != nil {
			return fmt.Errorf("uploading attestation %q: %w", name, err)
		}
	}
	return nil
}

// ownerRepo extracts the owner and repository slug from the configured repo URL.
func (c *Collector) ownerRepo() (owner, repo string, err error) {
	u, err := url.Parse(c.Options.RepoURL)
	if err != nil {
		return "", "", fmt.Errorf("parsing repository URL %q: %w", c.Options.RepoURL, err)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("repository URL %q does not contain an owner and repo", c.Options.RepoURL)
	}
	return parts[0], parts[1], nil
}

// fetchReleaseID resolves the numeric id of the release for the configured tag.
func (c *Collector) fetchReleaseID(ctx context.Context, token, owner, repo string) (int64, error) {
	endpoint := fmt.Sprintf(
		"%s/repos/%s/%s/releases/tags/%s",
		c.apiBaseURL, owner, repo, url.PathEscape(c.Options.Tag),
	)
	// The tagged-release endpoint does not resolve "latest"; use the dedicated
	// endpoint for it, mirroring how the collector reads releases.
	if c.Options.Tag == "" || c.Options.Tag == "latest" {
		endpoint = fmt.Sprintf("%s/repos/%s/%s/releases/latest", c.apiBaseURL, owner, repo)
	}

	body, err := withRetry(ctx, c.Options.Retries, func() ([]byte, error) {
		resp, err := c.ghRequest(ctx, http.MethodGet, endpoint, token, "", nil)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close() //nolint:errcheck
		return readResponse(resp, maxResponseSize)
	})
	if err != nil {
		return 0, err
	}

	var rel struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return 0, fmt.Errorf("decoding release response: %w", err)
	}
	if rel.ID == 0 {
		return 0, fmt.Errorf("release for tag %q not found", c.Options.Tag)
	}
	return rel.ID, nil
}

// uploadAsset uploads a single asset to the release. An asset that already
// exists (HTTP 422) is treated as success so repeated Store calls are
// idempotent.
func (c *Collector) uploadAsset(ctx context.Context, token, owner, repo string, releaseID int64, name string, data []byte) error {
	endpoint := fmt.Sprintf(
		"%s/repos/%s/%s/releases/%d/assets?name=%s",
		c.uploadsBaseURL, owner, repo, releaseID, url.QueryEscape(name),
	)

	_, err := withRetry(ctx, c.Options.Retries, func() ([]byte, error) {
		resp, err := c.ghRequest(ctx, http.MethodPost, endpoint, token, "application/json", data)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close() //nolint:errcheck
		// The asset is already on the release; nothing more to do.
		if resp.StatusCode == http.StatusUnprocessableEntity {
			return nil, nil
		}
		return readResponse(resp, maxResponseSize)
	})
	return err
}

// ghRequest issues an authenticated GitHub REST request. It does not interpret
// the status code; callers use readResponse to turn HTTP errors into (retryable
// or permanent) Go errors.
func (c *Collector) ghRequest(ctx context.Context, method, endpoint, token, contentType string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, backoff.Permanent(fmt.Errorf("building request: %w", err))
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-Github-Api-Version", githubAPIVersion)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return http.DefaultClient.Do(req)
}

// readResponse reads and returns the body of a successful response. Non-2xx
// responses become errors: client errors (4xx other than 429) are marked
// permanent so they are not retried, while 429 and 5xx errors are retryable.
func readResponse(resp *http.Response, limit int64) ([]byte, error) {
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit))
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		if readErr != nil {
			return nil, fmt.Errorf("reading response body: %w", readErr)
		}
		return body, nil
	}

	err := fmt.Errorf("github returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return nil, backoff.Permanent(err)
	}
	return nil, err
}

// withRetry runs op with exponential backoff, attempting it up to retries+1
// times. Errors wrapped with backoff.Permanent stop the retry loop early.
func withRetry(ctx context.Context, retries uint, op func() ([]byte, error)) ([]byte, error) {
	return backoff.Retry(
		ctx, op,
		backoff.WithBackOff(backoff.NewExponentialBackOff()),
		backoff.WithMaxTries(retries+1),
	)
}

// assetName returns a stable, content-addressed release-asset name for the
// given envelope bytes. Using the content digest keeps uploads idempotent:
// re-storing identical bytes resolves to the same asset name.
func assetName(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("attestation-%s.json", hex.EncodeToString(sum[:])[:16])
}
