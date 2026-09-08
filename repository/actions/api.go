// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cenkalti/backoff/v5"
)

const (
	githubAPIVersion = "2022-11-28"

	// artifactsPerPage is the page size used when listing a run's artifacts
	// (the maximum GitHub allows).
	artifactsPerPage = 100

	// maxListResponseSize bounds how much of an artifact listing page is read
	// into memory.
	maxListResponseSize = 4 << 20 // 4 MiB

	// maxErrorBodySize bounds how much of an error response is quoted in the
	// returned error.
	maxErrorBodySize = 1 << 10
)

// apiClient issues the GitHub API requests. It never follows redirects: the
// artifact download endpoint redirects to a blob storage URL and the token
// must not travel along (see downloadArtifact).
var apiClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// artifact is the subset of the GitHub artifact object the collector uses.
// SizeInBytes is the size of the zip archive delivered on download.
type artifact struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	SizeInBytes int64  `json:"size_in_bytes"`
	Expired     bool   `json:"expired"`
}

type artifactList struct {
	TotalCount int        `json:"total_count"`
	Artifacts  []artifact `json:"artifacts"`
}

// repoURL returns the API URL of the configured repository.
func (c *Collector) repoURL() string {
	return fmt.Sprintf(
		"%s/repos/%s/%s", c.apiBaseURL,
		url.PathEscape(c.Options.Owner), url.PathEscape(c.Options.Repo),
	)
}

// listArtifacts returns every artifact of the configured run, reading all the
// pages of the listing.
func (c *Collector) listArtifacts(ctx context.Context, token string) ([]artifact, error) {
	var all []artifact
	for page := 1; ; page++ {
		endpoint := fmt.Sprintf(
			"%s/actions/runs/%d/artifacts?per_page=%d&page=%d",
			c.repoURL(), c.Options.RunID, artifactsPerPage, page,
		)
		body, err := withRetry(ctx, c.Options.Retries, func() ([]byte, error) {
			resp, err := c.apiRequest(ctx, endpoint, token)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close() //nolint:errcheck
			return readResponse(resp, maxListResponseSize)
		})
		if err != nil {
			return nil, err
		}

		var list artifactList
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, fmt.Errorf("decoding artifact listing: %w", err)
		}
		all = append(all, list.Artifacts...)
		if len(list.Artifacts) < artifactsPerPage || len(all) >= list.TotalCount {
			return all, nil
		}
	}
}

// downloadArtifact returns the zip archive of an artifact. GitHub answers the
// download endpoint with a redirect to a short-lived blob storage URL, which
// is followed without credentials so the token never reaches a third party.
// The archive is read whole (zip needs random access) but never beyond
// maxSize bytes. Both hops are retried together as the redirect target
// expires within a minute.
func (c *Collector) downloadArtifact(ctx context.Context, token string, id, maxSize int64) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/actions/artifacts/%d/zip", c.repoURL(), id)
	return withRetry(ctx, c.Options.Retries, func() ([]byte, error) {
		resp, err := c.apiRequest(ctx, endpoint, token)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close() //nolint:errcheck

		if !isRedirect(resp.StatusCode) {
			return readResponse(resp, maxSize)
		}
		location := resp.Header.Get("Location")
		if location == "" {
			return nil, backoff.Permanent(errors.New("download redirect has no location"))
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
		if err != nil {
			return nil, backoff.Permanent(fmt.Errorf("building download request: %w", err))
		}
		blob, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer blob.Body.Close() //nolint:errcheck
		return readResponse(blob, maxSize)
	})
}

func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

// apiRequest issues an authenticated GET against the GitHub API. Redirects
// are returned to the caller instead of being followed.
func (c *Collector) apiRequest(ctx context.Context, endpoint, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, backoff.Permanent(fmt.Errorf("building request: %w", err))
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-Github-Api-Version", githubAPIVersion)
	return apiClient.Do(req)
}

// readResponse returns the body of a successful response, refusing bodies
// larger than limit. Non-2xx responses become errors: client errors other
// than 429 are permanent so they are not retried, while 429 and 5xx errors
// are retryable.
func readResponse(resp *http.Response, limit int64) ([]byte, error) {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		if resp.ContentLength > limit {
			return nil, backoff.Permanent(fmt.Errorf("response (%d bytes) exceeds max read size (%d bytes)", resp.ContentLength, limit))
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return nil, fmt.Errorf("reading response body: %w", err)
		}
		if int64(len(body)) > limit {
			return nil, backoff.Permanent(fmt.Errorf("response exceeds max read size (%d bytes)", limit))
		}
		return body, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
	if err != nil {
		body = nil
	}
	err = fmt.Errorf("github returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
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
