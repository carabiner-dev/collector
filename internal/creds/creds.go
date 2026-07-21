// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package creds resolves API access tokens for VCS hosting providers. It is
// shared by the collector's provider-specific drivers (GitHub today, GitLab in
// the future) so token resolution behaves consistently: an explicit token wins,
// otherwise the first non-empty variable from a provider's conventional
// environment variables is used.
package creds

import "os"

// Environment variables that conventionally hold access tokens, by provider.
// They are ordered by precedence.
var (
	GitHubEnvVars = []string{"GITHUB_TOKEN", "GH_TOKEN"}
	GitLabEnvVars = []string{"GITLAB_TOKEN", "CI_JOB_TOKEN"}
)

// Token resolves an access token. If explicit is non-empty it is returned
// unchanged. Otherwise the value of the first non-empty variable in envVars is
// returned. When nothing is found it returns an empty string; callers decide
// whether anonymous access is acceptable.
func Token(explicit string, envVars ...string) string {
	if explicit != "" {
		return explicit
	}
	for _, name := range envVars {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}
