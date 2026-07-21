// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package creds

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestToken(t *testing.T) {
	primary, secondary := GitHubEnvVars[0], GitHubEnvVars[1]
	for _, tc := range []struct {
		name     string
		explicit string
		env      map[string]string
		lookup   []string
		expect   string
	}{
		{
			name:     "explicit-wins-over-env",
			explicit: "explicit",
			env:      map[string]string{primary: "from-env"},
			lookup:   []string{primary},
			expect:   "explicit",
		},
		{
			name:   "first-env-var-set",
			env:    map[string]string{primary: "", secondary: "gh"},
			lookup: GitHubEnvVars,
			expect: "gh",
		},
		{
			name:   "env-precedence-order",
			env:    map[string]string{primary: "primary-tok", secondary: "secondary-tok"},
			lookup: GitHubEnvVars,
			expect: "primary-tok",
		},
		{
			name:   "nothing-set",
			env:    map[string]string{primary: "", secondary: ""},
			lookup: GitHubEnvVars,
			expect: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			require.Equal(t, tc.expect, Token(tc.explicit, tc.lookup...))
		})
	}
}
