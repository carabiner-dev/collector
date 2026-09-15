// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/stretchr/testify/require"
)

// hjsonPolicySet is a policy set as humans author it: not JSON, so it can
// only be a bare attestation.
const hjsonPolicySet = `{
    // A policy set in HJSON
    id: hjson-set
    meta: { version: 1 }
    policies: [ { id: "p", tenets: [ { id: "t", code: "true" } ] } ]
}`

func TestParseNonJSON(t *testing.T) {
	t.Parallel()

	t.Run("hjson-policy-is-a-bare-attestation", func(t *testing.T) {
		t.Parallel()
		envs, err := Parsers.Parse(bytes.NewReader([]byte(hjsonPolicySet)))
		require.NoError(t, err)
		require.Len(t, envs, 1)
		require.Equal(t, "https://carabiner.dev/ampel/policyset/v0", string(envs[0].GetStatement().GetPredicateType()))
	})

	t.Run("garbage-is-not-an-envelope-error", func(t *testing.T) {
		t.Parallel()
		_, err := Parsers.Parse(bytes.NewReader([]byte("\x00\x01 not json {")))
		require.ErrorIs(t, err, attestation.ErrNotCorrectFormat,
			"non-JSON data must fall through cleanly, not fail with a parser syntax error")
	})

	t.Run("bare-json-policy-still-parses", func(t *testing.T) {
		t.Parallel()
		envs, err := Parsers.Parse(bytes.NewReader([]byte(`{"id":"json-set","meta":{"version":1},"policies":[{"id":"p","tenets":[{"id":"t","code":"true"}]}]}`)))
		require.NoError(t, err)
		require.Len(t, envs, 1)
		require.Equal(t, "https://carabiner.dev/ampel/policyset/v0", string(envs[0].GetStatement().GetPredicateType()))
	})
}
