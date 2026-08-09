// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package spdx3

import (
	"os"
	"testing"

	"github.com/carabiner-dev/attestation"
	spdx3 "github.com/carabiner-dev/spdx3"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/predicate/generic"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		file        string
		mustErr     bool
		badFormat   bool
		expectNodes int
	}{
		{"spdx3", "testdata/spdx3.json", false, false, 5},
		{"spdx2", "testdata/spdx2.json", true, true, 0},
		{"cyclonedx", "testdata/cyclonedx.json", true, true, 0},
		{"other-jsonld", "testdata/other.json", true, true, 0},
		{"invalid-json", "testdata/invalid-json.json", true, true, 0},
		// Sniffs as SPDX 3 but does not parse, so the parser must report why
		// instead of handing the data to the next parser in line.
		{"bad-graph", "testdata/bad-graph.json", true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(tc.file)
			require.NoError(t, err)

			pred, err := New().Parse(data)
			if tc.mustErr {
				require.Error(t, err)
				if tc.badFormat {
					require.ErrorIs(t, err, attestation.ErrNotCorrectFormat)
				} else {
					require.NotErrorIs(t, err, attestation.ErrNotCorrectFormat)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pred)
			require.Equal(t, PredicateType, pred.GetType())
			require.Equal(t, data, pred.GetData())

			_, ok := pred.(*generic.Predicate)
			require.True(t, ok)

			env, ok := pred.GetParsed().(*spdx3.Envelope)
			require.True(t, ok)
			require.Equal(t, "3.0.1", env.Context.Version())
			require.Len(t, env.Graph, tc.expectNodes)
		})
	}
}

func TestSniff(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		data   string
		expect bool
	}{
		{"context-301", `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[]}`, true},
		{"context-release-candidate", `{"@context":"https://spdx.github.io/spdx-spec/v3.0.1-RC1/rdf/spdx-context.jsonld"}`, true},
		{"context-array", `{"@context":["https://example.com/ctx.jsonld","https://spdx.org/rdf/3.0.1/spdx-context.jsonld"]}`, true},
		{"context-spdx2", `{"@context":"https://spdx.org/rdf/2.3/spdx-context.jsonld"}`, false},
		{"context-unknown", `{"@context":"https://openvex.dev/ns/v0.2.0"}`, false},
		{"context-inline-object", `{"@context":{"spdx":"https://spdx.org/rdf/terms#"}}`, false},
		{"no-context", `{"@graph":[],"type":"SpdxDocument"}`, false},
		{"spdx2-version-wins", `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","spdxVersion":"SPDX-2.3"}`, false},
		{"cyclonedx-bomformat-wins", `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","bomFormat":"CycloneDX"}`, false},
		{"not-json", `not json at all`, false},
		{"json-array", `[{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}]`, false},
		{"empty", ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expect, Sniff([]byte(tc.data)))
		})
	}
}

func TestSupportsType(t *testing.T) {
	t.Parallel()
	p := New()
	require.True(t, p.SupportsType(PredicateType))
	require.True(t, p.SupportsType("https://spdx.dev/Document", PredicateType))
	require.False(t, p.SupportsType("https://spdx.dev/Document"))
	require.False(t, p.SupportsType())
}
