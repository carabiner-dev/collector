// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package openvex

import (
	"testing"

	"github.com/carabiner-dev/attestation"
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		data    string
		mustErr bool
	}{
		{"openvex", `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://openvex.dev/docs/example","author":"Wolfi J Inkinson","version":1,"statements":[]}`, false},
		{"openvex-bare-context", `{"@context":"https://openvex.dev/ns","author":"Wolfi J Inkinson","version":1}`, false},
		// Other JSON-LD formats carry a @context too and are not ours.
		{"spdx3", `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[]}`, true},
		{"context-array", `{"@context":["https://openvex.dev/ns/v0.2.0"]}`, true},
		{"no-context", `{"author":"Wolfi J Inkinson","version":1}`, true},
		{"not-json", `not json at all`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pred, err := New().Parse([]byte(tc.data))
			if tc.mustErr {
				require.ErrorIs(t, err, attestation.ErrNotCorrectFormat)
				return
			}
			require.NoError(t, err)
			require.Equal(t, PredicateType, pred.GetType())
			_, ok := pred.GetParsed().(*openvex.VEX)
			require.True(t, ok)
		})
	}
}
