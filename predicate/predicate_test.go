// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package predicate

import (
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/predicate/json"
	"github.com/carabiner-dev/collector/predicate/spdx"
	"github.com/carabiner-dev/collector/predicate/spdx3"
)

// spdx3Doc is the smallest SPDX 3 document the parsers should route to the
// SPDX 3 parser instead of the generic JSON fallback.
const spdx3Doc = `{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "urn:uuid:b61745ef-59c7-4804-878d-fccbe455bd80",
      "name": "example"
    }
  ]
}`

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		data       []byte
		options    []ParseOption
		expectType attestation.PredicateType
		mustErr    bool
	}{
		{"generic-json-fallback", []byte(`{"hello":"world", "isIt": true, "int": 32}`), nil, json.PredicateType, false},
		{"generic-json-err", []byte(`{"hello":"world", "isIt": true, "int": 32}`), []ParseOption{WithDefaulToJSON(false)}, "", true},
		{"spdx3", []byte(spdx3Doc), nil, spdx3.PredicateType, false},
		{"spdx3-type-hint", []byte(spdx3Doc), []ParseOption{WithTypeHints([]attestation.PredicateType{spdx3.PredicateType})}, spdx3.PredicateType, false},
		// SPDX 2 keeps routing to its own parser, not the SPDX 3 one.
		{"spdx2", []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"example"}`), nil, spdx.PredicateType, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pred, err := Parsers.Parse(tc.data, tc.options...)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pred)
			require.Equal(t, tc.expectType, pred.GetType())
		})
	}
}
