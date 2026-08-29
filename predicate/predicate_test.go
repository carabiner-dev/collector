// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package predicate

import (
	"os"
	"testing"

	"github.com/carabiner-dev/attestation"
	protoOSV "github.com/carabiner-dev/osv/go/osv"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/predicate/json"
	"github.com/carabiner-dev/collector/predicate/osv"
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

// TestGetTypeParsersLegacyOSVType ensures that a @v1.6.7 type hint selects the
// OSV parser (registered under @v1) via SupportsType, so the predicate is
// returned as *osv.Results and not as a generic DataMap.
func TestGetTypeParsersLegacyOSVType(t *testing.T) {
	t.Parallel()
	data := mustReadFile(t, "osv/testdata/osv-scan-2.0.0.json")
	pred, err := Parsers.Parse(data, WithTypeHints([]attestation.PredicateType{
		"https://ossf.github.io/osv-schema/results@v1.6.7",
	}))
	require.NoError(t, err)
	require.NotNil(t, pred)
	_, ok := pred.GetParsed().(*protoOSV.Results)
	require.True(t, ok, "expected *osv.Results, got %T", pred.GetParsed())
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

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
		// Legacy @v1.6.7 type hint must select the OSV parser (registered as @v1).
		// Regression test for GetTypeParsers ignoring SupportsType.
		{
			name: "osv-legacy-type-hint",
			data: mustReadFile(t, "osv/testdata/osv-scan-2.0.0.json"),
			options: []ParseOption{
				WithTypeHints([]attestation.PredicateType{"https://ossf.github.io/osv-schema/results@v1.6.7"}),
			},
			expectType: osv.PredicateType,
		},
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
