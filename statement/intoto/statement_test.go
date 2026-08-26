// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package intoto

import (
	"encoding/json"
	"testing"

	"github.com/carabiner-dev/attestation"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"
)

func TestToJson(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		mustErr bool
		att     string
	}{
		{
			name:    "regular",
			mustErr: false,
			att: `{
				"predicateType": "https://carabiner.dev/ampel/policyset/v0",
				"predicate": { "Hello": "World" },
				"_type": "https://in-toto.io/Statement/v1",
				"subject": [{"digest": {"sha256": "e5997c5a773219927a05835a661f1d35736ed88a25fbce5c08258325b433b513"}}]
            }`,
		},
		{
			name:    "no-subject",
			mustErr: false,
			att: `{
				"predicateType": "https://carabiner.dev/ampel/policyset/v0",
				"predicate": { "Hello": "World" },
				"_type": "https://in-toto.io/Statement/v1",
				"subject": []
            }`,
		},
		{
			name:    "nil-subject",
			mustErr: false,
			att: `{
				"predicateType": "https://carabiner.dev/ampel/policyset/v0",
				"predicate": { "Hello": "World" },
				"_type": "https://in-toto.io/Statement/v1"
            }`,
		},
		{
			name:    "no-type",
			mustErr: false,
			att: `{
				"predicateType": "https://carabiner.dev/ampel/policyset/v0",
				"predicate": { "Hello": "World" },
				"_type": "",
				"subject": [{"digest": {"sha256": "e5997c5a773219927a05835a661f1d35736ed88a25fbce5c08258325b433b513"}}]
            }`,
		},
		{
			name:    "no-predicateType",
			mustErr: false,
			att: `{
				"predicateType": "",
				"predicate": { "Hello": "World" },
				"_type": "https://in-toto.io/Statement/v1",
				"subject": [{"digest": {"sha256": "e5997c5a773219927a05835a661f1d35736ed88a25fbce5c08258325b433b513"}}]
            }`,
		},
		{
			name:    "no-predicate",
			mustErr: false,
			att: `{
				"predicateType": "https://carabiner.dev/ampel/policyset/v0",
				"_type": "https://in-toto.io/Statement/v1",
				"subject": [{"digest": {"sha256": "e5997c5a773219927a05835a661f1d35736ed88a25fbce5c08258325b433b513"}}]
            }`,
		},
		{
			name:    "no-predicate-no-subject",
			mustErr: false,
			att: `{
				"predicateType": "https://carabiner.dev/ampel/policyset/v0",
				"_type": "https://in-toto.io/Statement/v1",
				"subject": []
            }`,
		},
		{
			name:    "bad-json",
			mustErr: true,
			att: `{
				"predicateType": "https://carabiner.dev/ampel/policyset/v0",
				"_type": "https://in-toto.io/Statement/v1",
				"subject": [
            }`,
		},
		{
			name:    "type-no-dash",
			mustErr: false,
			att: `{
				"predicateType": "https://carabiner.dev/ampel/policyset/v0",
				"type": "https://in-toto.io/Statement/v1",
				"subject": []
            }`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := &Parser{}
			parsed, err := p.Parse([]byte(tt.att))
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, parsed)
		})
	}
}

// TestSerializeKeys Tests the consistency of serializing/deserializing by
// roundtripping the data and ensuring fields are present and match
func TestSerializeKeys(t *testing.T) {
	t.Parallel()
	att := `{
		"predicateType": "https://carabiner.dev/ampel/policyset/v0",
		"predicate": { "Hello": "World" },
		"_type": "https://in-toto.io/Statement/v1",
		"subject": [{"digest": {"sha256": "e5997c5a773219927a05835a661f1d35736ed88a25fbce5c08258325b433b513"}}]
    }`
	p := &Parser{}
	parsed, err := p.Parse([]byte(att))
	require.NoError(t, err)

	// CHeck the parsed values
	require.Equal(t, attestation.PredicateType("https://carabiner.dev/ampel/policyset/v0"), parsed.GetPredicateType())
	require.Equal(t, "https://in-toto.io/Statement/v1", parsed.GetType())
	require.Len(t, parsed.GetSubjects(), 1)
	require.Len(t, parsed.GetSubjects()[0].GetDigest(), 1)
	require.Equal(t, "e5997c5a773219927a05835a661f1d35736ed88a25fbce5c08258325b433b513", parsed.GetSubjects()[0].GetDigest()["sha256"])

	// Check the raw in-toto
	itt, ok := parsed.(*Statement)
	require.True(t, ok)

	require.Equal(t, "https://in-toto.io/Statement/v1", itt.Type)
	require.Empty(t, itt.Statement.GetType(), "the proto's type must be moved, not copied")
	require.Empty(t, itt.Statement.GetPredicateType(), "the proto's predicate type must be moved, not copied")
	require.Equal(t, attestation.PredicateType("https://carabiner.dev/ampel/policyset/v0"), itt.PredicateType)
	require.Len(t, itt.Subject, 1)
	require.Len(t, itt.Subject[0].Digest, 1)                                                                              //nolint:protogetter
	require.Equal(t, "e5997c5a773219927a05835a661f1d35736ed88a25fbce5c08258325b433b513", itt.Subject[0].Digest["sha256"]) //nolint:protogetter

	// Now reserialize
	data, err := itt.ToJson()
	require.NoError(t, err)

	// Parse to a map to verify
	mapa := map[string]any{}
	require.NoError(t, json.Unmarshal(data, &mapa))

	// Test the fields
	require.Equal(t, "https://carabiner.dev/ampel/policyset/v0", mapa["predicateType"])
	require.Equal(t, "https://in-toto.io/Statement/v1", mapa["_type"])
	_, ok = mapa["subject"]
	require.True(t, ok)
	require.NotContains(t, mapa, "type", "the proto's Go JSON name must not render")
	require.NotContains(t, mapa, "predicate_type", "the proto's Go JSON name must not render")
}

// Statements must render the same in-toto JSON keys whether they are
// written through WriteJson or marshaled directly with encoding/json, and
// whether they were parsed or built with NewStatement. Regression test for
// https://github.com/carabiner-dev/collector/issues/39, where a parsed
// statement rendered "_type": "" next to "type": "<uri>".
func TestStatementJSONKeys(t *testing.T) {
	t.Parallel()
	const uri = "https://in-toto.io/Statement/v1"
	parsed, err := (&Parser{}).Parse([]byte(`{
		"_type": "` + uri + `",
		"predicateType": "https://in-toto.io/attestation/release/v0.1",
		"predicate": {"tag": "v1.0"},
		"subject": [{"uri": "pkg:github/puerco/test-immutable-releases@v1.0", "digest": {"sha1": "3ede92d1d86076be3e238618b5a54c8189668e3f"}}]
	}`))
	require.NoError(t, err)

	built := NewStatement(
		WithPredicate(parsed.GetPredicate()),
		WithSubject(&gointoto.ResourceDescriptor{Uri: "pkg:x", Digest: map[string]string{"sha256": "aa"}}),
	)
	require.Equal(t, uri, parsed.GetType())
	require.Equal(t, uri, built.GetType(), "a built statement must report its type too")
	parsedStmt, ok := parsed.(*Statement)
	require.True(t, ok)

	for name, stmt := range map[string]*Statement{"parsed": parsedStmt, "built": built} {
		for _, render := range []struct {
			name string
			fn   func() ([]byte, error)
		}{
			{"json.Marshal", func() ([]byte, error) { return json.Marshal(stmt) }},
			{"ToJson", stmt.ToJson},
		} {
			t.Run(name+"/"+render.name, func(t *testing.T) {
				t.Parallel()
				data, err := render.fn()
				require.NoError(t, err)

				got := map[string]any{}
				require.NoError(t, json.Unmarshal(data, &got))
				require.Equal(t, uri, got["_type"])
				require.Equal(t, "https://in-toto.io/attestation/release/v0.1", got["predicateType"])
				require.NotContains(t, got, "type")
				require.NotContains(t, got, "predicate_type")
				require.Contains(t, got, "subject")
				require.Contains(t, got, "predicate")
			})
		}
	}
}
