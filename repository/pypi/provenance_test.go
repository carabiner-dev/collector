// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package pypi

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/stretchr/testify/require"
)

func loadProvenance(t *testing.T) *Provenance {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", wheelName+".provenance.json"))
	require.NoError(t, err)
	prov, err := ParseProvenance(data)
	require.NoError(t, err)
	return prov
}

func TestParseProvenance(t *testing.T) {
	t.Parallel()
	prov := loadProvenance(t)
	require.Equal(t, 1, prov.Version)
	require.Len(t, prov.AttestationBundles, 1)
	require.Len(t, prov.AttestationBundles[0].Attestations, 1)

	_, err := ParseProvenance([]byte(`{"version": 2, "attestation_bundles": []}`))
	require.Error(t, err)
	_, err = ParseProvenance([]byte(`not json`))
	require.Error(t, err)
}

func TestEnvelopesAllBundles(t *testing.T) {
	t.Parallel()
	// Duplicate the bundle: every attestation of every bundle is returned.
	prov := loadProvenance(t)
	prov.AttestationBundles = append(prov.AttestationBundles, prov.AttestationBundles[0])
	prov.AttestationBundles[1].Attestations = append(prov.AttestationBundles[1].Attestations, prov.AttestationBundles[1].Attestations[0])

	envs, err := prov.Envelopes(&Distribution{Project: "sampleproject", Version: "4.0.0", Filename: wheelName})
	require.NoError(t, err)
	require.Len(t, envs, 3)
}

func TestEnvelopesPassThrough(t *testing.T) {
	t.Parallel()
	// A statement with a real predicate is served as signed: no extension
	// is synthesized and the predicate type is the signed one.
	prov := loadProvenance(t)
	att := &prov.AttestationBundles[0].Attestations[0]
	att.Envelope.Statement = base64.StdEncoding.EncodeToString([]byte(`{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": [{"name": "` + wheelName + `", "digest": {"sha256": "` + wheelSHA256 + `"}}],
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {"buildType": "https://example.com/build"}}
	}`))

	envs, err := prov.Envelopes(&Distribution{Project: "sampleproject", Version: "4.0.0", Filename: wheelName})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	stmt := envs[0].GetStatement()
	require.NotNil(t, stmt)
	require.Equal(t, attestation.PredicateType("https://slsa.dev/provenance/v1"), stmt.GetPredicateType())
	require.Empty(t, stmt.GetSubjects()[0].GetUri())
	require.NotContains(t, string(envs[0].GetPredicate().GetData()), ExtensionKey)
}

func TestEnvelopesErrors(t *testing.T) {
	t.Parallel()
	dist := &Distribution{Project: "sampleproject", Version: "4.0.0", Filename: wheelName}
	for _, tc := range []struct {
		name   string
		mutate func(*Attestation)
	}{
		{"bad-version", func(a *Attestation) { a.Version = 2 }},
		{"bad-statement-base64", func(a *Attestation) { a.Envelope.Statement = "!!" }},
		{"bad-signature-base64", func(a *Attestation) { a.Envelope.Signature = "!!" }},
		{"bad-certificate-base64", func(a *Attestation) { a.VerificationMaterial.Certificate = "!!" }},
		{"bad-certificate-der", func(a *Attestation) {
			a.VerificationMaterial.Certificate = base64.StdEncoding.EncodeToString([]byte("nope"))
		}},
		{"no-tlog-entries", func(a *Attestation) { a.VerificationMaterial.TransparencyEntries = nil }},
		{"bad-tlog-entry", func(a *Attestation) {
			a.VerificationMaterial.TransparencyEntries = []json.RawMessage{json.RawMessage(`{"bogus": 1}`)}
		}},
		{"empty-predicate-unknown-type", func(a *Attestation) {
			a.Envelope.Statement = base64.StdEncoding.EncodeToString([]byte(
				`{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"https://example.com/empty/v1","predicate":null}`,
			))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			prov := loadProvenance(t)
			tc.mutate(&prov.AttestationBundles[0].Attestations[0])
			_, err := prov.Envelopes(dist)
			require.Error(t, err)
		})
	}
}
