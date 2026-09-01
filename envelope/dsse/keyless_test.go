// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const keylessFixture = "testdata/keyless/generator.intoto.jsonl"

func parseKeylessFixture(t *testing.T) (env *Envelope, raw []byte) {
	t.Helper()
	data, err := os.ReadFile(keylessFixture)
	require.NoError(t, err)
	envs, err := (&Parser{}).ParseStream(bytes.NewReader(data))
	require.NoError(t, err)
	require.Len(t, envs, 1)
	env, ok := envs[0].(*Envelope)
	require.True(t, ok)
	return env, data
}

// The cert extension is captured on the wrapper signatures, next to the
// spec-clean proto.
func TestParserCapturesSignatureCerts(t *testing.T) {
	t.Parallel()
	env, _ := parseKeylessFixture(t)
	require.Len(t, env.Signatures, 1)
	sig, ok := env.Signatures[0].(*Signature)
	require.True(t, ok)
	assert.Contains(t, string(sig.GetCertificate()), "BEGIN CERTIFICATE")
	assert.NotEmpty(t, sig.GetSig())
}

// A parsed envelope re-marshals to its original bytes, so storing a
// keyless envelope and reading it back keeps it verifiable.
func TestMarshalKeepsTheCertExtension(t *testing.T) {
	t.Parallel()
	env, data := parseKeylessFixture(t)
	out, err := json.Marshal(env)
	require.NoError(t, err)
	assert.Equal(t, data, out)
	assert.Contains(t, string(out), `"cert":`)
}

// Without keys and without the transparency log option, verifying a
// keyless envelope records an UNVERIFIABLE conclusion naming the switch.
func TestVerifyKeylessDisabledRecordsUnverifiable(t *testing.T) {
	t.Parallel()
	env, _ := parseKeylessFixture(t)
	require.NoError(t, env.Verify())
	ver, ok := env.GetVerification().(*sapi.Verification)
	require.True(t, ok)
	assert.Equal(t, sapi.VerificationStatus_UNVERIFIABLE, ver.GetSignature().GetStatus())
	assert.Contains(t, ver.GetSignature().GetError(), "WithRekorVerification")
}

// Signer verification options pass through Verify: with the lookup
// enabled and the entry served by the test log, the keyless envelope
// verifies and the Fulcio identity is recorded on the predicate.
func TestVerifyKeylessRekorOption(t *testing.T) {
	t.Parallel()
	frozen, err := os.ReadFile("testdata/keyless/rekor-response.json")
	require.NoError(t, err)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) //nolint:errcheck // best-effort drain
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write(frozen)
		assert.NoError(t, err)
	}))
	t.Cleanup(ts.Close)

	env, _ := parseKeylessFixture(t)
	require.NoError(t, env.Verify(
		options.WithRekorVerification(true),
		options.WithRekorURL(ts.URL),
	))
	ver, ok := env.GetVerification().(*sapi.Verification)
	require.True(t, ok)
	require.Equal(t, sapi.VerificationStatus_VERIFIED, ver.GetSignature().GetStatus(), ver.GetSignature().GetError())
	ids := ver.GetSignature().GetIdentities()
	require.Len(t, ids, 1)
	assert.Contains(t, ids[0].GetSigstore().GetIdentity(), "builder_go_slsa3.yml")
}

// Arguments Verify does not understand are still rejected.
func TestVerifyRejectsUnknownArguments(t *testing.T) {
	t.Parallel()
	env, _ := parseKeylessFixture(t)
	require.ErrorContains(t, env.Verify(42), "unsupported argument")
}
