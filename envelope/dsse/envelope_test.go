package dsse

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/key"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	t.Parallel()
	dsseParser := Parser{}
	keyParser := key.NewParser()
	goodKey, err := keyParser.ParsePublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9
nQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==
-----END PUBLIC KEY-----`))
	require.NoError(t, err)

	badKey, err := keyParser.ParsePublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq0F7Qy812rYgbwi5c1wSnevN8FEC
hDjayw2lL6wkyR9k1vWICQYbe4FqOZeulBbfWBU7/BKdtlwKRStEVEffvg==
-----END PUBLIC KEY-----`))
	require.NoError(t, err)

	for _, tt := range []struct {
		name         string
		mustFail     bool
		envelopePath string
		keys         []key.PublicKeyProvider
		unsign       bool
		wantStatus   sapi.VerificationStatus
	}{
		{"good-key", false, "rebuild.intoto.json", []key.PublicKeyProvider{goodKey}, false, sapi.VerificationStatus_VERIFIED},
		{"bad-key", false, "rebuild.intoto.json", []key.PublicKeyProvider{badKey}, false, sapi.VerificationStatus_FAILED},
		{"both-keys", false, "rebuild.intoto.json", []key.PublicKeyProvider{badKey, goodKey}, false, sapi.VerificationStatus_VERIFIED},
		{"no-keys", false, "rebuild.intoto.json", []key.PublicKeyProvider{}, false, sapi.VerificationStatus_UNVERIFIABLE},
		{"unsigned", false, "rebuild.intoto.json", []key.PublicKeyProvider{goodKey}, true, sapi.VerificationStatus_UNSIGNED},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f, err := os.Open(filepath.Join("testdata", tt.envelopePath))
			require.NoError(t, err)
			envelopes, err := dsseParser.ParseStream(f)
			require.NoError(t, err)
			env, ok := envelopes[0].(*Envelope)
			require.True(t, ok)
			if tt.unsign {
				env.Envelope.Signatures = nil
				env.Signatures = nil
			}

			err = env.Verify(tt.keys)
			if tt.mustFail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Every conclusion is recorded, whichever way it went
			verification := env.GetVerification()
			require.NotNil(t, verification)
			sv, ok := verification.(*sapi.Verification)
			require.True(t, ok)
			require.Equal(t, tt.wantStatus, sv.GetSignature().GetStatus())
			require.Equal(t, tt.wantStatus == sapi.VerificationStatus_VERIFIED, verification.GetVerified())

			if tt.wantStatus != sapi.VerificationStatus_VERIFIED {
				require.NotEmpty(t, sv.GetSignature().GetError())
				require.Empty(t, sv.GetSignature().GetIdentities())
				return
			}

			// Check identity: the good key must be the recorded signer
			require.Len(t, sv.GetSignature().GetIdentities(), 1)
			require.Equal(t, goodKey.ID(), sv.GetSignature().GetIdentities()[0].GetKey().GetId())
			require.True(t, verification.MatchesIdentity(&sapi.Identity{Key: &sapi.IdentityKey{Id: goodKey.ID()}}))
			require.False(t, verification.MatchesIdentity(&sapi.Identity{Key: &sapi.IdentityKey{Id: badKey.ID()}}))
		})
	}
}

// A marshaled envelope must be DSSE JSON: parsing it back must yield the
// same signatures, and they must still verify. Regression test for
// https://github.com/carabiner-dev/collector/issues/18.
func TestMarshalJSONRoundTrip(t *testing.T) {
	t.Parallel()
	goodKey, err := key.NewParser().ParsePublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9
nQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==
-----END PUBLIC KEY-----`))
	require.NoError(t, err)

	f, err := os.Open(filepath.Join("testdata", "rebuild.intoto.json"))
	require.NoError(t, err)
	envelopes, err := (&Parser{}).ParseStream(f)
	require.NoError(t, err)
	original, ok := envelopes[0].(*Envelope)
	require.True(t, ok)

	data, err := json.Marshal(original)
	require.NoError(t, err)

	// DSSE keys, not the wrapper's Go names
	var raw struct {
		Payload     string              `json:"payload"`
		PayloadType string              `json:"payloadType"`
		Signatures  []map[string]string `json:"signatures"`
	}
	require.NoError(t, json.Unmarshal(data, &raw))
	require.NotEmpty(t, raw.Payload)
	require.Equal(t, original.GetPayloadType(), raw.PayloadType)
	require.Len(t, raw.Signatures, 1)
	require.Contains(t, raw.Signatures[0], "sig")
	require.Contains(t, raw.Signatures[0], "keyid")
	require.NotContains(t, raw.Signatures[0], "Signature")
	require.NotContains(t, raw.Signatures[0], "KeyID")

	// Parsing it back yields the same signatures ...
	back, err := (&Parser{}).ParseStream(bytes.NewReader(data))
	require.NoError(t, err)
	parsed, ok := back[0].(*Envelope)
	require.True(t, ok)
	require.Equal(t, original.GetPayload(), parsed.GetPayload())
	require.Len(t, parsed.Envelope.GetSignatures(), 1)
	require.Equal(t, original.Envelope.GetSignatures()[0].GetKeyid(), parsed.Envelope.GetSignatures()[0].GetKeyid())
	require.Equal(t, original.Envelope.GetSignatures()[0].GetSig(), parsed.Envelope.GetSignatures()[0].GetSig())

	// ... which still verify.
	require.NoError(t, parsed.Verify([]key.PublicKeyProvider{goodKey}))
	require.NotNil(t, parsed.GetVerification())
	require.True(t, parsed.GetVerification().GetVerified())
}
