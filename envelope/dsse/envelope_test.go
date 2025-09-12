package dsse

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

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
		mustVerify   bool
		envelopePath string
		keys         []key.PublicKeyProvider
	}{
		{"good-key", false, true, "rebuild.intoto.json", []key.PublicKeyProvider{goodKey}},
		{"bad-key", false, false, "rebuild.intoto.json", []key.PublicKeyProvider{badKey}},
		{"both-keys", false, true, "rebuild.intoto.json", []key.PublicKeyProvider{badKey, goodKey}},
		{"no-keys", false, false, "rebuild.intoto.json", []key.PublicKeyProvider{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f, err := os.Open(filepath.Join("testdata", tt.envelopePath))
			require.NoError(t, err)
			envelopes, err := dsseParser.ParseStream(f)
			require.NoError(t, err)

			fmt.Printf("%+v\n", envelopes[0])
			err = envelopes[0].Verify(tt.keys)
			if tt.mustFail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Check the results
			verification := envelopes[0].GetVerification()
			require.NotNil(t, verification)

			if !tt.mustVerify {
				require.False(t, verification.GetVerified())
				return
			}

			require.True(t, verification.GetVerified())
			// Check identity
		})
	}
}
