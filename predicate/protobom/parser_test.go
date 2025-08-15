// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package protobom

import (
	"os"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/collector/predicate/generic"
)

func TestParse(t *testing.T) {
	// the protobom parser is disabled for now
	t.Skip()
	for _, tc := range []struct {
		name        string
		file        string
		mustErr     bool
		badFormat   bool
		expectNodes int
		expectRoot  int
	}{
		{"spdx", "testdata/spdx.json", false, false, 40, 1},
		{"other-json", "testdata/other.json", true, true, 0, 0},
		{"invalid-json", "testdata/invalid-json.json", true, false, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Parser{}
			data, err := os.ReadFile(tc.file)
			require.NoError(t, err)
			pred, err := p.Parse(data)
			if tc.mustErr {
				require.Error(t, err)
				if tc.badFormat {
					require.ErrorIs(t, err, attestation.ErrNotCorrectFormat)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pred)
			protopred, ok := pred.(*generic.Predicate)
			require.True(t, ok)
			require.NotEmpty(t, protopred.Data)
			require.Len(t, protopred.Parsed.(*sbom.Document).GetNodeList().GetRootElements(), tc.expectRoot) //nolint:errcheck,forcetypeassert
			require.Len(t, protopred.Parsed.(*sbom.Document).GetNodeList().GetNodes(), tc.expectNodes)       //nolint:errcheck,forcetypeassert
		})
	}
}
