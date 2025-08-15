// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	"os"
	"testing"

	"github.com/carabiner-dev/attestation"
	protoOSV "github.com/carabiner-dev/osv/go/osv"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		path        string
		data        []byte
		mustErr     bool
		verifyParse func(*testing.T, attestation.Predicate)
	}{
		{"debian", "testdata/osv-scanner-release.json", []byte{}, false, func(t *testing.T, pred attestation.Predicate) {
			t.Helper()
			require.NotNil(t, pred.GetParsed())
			parsed, ok := pred.GetParsed().(*protoOSV.Results)
			require.True(t, ok)
			require.NotNil(t, parsed.GetDate())
			require.NotNil(t, parsed.GetResults())

			require.Len(t, parsed.GetResults(), 1)
			require.Len(t, parsed.GetResults()[0].GetPackages(), 4)
			require.Len(t, parsed.GetResults()[0].GetPackages()[0].GetVulnerabilities(), 4)
			require.Len(t, parsed.GetResults()[0].GetPackages()[0].GetVulnerabilities()[0].GetAffected(), 3)

			require.Equal(t, "GHSA-r9px-m959-cxf4", parsed.GetResults()[0].GetPackages()[0].GetVulnerabilities()[0].GetId())
		}},
		{"scanner-2", "testdata/osv-scan-2.0.0.json", []byte{}, false, func(t *testing.T, pred attestation.Predicate) {
			t.Helper()
			require.NotNil(t, pred.GetParsed())
			parsed, ok := pred.GetParsed().(*protoOSV.Results)
			require.True(t, ok)
			require.NotNil(t, parsed.GetResults())

			require.Len(t, parsed.GetResults(), 1)
			require.Len(t, parsed.GetResults()[0].GetPackages(), 2)
			require.Len(t, parsed.GetResults()[0].GetPackages()[0].GetVulnerabilities(), 2)
			require.Len(t, parsed.GetResults()[0].GetPackages()[0].GetVulnerabilities()[0].GetAffected(), 3)

			require.Equal(t, "GHSA-c6gw-w398-hv78", parsed.GetResults()[0].GetPackages()[0].GetVulnerabilities()[0].GetId())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parser := &Parser{}
			data := tc.data
			var err error
			if len(data) == 0 && tc.path != "" {
				data, err = os.ReadFile(tc.path)
				require.NoError(t, err)
			}
			pred, err := parser.Parse(data)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pred)
			if tc.verifyParse != nil {
				tc.verifyParse(t, pred)
			}
		})
	}
}
