// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vulns

import (
	"os"
	"testing"

	"github.com/carabiner-dev/attestation"
	v02 "github.com/in-toto/attestation/go/predicates/vulns/v02"
	"github.com/stretchr/testify/require"
)

func TestParseV2(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name              string
		filename          string
		data              []byte
		mustErr           bool
		errType           error
		validatePredicate func(*testing.T, attestation.Predicate)
	}{
		{"v2", "testdata/vulns-v02.json", []byte{}, false, nil, func(t *testing.T, p attestation.Predicate) {
			t.Helper()
			parsed, ok := p.GetParsed().(*v02.Vulns)
			require.True(t, ok)
			require.NotNil(t, parsed.GetScanner())
			require.NotNil(t, parsed.GetScanner().GetDb())
			require.NotNil(t, parsed.GetScanner().GetResult())
			require.NotNil(t, parsed.GetMetadata())
			require.Equal(t, "pkg:github/aquasecurity/trivy@244fd47e07d1004f0aed9", parsed.GetScanner().GetUri())
			require.Equal(t, "0.19.2", parsed.GetScanner().GetVersion())
			require.Equal(t, "pkg:github/aquasecurity/trivy-db/commit/4c76bb580b2736d67751410fa4ab66d2b6b9b27d", parsed.GetScanner().GetDb().GetUri())
			require.Len(t, parsed.GetScanner().GetResult(), 1)
			require.Equal(t, "CVE-123", parsed.GetScanner().GetResult()[0].GetId())
			require.Len(t, parsed.GetScanner().GetResult()[0].GetSeverity(), 2)
		}},
		{"other-json", "", []byte(`{name: "John Doe", "Today": 1, "IsItTrue": false}`), true, attestation.ErrNotCorrectFormat, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := tc.data
			var err error
			if len(data) == 0 && tc.filename != "" {
				data, err = os.ReadFile(tc.filename)
				require.NoError(t, err)
			}
			pred, err := parseV2(data)
			if tc.mustErr {
				if tc.errType != nil {
					require.ErrorIs(t, err, tc.errType)
				}
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pred)
		})
	}
}
