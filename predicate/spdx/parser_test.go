// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package spdx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/stretchr/testify/require"
)

// The SPDX 2 parser must claim SPDX 2 documents and decline everything
// else — in particular SPDX 3, which protobom's sniffer also recognizes as
// SPDX but which belongs to the spdx3 parser.
func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		fixture string
		accept  bool
	}{
		{"spdx2", "spdx2.json", true},
		{"spdx3", "spdx3.json", false},
		{"cyclonedx", "cyclonedx.json", false},
		{"other json", "other.json", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "spdx3", "testdata", tc.fixture))
			require.NoError(t, err)

			pred, err := New().Parse(data)
			if !tc.accept {
				require.ErrorIs(t, err, attestation.ErrNotCorrectFormat)
				require.Nil(t, pred)
				return
			}
			require.NoError(t, err)
			require.Equal(t, PredicateType, pred.GetType())
		})
	}
}
