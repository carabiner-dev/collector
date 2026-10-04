// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"sync"
	"testing"

	"github.com/policylabs/signer"
	"github.com/stretchr/testify/require"
)

func TestDefaultIsShared(t *testing.T) {
	t.Parallel()
	const n = 8
	got := make([]*signer.Verifier, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { got[i] = Default() })
	}
	wg.Wait()
	require.NotNil(t, got[0])
	for _, v := range got[1:] {
		require.Same(t, got[0], v)
	}
}
