// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStoreError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("rejected")

	partial := &StoreError{
		Stored: 2,
		Failed: map[int]error{3: errors.New("timeout"), 1: fmt.Errorf("wrapped: %w", sentinel)},
	}
	require.Equal(t, "failed to store 2 of 4 envelopes: #1: wrapped: rejected; #3: timeout", partial.Error())
	require.False(t, partial.AllFailed())
	require.ErrorIs(t, partial, sentinel, "the failed envelope errors must be reachable through errors.Is")

	var serr *StoreError
	require.ErrorAs(t, fmt.Errorf("storing: %w", partial), &serr)
	require.Equal(t, 2, serr.Stored)

	total := &StoreError{Failed: map[int]error{0: errors.New("nope")}}
	require.True(t, total.AllFailed())
	require.Equal(t, "failed to store 1 of 1 envelopes: #0: nope", total.Error())
}
