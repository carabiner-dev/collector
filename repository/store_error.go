// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"fmt"
	"slices"
	"strings"
)

// StoreError is returned by repositories that keep storing the remaining
// envelopes when one of them fails. It records how many envelopes were
// stored and, by their position in the slice handed to Store, the ones
// that were not and why. Callers can decide whether a partial store is
// acceptable, for example by checking AllFailed.
type StoreError struct {
	Stored int
	Failed map[int]error
}

// NewStoreError returns an empty StoreError ready to record failures.
func NewStoreError() *StoreError {
	return &StoreError{Failed: map[int]error{}}
}

// ErrorOrNil returns e as an error when any envelope failed and nil
// otherwise, so a Store implementation can end with it.
func (e *StoreError) ErrorOrNil() error {
	if len(e.Failed) == 0 {
		return nil
	}
	return e
}

// Error lists the failed envelopes in order.
func (e *StoreError) Error() string {
	msgs := make([]string, 0, len(e.Failed))
	for _, i := range e.indexes() {
		msgs = append(msgs, fmt.Sprintf("#%d: %v", i, e.Failed[i]))
	}
	return fmt.Sprintf(
		"failed to store %d of %d envelopes: %s",
		len(e.Failed), len(e.Failed)+e.Stored, strings.Join(msgs, "; "),
	)
}

// Unwrap returns the errors of the failed envelopes so errors.Is and
// errors.As can inspect them.
func (e *StoreError) Unwrap() []error {
	errs := make([]error, 0, len(e.Failed))
	for _, i := range e.indexes() {
		errs = append(errs, e.Failed[i])
	}
	return errs
}

// AllFailed is true when not a single envelope was stored.
func (e *StoreError) AllFailed() bool {
	return e.Stored == 0
}

func (e *StoreError) indexes() []int {
	idx := make([]int, 0, len(e.Failed))
	for i := range e.Failed {
		idx = append(idx, i)
	}
	slices.Sort(idx)
	return idx
}
