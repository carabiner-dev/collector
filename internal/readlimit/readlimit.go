// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package readlimit provides helpers to enforce read size limits across
// repository collectors.
package readlimit

import "io"

// DefaultMaxReadSize is the fallback maximum read size (7 MiB) used when
// the caller does not specify a limit (i.e. MaxReadSize == 0).
const DefaultMaxReadSize int64 = 7 << 20

// Resolve returns maxReadSize if it is positive, otherwise DefaultMaxReadSize.
func Resolve(maxReadSize int64) int64 {
	if maxReadSize > 0 {
		return maxReadSize
	}
	return DefaultMaxReadSize
}

// Reader wraps r with an io.LimitReader using the resolved max read size.
func Reader(r io.Reader, maxReadSize int64) io.Reader {
	return io.LimitReader(r, Resolve(maxReadSize))
}
