// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package testutil contains helpers shared by the collector's test suites.
package testutil

import (
	"path/filepath"
	"strings"
)

// FileLocator builds a file:// locator for a local filesystem path that works
// on all platforms. On Windows the drive-letter path (e.g. C:\foo\bar) is
// converted to forward slashes and prefixed with an extra slash so the drive
// letter isn't parsed as a URL scheme (file:///C:/foo/bar).
func FileLocator(path string) string {
	p := filepath.ToSlash(path)
	if p != "" && !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return "file://" + p
}
