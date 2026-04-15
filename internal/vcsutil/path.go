// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package vcsutil contains helpers for working with vcslocator components.
package vcsutil

// FileRepoPathToLocal converts a vcslocator file:// RepoPath into a native
// filesystem path. On Windows, vcslocator yields "/C:/foo/bar" for a file URL
// like file:///C:/foo/bar; go-git's local opener reads that as a
// drive-relative path and prepends the current drive, so the leading slash
// must be stripped when a drive letter is present.
func FileRepoPathToLocal(p string) string {
	if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		return p[1:]
	}
	return p
}
