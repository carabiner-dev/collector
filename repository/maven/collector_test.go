// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDirectoryListing(t *testing.T) {
	html := `<html><head><title>Central Repository</title></head><body>
<a href="../">../</a>
<a href="alibabacloud-ga20191120-3.0.1.jar">alibabacloud-ga20191120-3.0.1.jar</a>
<a href="alibabacloud-ga20191120-3.0.1.jar.asc">alibabacloud-ga20191120-3.0.1.jar.asc</a>
<a href="alibabacloud-ga20191120-3.0.1.jar.sha1">alibabacloud-ga20191120-3.0.1.jar.sha1</a>
<a href="alibabacloud-ga20191120-3.0.1.pom">alibabacloud-ga20191120-3.0.1.pom</a>
<a href="alibabacloud-ga20191120-3.0.1.jsonl">alibabacloud-ga20191120-3.0.1.jsonl</a>
<a href="alibabacloud-ga20191120-3.0.1.spdx.json">alibabacloud-ga20191120-3.0.1.spdx.json</a>
<a href="alibabacloud-ga20191120-3.0.1.cdx.json">alibabacloud-ga20191120-3.0.1.cdx.json</a>
</body></html>`

	files := parseDirectoryListing(html)
	require.Len(t, files, 7)
	require.Contains(t, files, "alibabacloud-ga20191120-3.0.1.jar")
	require.Contains(t, files, "alibabacloud-ga20191120-3.0.1.jar.asc")
	require.Contains(t, files, "alibabacloud-ga20191120-3.0.1.jsonl")
	require.Contains(t, files, "alibabacloud-ga20191120-3.0.1.spdx.json")
	require.Contains(t, files, "alibabacloud-ga20191120-3.0.1.cdx.json")
}

func TestParseDirectoryListingSkipsAbsoluteAndParent(t *testing.T) {
	html := `<a href="../">Parent</a>
<a href="/absolute/path">Absolute</a>
<a href="https://example.com">External</a>
<a href="file.jar">file.jar</a>`

	files := parseDirectoryListing(html)
	require.Len(t, files, 1)
	require.Equal(t, "file.jar", files[0])
}

func TestOptionsDirectoryURL(t *testing.T) {
	for _, tc := range []struct {
		name     string
		purl     string
		baseURL  string
		expected string
	}{
		{
			name:     "maven central",
			purl:     "pkg:maven/com.aliyun/alibabacloud-ga20191120@3.0.1",
			baseURL:  defaultBaseURL,
			expected: "https://repo.maven.apache.org/maven2/com/aliyun/alibabacloud-ga20191120/3.0.1/",
		},
		{
			name:     "custom nexus",
			purl:     "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			baseURL:  "https://nexus.example.com/repository/maven-central",
			expected: "https://nexus.example.com/repository/maven-central/org/apache/commons/commons-lang3/3.12.0/",
		},
		{
			name:     "deep namespace",
			purl:     "pkg:maven/io.github.user.project/artifact@1.0.0",
			baseURL:  defaultBaseURL,
			expected: "https://repo.maven.apache.org/maven2/io/github/user/project/artifact/1.0.0/",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(WithPackageURL(tc.purl), WithBaseURL(tc.baseURL))
			require.NoError(t, err)
			require.Equal(t, tc.expected, c.Options.directoryURL())
		})
	}
}

func TestOptionsArtifactBaseName(t *testing.T) {
	c, err := New(WithPackageURL("pkg:maven/com.aliyun/alibabacloud-ga20191120@3.0.1"))
	require.NoError(t, err)
	require.Equal(t, "alibabacloud-ga20191120-3.0.1", c.Options.artifactBaseName())
}

func TestNewValidation(t *testing.T) {
	// Missing purl
	_, err := New()
	require.Error(t, err)

	// Non-maven purl
	_, err = New(WithPackageURL("pkg:npm/foo@1.0.0"))
	require.Error(t, err)

	// Missing version
	_, err = New(WithPackageURL("pkg:maven/com.example/foo"))
	require.Error(t, err)

	// Valid
	c, err := New(WithPackageURL("pkg:maven/com.example/foo@1.0.0"))
	require.NoError(t, err)
	require.Equal(t, defaultBaseURL, c.Options.BaseURL)
}

func TestWithBaseURL(t *testing.T) {
	c, err := New(
		WithPackageURL("pkg:maven/com.example/foo@1.0.0"),
		WithBaseURL("https://nexus.example.com/repo/"),
	)
	require.NoError(t, err)
	// Trailing slash should be trimmed.
	require.Equal(t, "https://nexus.example.com/repo", c.Options.BaseURL)
}

func TestBuildFactory(t *testing.T) {
	repo, err := Build("pkg:maven/com.example/foo@1.0.0")
	require.NoError(t, err)
	require.NotNil(t, repo)

	c, ok := repo.(*Collector)
	require.True(t, ok)
	require.Equal(t, "com.example", c.Options.PackageURL.Namespace)
	require.Equal(t, "foo", c.Options.PackageURL.Name)
	require.Equal(t, "1.0.0", c.Options.PackageURL.Version)
}
