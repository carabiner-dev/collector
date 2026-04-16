// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
		{
			name:     "namespace with slashes",
			purl:     "pkg:maven/org/apache/commons/commons-lang3@3.12.0",
			baseURL:  defaultBaseURL,
			expected: "https://repo.maven.apache.org/maven2/org/apache/commons/commons-lang3/3.12.0/",
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

func TestArtifactTypeAndClassifier(t *testing.T) {
	for _, tc := range []struct {
		name           string
		purl           string
		wantType       string
		wantClassifier string
	}{
		{
			name:           "defaults",
			purl:           "pkg:maven/com.example/foo@1.0.0",
			wantType:       "jar",
			wantClassifier: "",
		},
		{
			name:           "type war",
			purl:           "pkg:maven/com.example/foo@1.0.0?type=war",
			wantType:       "war",
			wantClassifier: "",
		},
		{
			name:           "classifier sources",
			purl:           "pkg:maven/com.example/foo@1.0.0?classifier=sources",
			wantType:       "jar",
			wantClassifier: "sources",
		},
		{
			name:           "type and classifier",
			purl:           "pkg:maven/com.example/foo@1.0.0?type=jar&classifier=javadoc",
			wantType:       "jar",
			wantClassifier: "javadoc",
		},
		{
			name:           "empty type falls back to jar",
			purl:           "pkg:maven/com.example/foo@1.0.0?type=",
			wantType:       "jar",
			wantClassifier: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(WithPackageURL(tc.purl))
			require.NoError(t, err)
			require.Equal(t, tc.wantType, c.Options.artifactType())
			require.Equal(t, tc.wantClassifier, c.Options.artifactClassifier())
		})
	}
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

func TestBaseURLFromQualifier(t *testing.T) {
	c, err := New(WithPackageURL("pkg:maven/com.example/foo@1.0.0?repository_url=https://nexus.example.com/repo"))
	require.NoError(t, err)
	require.Equal(t, "https://nexus.example.com/repo", c.Options.BaseURL)
	require.Equal(t,
		"https://nexus.example.com/repo/com/example/foo/1.0.0/",
		c.Options.directoryURL(),
	)
}

func TestBaseURLQualifierOverriddenByWithBaseURL(t *testing.T) {
	c, err := New(
		WithPackageURL("pkg:maven/com.example/foo@1.0.0?repository_url=https://from-qualifier.com"),
		WithBaseURL("https://explicit-override.com"),
	)
	require.NoError(t, err)
	require.Equal(t, "https://explicit-override.com", c.Options.BaseURL)
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

func TestResolveFilename(t *testing.T) {
	for _, tc := range []struct {
		name       string
		artifactID string
		sv         snapshotVersion
		expected   string
	}{
		{
			name:       "jar without classifier",
			artifactID: "commons-lang3",
			sv:         snapshotVersion{Extension: "jar", Value: "3.21.0-20260403.173453-4"},
			expected:   "commons-lang3-3.21.0-20260403.173453-4.jar",
		},
		{
			name:       "jar with classifier",
			artifactID: "commons-lang3",
			sv:         snapshotVersion{Classifier: "sources", Extension: "jar", Value: "3.21.0-20260403.173453-4"},
			expected:   "commons-lang3-3.21.0-20260403.173453-4-sources.jar",
		},
		{
			name:       "cyclonedx json with classifier",
			artifactID: "commons-lang3",
			sv:         snapshotVersion{Classifier: "cyclonedx", Extension: "json", Value: "3.21.0.slsa-20260403.173453-4"},
			expected:   "commons-lang3-3.21.0.slsa-20260403.173453-4-cyclonedx.json",
		},
		{
			name:       "spdx.json multi-dot extension",
			artifactID: "commons-lang3",
			sv:         snapshotVersion{Extension: "spdx.json", Value: "3.21.0.slsa-20260403.173453-4"},
			expected:   "commons-lang3-3.21.0.slsa-20260403.173453-4.spdx.json",
		},
		{
			name:       "jar.asc signature",
			artifactID: "commons-lang3",
			sv:         snapshotVersion{Extension: "jar.asc", Value: "3.21.0.slsa-20260402.132124-3"},
			expected:   "commons-lang3-3.21.0.slsa-20260402.132124-3.jar.asc",
		},
		{
			name:       "intoto.jsonl",
			artifactID: "commons-lang3",
			sv:         snapshotVersion{Extension: "intoto.jsonl", Value: "3.21.0.slsa-20260403.173453-4"},
			expected:   "commons-lang3-3.21.0.slsa-20260403.173453-4.intoto.jsonl",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, resolveFilename(tc.artifactID, tc.sv))
		})
	}
}

func TestFindSnapshotVersion(t *testing.T) {
	md := &mavenMetadata{
		Versioning: mavenVersioning{
			SnapshotVersions: []snapshotVersion{
				{Extension: "jar", Value: "3.21.0-20260403.173453-4"},
				{Extension: "jar.asc", Value: "3.21.0-20260402.132124-3"},
				{Extension: "intoto.jsonl", Value: "3.21.0-20260403.173453-4"},
				{Extension: "spdx.json", Value: "3.21.0-20260403.173453-4"},
				{Classifier: "cyclonedx", Extension: "json", Value: "3.21.0-20260403.173453-4"},
				{Classifier: "sources", Extension: "jar", Value: "3.21.0-20260403.173453-4"},
			},
		},
	}

	// Found cases
	sv, ok := findSnapshotVersion(md, "jar", "")
	require.True(t, ok)
	require.Equal(t, "3.21.0-20260403.173453-4", sv.Value)

	sv, ok = findSnapshotVersion(md, "jar.asc", "")
	require.True(t, ok)
	require.Equal(t, "3.21.0-20260402.132124-3", sv.Value)

	sv, ok = findSnapshotVersion(md, "json", "cyclonedx")
	require.True(t, ok)
	require.Equal(t, "cyclonedx", sv.Classifier)

	sv, ok = findSnapshotVersion(md, "jar", "sources")
	require.True(t, ok)
	require.Equal(t, "sources", sv.Classifier)

	// Not found
	_, ok = findSnapshotVersion(md, "cdx.json", "")
	require.False(t, ok)

	_, ok = findSnapshotVersion(md, "jar", "nonexistent")
	require.False(t, ok)
}
