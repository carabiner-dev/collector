// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package maven

import (
	"testing"

	"github.com/carabiner-dev/attestation"
	gopurl "github.com/package-url/packageurl-go"
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
	// No purl — global mode is valid.
	c, err := New()
	require.NoError(t, err)
	require.False(t, c.Options.HasPackageURL())

	// Explicit empty purl — also global mode.
	c, err = New(WithPackageURL(""))
	require.NoError(t, err)
	require.False(t, c.Options.HasPackageURL())

	// Non-maven purl
	_, err = New(WithPackageURL("pkg:npm/foo@1.0.0"))
	require.Error(t, err)

	// Missing version
	_, err = New(WithPackageURL("pkg:maven/com.example/foo"))
	require.Error(t, err)

	// Valid
	c, err = New(WithPackageURL("pkg:maven/com.example/foo@1.0.0"))
	require.NoError(t, err)
	require.Equal(t, defaultBaseURL, c.Options.BaseURL)
	require.True(t, c.Options.HasPackageURL())
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

	// Verify the explicit BaseURL also wins at fetch time (configured mode
	// treats c.Options.BaseURL as authoritative and does not re-read the
	// purl's repository_url qualifier).
	require.Equal(t,
		"https://explicit-override.com/com/example/foo/1.0.0/",
		directoryURL(&c.Options.PackageURL, c.Options.BaseURL),
	)
}

func TestGlobalModeHonorsSubjectRepositoryURLQualifier(t *testing.T) {
	c, err := New() // global mode: no package URL configured
	require.NoError(t, err)

	// A per-subject purl with repository_url should target its own repo.
	p, err := gopurl.FromString("pkg:maven/com.example/foo@1.0.0?repository_url=https://from-subject.com")
	require.NoError(t, err)
	require.Equal(t, "https://from-subject.com", baseURLForPurl(&p, c.Options.BaseURL))

	// Without the qualifier, the collector's BaseURL is used as fallback.
	plain, err := gopurl.FromString("pkg:maven/com.example/bar@2.0.0")
	require.NoError(t, err)
	require.Equal(t, defaultBaseURL, baseURLForPurl(&plain, c.Options.BaseURL))
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

func TestBuildFactoryGlobalMode(t *testing.T) {
	// An empty init string (e.g. "maven:") yields a global-mode collector
	// with no configured package URL.
	repo, err := Build("")
	require.NoError(t, err)
	require.NotNil(t, repo)

	c, ok := repo.(*Collector)
	require.True(t, ok)
	require.False(t, c.Options.HasPackageURL())
	require.Equal(t, defaultBaseURL, c.Options.BaseURL)
}

// fakeSubject satisfies attestation.Subject for unit tests.
type fakeSubject struct {
	name, uri string
	digest    map[string]string
}

func (fs *fakeSubject) GetName() string              { return fs.name }
func (fs *fakeSubject) GetUri() string               { return fs.uri }
func (fs *fakeSubject) GetDigest() map[string]string { return fs.digest }

func TestExtractMavenPurls(t *testing.T) {
	subjects := []attestation.Subject{
		// Maven purl in Uri.
		&fakeSubject{uri: "pkg:maven/com.example/foo@1.0.0"},
		// Maven purl in Name.
		&fakeSubject{name: "pkg:maven/com.example/bar@2.0.0"},
		// Non-maven purl — ignored.
		&fakeSubject{uri: "pkg:npm/lodash@4.0.0"},
		// Unparseable — ignored.
		&fakeSubject{uri: "not-a-purl"},
		// Duplicate of the first — deduped.
		&fakeSubject{uri: "pkg:maven/com.example/foo@1.0.0"},
		// Incomplete maven purl (no version) — ignored.
		&fakeSubject{uri: "pkg:maven/com.example/baz"},
	}

	got := extractMavenPurls(subjects)
	require.Len(t, got, 2)

	names := []string{got[0].Name, got[1].Name}
	require.Contains(t, names, "foo")
	require.Contains(t, names, "bar")
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
