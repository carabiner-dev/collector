// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"fmt"
	"testing"

	"github.com/carabiner-dev/attestation"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name         string
		opts         Options
		expectedType string
	}{
		{"no-capabilities", Options{}, "*http.Collector"},
		{"subject", Options{TemplateSubject: "https://example.com"}, "*http.CollectorSubject"},
		{"predicate-type", Options{TemplatePredicateType: "https://example.com"}, "*http.CollectorPredicateType"},
		{"dual", Options{TemplatePredicateType: "https://example.com", TemplateSubject: "https://exactl.com"}, "*http.CollectorSubjectAndType"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(
				WithTemplatePredicateType(tt.opts.TemplatePredicateType),
				WithTemplateSubject(tt.opts.TemplateSubject),
			)
			require.NoError(t, err)
			require.Equal(t, tt.expectedType, fmt.Sprintf("%T", c))
		})
	}
}

func TestFetchData(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name            string
		expectedAtts    int
		mustErr         bool
		uri             string
		subjectTemplate string
		typeTemplate    string
	}{
		{"fixed-url", 2, false, "https://storage.googleapis.com/google-rebuild-attestations/npm/chalk/5.6.2/chalk-5.6.2.tgz/rebuild.intoto.jsonl", "", ""},
		{"bad-url", 0, true, "https://this-is-wrong/myadata.json", "", ""},
		{"url-404", 0, false, "https://storage-that-is-note.googleapis.com/google-rebuild-attestations/npm/chalk/5.6.2/chalk-5.6.2.tgz/SOMETHING", "", ""},
		{"subject", 0, false, "https://storage-that-is-note.googleapis.com/google-rebuild-attestations/npm/chalk/5.6.2/chalk-5.6.2.tgz/SOMETHING", "https://storage.googleapis.com/google-rebuild-attestations/npm/chalk/5.6.2/chalk-5.6.2.tgz/rebuild.intoto.jsonl", ""},
		{"predicate-type", 0, false, "https://storage-that-is-note.googleapis.com/google-rebuild-attestations/npm/chalk/5.6.2/chalk-5.6.2.tgz/SOMETHING", "", "https://storage.googleapis.com/google-rebuild-attestations/npm/chalk/5.6.2/chalk-5.6.2.tgz/rebuild.intoto.jsonl"},
		{"both", 0, false, "https://storage-that-is-note.googleapis.com/google-rebuild-attestations/npm/chalk/5.6.2/chalk-5.6.2.tgz/SOMETHING", "https://storage.googleapis.com/google-rebuild-attestations/npm/chalk/5.6.2/chalk-5.6.2.tgz/rebuild.intoto.jsonl", "https://storage.googleapis.com/google-rebuild-attestations/npm/chalk/5.6.2/chalk-5.6.2.tgz/rebuild.intoto.jsonl"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			collector, err := New(
				WithURL(tt.uri),
				WithTemplateSubject(tt.subjectTemplate),
				WithTemplatePredicateType(tt.typeTemplate),
			)
			// If we know it will err, don't retry
			if tt.mustErr {
				collector.(*Collector).Options.Retries = 1 //nolint:errcheck,forcetypeassert
			}
			require.NoError(t, err)
			atts, err := collector.Fetch(t.Context(), attestation.FetchOptions{
				Limit: 0,
				Query: nil,
			})
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, atts, tt.expectedAtts)

			if tt.subjectTemplate != "" {
				sf, ok := collector.(attestation.FetcherBySubject)
				require.True(t, ok)
				atts, err := sf.FetchBySubject(t.Context(), attestation.FetchOptions{}, []attestation.Subject{&intoto.ResourceDescriptor{
					Name: "test",
					Uri:  "http://example.com",
					Digest: map[string]string{
						"sha256": "0071d3218204864d8896822c37757ad5c6f7fb9fd09fbb22aa216816d6b7e4a5",
					},
				}})
				require.NoError(t, err)
				require.NotEmpty(t, atts)
			}

			if tt.typeTemplate != "" {
				sf, ok := collector.(attestation.FetcherByPredicateType)
				require.True(t, ok)
				atts, err := sf.FetchByPredicateType(t.Context(), attestation.FetchOptions{}, []attestation.PredicateType{"http://example.com/"})
				require.NoError(t, err)
				require.NotEmpty(t, atts)
			}
		})
	}
	//
}
