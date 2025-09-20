// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"text/template"

	"github.com/carabiner-dev/attestation"
	"sigs.k8s.io/release-utils/http"

	"github.com/carabiner-dev/collector/envelope"
)

// fetchGeneral is the URL to retrieve all available attestations
func fetchGeneral(_ context.Context, opts *Options, _ attestation.FetchOptions) ([]attestation.Envelope, error) {
	if len(opts.URLs) == 0 {
		return nil, fmt.Errorf("unable to do request, url empty")
	}

	// Create the agent
	a := http.NewAgent().WithRetries(opts.Retries).WithFailOnHTTPError(true)

	var attestations []attestation.Envelope
	var err error
	datas, errs := a.GetGroup(opts.URLs)
	for i := range datas {
		if errs[i] != nil {
			// Don't take 404 as an error
			if strings.Contains(errs[i].Error(), "HTTP error 404") {
				continue
			}
			return nil, fmt.Errorf("fetching http data: %w", errs[i])
		}

		// Parse the request output
		var atts []attestation.Envelope
		if opts.ReadJSONL {
			atts, err = envelope.NewJSONL().Parse(datas[i])
		} else {
			atts, err = envelope.Parsers.Parse(bytes.NewReader(datas[i]))
		}
		if err != nil {
			return nil, fmt.Errorf("parsing attestation data: %w", err)
		}
		attestations = append(attestations, atts...)
	}
	return attestations, err
}

// fetchBySubject fetches the subject from the subject URL. If the collector
// has specialized URL templates defined for name, digest or uri, then
// those will be used to fetch data.
func fetchBySubject(_ context.Context, opts *Options, _ attestation.FetchOptions, subjects []attestation.Subject) ([]attestation.Envelope, error) {
	var subjectNameTemplate, subjectDigestTemplate, subjectUriTemplate *template.Template
	var err error

	// Template for fetch by subject name
	subjNameTemplateURI := opts.TemplateSubject
	if opts.TemplateSubjectName != "" {
		subjNameTemplateURI = opts.TemplateSubjectName
	}
	if subjNameTemplateURI != "" {
		subjectNameTemplate, err = template.New("subjectNameTemplate").Parse(subjNameTemplateURI)
		if err != nil {
			return nil, fmt.Errorf("parsing predicate URL template: %w", err)
		}
	}

	// Template for fetch by subject digest
	subjDigestTemplateURI := opts.TemplateSubject
	if opts.TemplateSubjectDigest != "" {
		subjDigestTemplateURI = opts.TemplateSubjectName
	}
	if subjDigestTemplateURI != "" {
		subjectDigestTemplate, err = template.New("subjectNameTemplate").Parse(subjDigestTemplateURI)
		if err != nil {
			return nil, fmt.Errorf("parsing predicate URL template: %w", err)
		}
	}

	// Template for fetch by subject uri
	subjUriTemplateURI := opts.TemplateSubject
	if opts.TemplateSubjectUri != "" {
		subjUriTemplateURI = opts.TemplateSubjectUri
	}
	if subjUriTemplateURI != "" {
		subjectUriTemplate, err = template.New("subjectNameTemplate").Parse(subjUriTemplateURI)
		if err != nil {
			return nil, fmt.Errorf("parsing predicate URL template: %w", err)
		}
	}

	// Assemble the URLs to fetch
	urls := []string{}
	for _, subject := range subjects {
		var b bytes.Buffer

		// Assemble with the subject name
		if subjNameTemplateURI != "" && subject.GetName() != "" {
			if err := subjectNameTemplate.Execute(&b, struct{ SubjectName string }{SubjectName: subject.GetName()}); err != nil {
				return nil, fmt.Errorf("executing subject name template: %w", err)
			}
			urls = append(urls, b.String())
		}

		// Add the digest URLs
		if subjDigestTemplateURI != "" {
			for algo, val := range subject.GetDigest() {
				if err := subjectDigestTemplate.Execute(&b, struct{ SubjectAlgorithm, SubjectDigest string }{SubjectAlgorithm: algo, SubjectDigest: val}); err != nil {
					return nil, fmt.Errorf("executing subject digest template: %w", err)
				}
				urls = append(urls, b.String())
			}
		}

		// Assemble with the subject name
		if subjUriTemplateURI != "" && subject.GetUri() != "" {
			if err := subjectUriTemplate.Execute(&b, struct{ SubjectUri string }{SubjectUri: subject.GetUri()}); err != nil {
				return nil, fmt.Errorf("executing subject URI template: %w", err)
			}
			urls = append(urls, b.String())
		}
	}

	attestations := []attestation.Envelope{}
	datas, errs := http.NewAgent().WithRetries(opts.Retries).WithFailOnHTTPError(true).GetGroup(urls)
	for i, data := range datas {
		if errs[i] != nil {
			if strings.Contains(errs[i].Error(), "HTTP error 404") {
				continue
			}
			return nil, fmt.Errorf("error requesting data: %w", errs[i])
		}

		var atts []attestation.Envelope
		if opts.ReadJSONL {
			atts, err = envelope.NewJSONL().Parse(data)
		} else {
			atts, err = envelope.Parsers.Parse(bytes.NewReader(data))
		}
		if err != nil {
			return nil, fmt.Errorf("parsing attestation data: %w", err)
		}
		attestations = append(attestations, atts...)
	}
	// TODO(puerco): Trim attestations to max
	return attestations, nil
}

func fetchByPredicateType(_ context.Context, opts *Options, _ attestation.FetchOptions, types []attestation.PredicateType) ([]attestation.Envelope, error) {
	tmpl, err := template.New("urltemplate").Parse(opts.TemplatePredicateType)
	if err != nil {
		return nil, fmt.Errorf("parsing predicate URL template: %w", err)
	}
	urls := []string{}
	for _, pt := range types {
		var b bytes.Buffer
		if err := tmpl.Execute(&b, struct{ PredicateType string }{PredicateType: string(pt)}); err != nil {
			return nil, fmt.Errorf("executing predicate type template: %w", err)
		}
		urls = append(urls, b.String())
	}
	attestations := []attestation.Envelope{}
	datas, errs := http.NewAgent().WithRetries(opts.Retries).WithFailOnHTTPError(true).GetGroup(urls)
	for i, data := range datas {
		if errs[i] != nil {
			if strings.Contains(err.Error(), "HTTP error 404") {
				continue
			}
			return nil, fmt.Errorf("error requesting data: %w", err)
		}

		var atts []attestation.Envelope
		if opts.ReadJSONL {
			atts, err = envelope.NewJSONL().Parse(data)
		} else {
			atts, err = envelope.Parsers.Parse(bytes.NewReader(data))
		}
		if err != nil {
			return nil, fmt.Errorf("parsing attestation data: %w", err)
		}
		attestations = append(attestations, atts...)
	}
	// TODO(puerco): Trim attestations to max
	return attestations, nil
}
