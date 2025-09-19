// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package http

import "net/url"

type optFn = func(*Options) error

// Options captures the URLs and templates for the http collector variants.
// The options control the collector variant that gets returned by New()
type Options struct {
	URL                          string
	TemplateSubject              string
	TemplateSubjectDigest        string
	TemplateSubjectName          string
	TemplateSubjectUri           string
	TemplatePredicateType        string
	TemplatePredicateTypeSubject string
	Retries                      uint
	ReadJSONL                    bool
}

func (o *Options) CanFetchSubject() bool {
	return o.TemplateSubject != "" || o.TemplateSubjectDigest != "" || o.TemplateSubjectName != ""
}

func (o *Options) CanFetchPredicateType() bool {
	return o.TemplatePredicateType != ""
}

func (o *Options) CanTemplatePredicateTypeSubject() bool {
	return o.TemplatePredicateTypeSubject != ""
}

// WithReadJSONL sets the options to assume the data read will be in linear
// json data.
func WithReadJSONL(doit bool) optFn {
	return func(opts *Options) error {
		opts.ReadJSONL = doit
		return nil
	}
}

// WithRetries fetches the number of retires to read
func WithRetries(num uint) optFn {
	return func(opts *Options) error {
		opts.Retries = num
		return nil
	}
}

// WithURL sets the URl to fetch the data
func WithURL(uriString string) optFn {
	return func(opts *Options) error {
		_, err := url.Parse(uriString)
		if err != nil {
			return err
		}
		opts.URL = uriString
		return nil
	}
}

func WithTemplateSubject(templ string) optFn {
	return func(opts *Options) error {
		opts.TemplateSubject = templ
		return nil
	}
}

func WithTemplateSubjectDigest(templ string) optFn {
	return func(opts *Options) error {
		opts.TemplateSubjectDigest = templ
		return nil
	}
}

func WithTemplateSubjectName(templ string) optFn {
	return func(opts *Options) error {
		opts.TemplateSubjectName = templ
		return nil
	}
}

func WithTemplateSubjectUri(templ string) optFn {
	return func(opts *Options) error {
		opts.TemplateSubjectUri = templ
		return nil
	}
}

func WithTemplatePredicateType(templ string) optFn {
	return func(opts *Options) error {
		opts.TemplatePredicateType = templ
		return nil
	}
}
