// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package spdx3 parses SPDX 3 documents into a native predicate. The parsed
// value is the *spdx3.Envelope the carabiner SPDX 3 library returns: the
// document's @context and its graph of nodes, each typed to its SPDX class.
//
// SPDX 2 documents are handled by the sibling spdx package, which keys off a
// different predicate type and leaves the payload as plain JSON.
package spdx3

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/carabiner-dev/attestation"
	spdx3 "github.com/carabiner-dev/spdx3"

	"github.com/carabiner-dev/collector/predicate/generic"
)

// PredicateType is the in-toto predicate type of an SPDX 3 document.
var PredicateType = attestation.PredicateType("https://spdx.dev/Document/v3")

type Parser struct{}

// Ensure this parser implements the interface
var _ attestation.PredicateParser = (*Parser)(nil)

func New() *Parser {
	return &Parser{}
}

// Parse reads an SPDX 3 document and returns it as a predicate carrying the
// parsed graph. Data that does not sniff as SPDX 3 returns
// attestation.ErrNotCorrectFormat, data that does but will not parse returns
// the reason it failed.
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	if !Sniff(data) {
		return nil, attestation.ErrNotCorrectFormat
	}

	env, err := spdx3.NewParser().Parse(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parsing SPDX 3 document: %w", err)
	}

	return &generic.Predicate{
		Type:   PredicateType,
		Parsed: env,
		Data:   data,
	}, nil
}

func (p *Parser) SupportsType(predTypes ...attestation.PredicateType) bool {
	return slices.Contains(predTypes, PredicateType)
}
