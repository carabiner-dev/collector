// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	"fmt"
	"slices"

	"github.com/carabiner-dev/attestation"
	protoOSV "github.com/carabiner-dev/osv/go/osv"

	"github.com/carabiner-dev/collector/predicate/generic"
)

var (
	// PredicateType is the OSV results predicate type this parser emits.
	PredicateType = attestation.PredicateType("https://ossf.github.io/osv-schema/results@v1")

	// legacyPredicateType is the previous, schema-patch-versioned type. It is
	// still accepted on read so attestations produced before the switch to the
	// major-version type keep parsing.
	legacyPredicateType = attestation.PredicateType("https://ossf.github.io/osv-schema/results@v1.6.7")

	// supportedTypes is the set of predicate types this parser will read.
	supportedTypes = []attestation.PredicateType{PredicateType, legacyPredicateType}
)

type Parser struct{}

var _ attestation.PredicateParser = (*Parser)(nil)

func New() *Parser {
	return &Parser{}
}

// SupportsType returns true if the OSV parser supports any of the given types.
// Both the current major-version type and the legacy patch-versioned type are
// accepted.
func (*Parser) SupportsType(predTypes ...attestation.PredicateType) bool {
	for _, predType := range predTypes {
		if slices.Contains(supportedTypes, predType) {
			return true
		}
	}
	return false
}

// Parse parses a byte slice into a OSV predicate
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	parser := protoOSV.NewParser()
	results, err := parser.ParseResults(data)
	if err != nil {
		return nil, fmt.Errorf("parsing results into predicate: %w", err)
	}

	if results == nil || (results.GetDate() == nil && len(results.GetResults()) == 0) {
		return nil, attestation.ErrNotCorrectFormat
	}

	return &generic.Predicate{
		Type:   PredicateType,
		Parsed: results,
		Data:   data,
	}, nil
}
