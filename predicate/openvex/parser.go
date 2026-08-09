// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package openvex

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/carabiner-dev/attestation"
	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/carabiner-dev/collector/predicate/generic"
)

type Parser struct{}

var (
	PredicateType   = attestation.PredicateType("https://openvex.dev/ns")
	PredicateType02 = attestation.PredicateType("https://openvex.dev/ns/v0.2.0")
)

var _ attestation.PredicateParser = (*Parser)(nil)

func New() *Parser {
	return &Parser{}
}

func (*Parser) SupportsType(predTypes ...attestation.PredicateType) bool {
	return slices.Contains(predTypes, PredicateType) || slices.Contains(predTypes, PredicateType02)
}

// sniff reports whether data carries an OpenVEX @context, either the bare
// context or one of its versioned locators. Other formats are JSON-LD too,
// so the presence of a @context on its own says nothing.
func sniff(data []byte) bool {
	var doc struct {
		Context string `json:"@context"`
	}
	// A @context that is not a string belongs to another format: OpenVEX
	// only ever writes the locator.
	if err := json.Unmarshal(data, &doc); err != nil {
		return false
	}
	return doc.Context == openvex.Context || strings.HasPrefix(doc.Context, openvex.Context+"/")
}

// Parse parses openvex predicate data
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	if !sniff(data) {
		return nil, attestation.ErrNotCorrectFormat
	}
	doc, err := openvex.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing VEX predicate: %w", err)
	}
	return &generic.Predicate{
		Type:   PredicateType,
		Parsed: doc,
		Data:   data,
	}, nil
}
