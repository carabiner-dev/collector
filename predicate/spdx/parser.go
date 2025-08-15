// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package spdx

import (
	"bytes"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/protobom/protobom/pkg/formats"

	"github.com/carabiner-dev/collector/predicate/json"
)

type Parser struct{}

// Ensure this parser implements the interface
var _ attestation.PredicateParser = (*Parser)(nil)

func New() *Parser {
	return &Parser{}
}

var PredicateType = attestation.PredicateType("https://spdx.dev/Document")

// Parse generates a generic JSON predicate object from any JSON it gets.
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	r := bytes.NewReader(data)
	sniffer := formats.Sniffer{}
	format, err := sniffer.SniffReader(r)
	if err != nil {
		// TODO(puerco): Swap this to a new error type
		if strings.Contains(err.Error(), "unknown SBOM format") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, err
	}

	if format.Encoding() != "json" {
		return nil, attestation.ErrNotCorrectFormat
	}

	if format.Type() != formats.SPDXFORMAT {
		return nil, attestation.ErrNotCorrectFormat
	}

	pred, err := json.New(json.WithJson(data), json.WithType(PredicateType))
	if err != nil {
		return nil, err
	}
	return pred, nil
}

func (p *Parser) SupportsType(predTypes ...attestation.PredicateType) bool {
	for _, t := range predTypes {
		if t != PredicateType {
			return false
		}
	}
	return true
}
