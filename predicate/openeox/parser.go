// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package openeox

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/openeox"

	"github.com/carabiner-dev/collector/predicate/generic"
)

var (
	PredicateTypeShell = attestation.PredicateType("https://docs.oasis-open.org/openeox/shell/v1.0")
	PredicateTypeCore  = attestation.PredicateType("https://docs.oasis-open.org/openeox/core/v1.0")
)

type Parser struct{}

func New() *Parser {
	return &Parser{}
}

func (*Parser) SupportsType(predTypes ...attestation.PredicateType) bool {
	return slices.Contains(predTypes, PredicateTypeShell) || slices.Contains(predTypes, PredicateTypeCore)
}

// Parse reads a byte slice with an OpenEoX shell or core and returns an attestation
// predicate with the appropriate predicate type.
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	parser, err := openeox.NewParser()
	if err != nil {
		return nil, fmt.Errorf("creating openeox parser: %w", err)
	}

	isShell := true
	shell, err := parser.ParseShell(data)
	if err != nil {
		if isFormatError(err) {
			isShell = false
		} else {
			return nil, fmt.Errorf("parsing data: %w", err)
		}
	}

	if isShell {
		return &generic.Predicate{
			Type:   PredicateTypeShell,
			Parsed: shell,
			Data:   data,
		}, nil
	}

	// If its not a shell, it should be a direct core
	core, err := parser.ParseCore(data)
	if err != nil {
		if isFormatError(err) {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("parsing data: %w", err)
	}

	return &generic.Predicate{
		Type:   PredicateTypeCore,
		Parsed: core,
		Data:   data,
	}, nil
}

// isFormatError returns true when err indicates the data does not match the
// parser's expected format. The openeox library may signal this via
// attestation.ErrNotCorrectFormat or via a protobuf "unknown field" error.
func isFormatError(err error) bool {
	if errors.Is(err, attestation.ErrNotCorrectFormat) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "proto:") && strings.Contains(msg, "unknown field")
}
