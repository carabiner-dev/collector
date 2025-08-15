// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package bare implenta a parser to make non-signed attestations
// compatible with the ampel policy engine.
package bare

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/hasher"

	"github.com/carabiner-dev/collector/predicate"
	"github.com/carabiner-dev/collector/statement"
	"github.com/carabiner-dev/collector/statement/intoto"
)

type Parser struct{}

func New() *Parser {
	return &Parser{}
}

// ParseStream reads an open stream and returns a parsed envelope
func (p *Parser) ParseStream(r io.Reader) ([]attestation.Envelope, error) {
	env := &Envelope{}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading input data: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("short read when parsing attestation source")
	}

	digests, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(data)})
	if err != nil || len(*digests) == 0 {
		return nil, fmt.Errorf("error hashing envelope data: %w", err)
	}

	// When dealing with bare attestations, we can expect any JSON so we synthesize
	// an attestation and we will create a known predicate for it EXCEPT when the
	// json data is an attestation.
	s, err := statement.Parsers.Parse(data)
	if err == nil {
		env.Statement = s
		return []attestation.Envelope{env}, nil
	}

	if !errors.Is(err, attestation.ErrNotCorrectFormat) {
		return nil, fmt.Errorf("parsing predicate: %w", err)
	}

	// OK, the reader does not contain a known statement type. So, to synthesize
	// our attestation, first we parse the data as a predicate
	pred, err := predicate.Parsers.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing predicate: %w", err)
	}

	// Assign the new statement
	s = intoto.NewStatement(intoto.WithPredicate(pred))
	s.GetPredicate().SetOrigin(digests.ToResourceDescriptors()[0])
	env.Statement = s
	return []attestation.Envelope{env}, nil
}

// FileExtensions returns the file extennsions this parser will look at.
func (p *Parser) FileExtensions() []string {
	return []string{"json"}
}
