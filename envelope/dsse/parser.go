// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"fmt"
	"io"

	"github.com/carabiner-dev/attestation"
	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/collector/statement"
)

// Parser for attestations wrapped in DSSE envelopes
type Parser struct{}

// ParseFile parses a file and returns all envelopes in it.
func (p *Parser) ParseStream(r io.Reader) ([]attestation.Envelope, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading attestation envelope data: %w", err)
	}

	// Parse the envelope to its protobuf representation
	dsseEnvelope := &sdsse.Envelope{}
	// Since the envelope is simple (just three fields) we discard all
	// unknown JSON and check for the envelope integrity after parsing.
	// This avoids string matching on the error.
	unmarshler := protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}
	if err := unmarshler.Unmarshal(data, dsseEnvelope); err != nil {
		return nil, fmt.Errorf("unmarshalling data: %w", err)
	}

	// Assign the proto to our envelope wrapper
	env := Envelope{
		Envelope: dsseEnvelope,
	}

	// If there is no payload and no sig, then don't treat the envelope as DSSE
	if env.Payload == nil && len(env.Signatures) == 0 {
		return nil, attestation.ErrNotCorrectFormat
	}

	for _, s := range env.Envelope.GetSignatures() {
		env.Signatures = append(env.Signatures, &Signature{
			KeyID:     s.GetKeyid(),
			Signature: s.GetSig(),
		})
	}

	// Parse the envelope payload
	s, err := statement.Parsers.Parse(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("error parsing the envelope payload: %w", err)
	}

	env.Statement = s
	return []attestation.Envelope{&env}, nil
}

// FileExtensions returns the file extennsions this parser will look at.
func (p *Parser) FileExtensions() []string {
	return []string{"json", "intoto"}
}
