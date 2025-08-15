// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package intoto

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/carabiner-dev/attestation"
	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/ampel/pkg/formats/predicate"
)

type Parser struct{}

func (p *Parser) Parse(b []byte) (attestation.Statement, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("empty statement data when attempting to parse")
	}
	stmt := Statement{
		Predicate: nil,
		Statement: v1.Statement{},
	}

	// Decode the statement data
	if err := protojson.Unmarshal(b, &stmt); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("decoding statement json: %w", err)
	}

	// Check if we got something meaningful
	if stmt.Predicate == nil && len(stmt.Subject) == 0 {
		return nil, attestation.ErrNotCorrectFormat
	}

	if stmt.Statement.PredicateType != "" {
		stmt.PredicateType = attestation.PredicateType(stmt.Statement.PredicateType)
		stmt.Statement.PredicateType = ""
	}

	pdata, err := stmt.Statement.Predicate.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate data to JSON: %w", err)
	}
	parseOpts := []predicate.ParseOption{}
	if stmt.GetPredicateType() != "" {
		logrus.Debugf("constraining predicate parser to attestation type: %s", stmt.GetPredicateType())
		parseOpts = append(parseOpts, predicate.WithTypeHints([]attestation.PredicateType{
			stmt.GetPredicateType(),
		}))
	}
	pred, err := predicate.Parsers.Parse(pdata, parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("parsing predicate: %w", err)
	}

	if stmt.GetPredicateType() != "" {
		if err := pred.SetType(stmt.GetPredicateType()); err != nil {
			return nil, fmt.Errorf("setting predicate type: %w", err)
		}
	}

	stmt.Predicate = pred

	return &stmt, nil
}

func (p *Parser) ParseBase64(b []byte) (attestation.Statement, error) {
	res, err := base64.RawStdEncoding.DecodeString(string(b))
	if err != nil {
		return nil, fmt.Errorf("decoding base64 data: %w", err)
	}
	return p.Parse(res)
}
