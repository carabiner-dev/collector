// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package intoto implements a parser and a statement variant for
// attestations in the in-toto format.
package intoto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/carabiner-dev/attestation"
	gointoto "github.com/in-toto/attestation/go/v1"

	"github.com/carabiner-dev/collector/predicate"
)

// var _ attestation.Subject = (*Subject)(nil)
type StatementOption func(*Statement)

func WithPredicate(pred attestation.Predicate) StatementOption {
	return func(stmnt *Statement) {
		stmnt.Predicate = pred
		stmnt.PredicateType = pred.GetType()
	}
}

func WithSubject(subjects ...*gointoto.ResourceDescriptor) StatementOption {
	return func(stmnt *Statement) {
		stmnt.Subject = append(stmnt.Subject, subjects...)
	}
}

func NewStatement(opts ...StatementOption) *Statement {
	s := &Statement{
		Predicate: nil,
		Type:      gointoto.StatementTypeUri,
		Statement: gointoto.Statement{},
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

type Statement struct {
	PredicateType attestation.PredicateType `json:"predicateType"`
	Predicate     attestation.Predicate     `json:"predicate"`
	Type          string                    `json:"_type"`
	gointoto.Statement
}

func (s *Statement) AddSubject(sbj attestation.Subject) {
	descr := gointoto.ResourceDescriptor{
		Name:   sbj.GetName(),
		Uri:    sbj.GetUri(),
		Digest: sbj.GetDigest(),
	}
	s.Subject = append(s.Subject, &descr)
}

func (s *Statement) GetPredicate() attestation.Predicate {
	return s.Predicate
}

// ParsePredicate reparses the underlying intoto predicate and regenerates the
// statement's predicate.
func (s *Statement) ParsePredicate() error {
	pred, err := predicate.Parsers.Parse([]byte(s.Statement.GetPredicate().String()))
	if err != nil {
		return fmt.Errorf("parsing predicate: %w", err)
	}

	s.Predicate = pred
	return nil
}

// GetSubjects returns the statement's subjects
func (s *Statement) GetSubjects() []attestation.Subject {
	ret := make([]attestation.Subject, 0, len(s.Subject))
	for i := range s.Subject {
		ret = append(ret, s.Subject[i])
	}
	return ret
}

func (s *Statement) GetPredicateType() attestation.PredicateType {
	return s.PredicateType
}

// ToJson returns a byte slice with the predicate in JSON
func (s *Statement) ToJson() ([]byte, error) {
	var b bytes.Buffer
	if err := s.WriteJson(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (s *Statement) WriteJson(w io.Writer) error {
	s.Type = gointoto.StatementTypeUri // This needs to be coerced as it will not be read from proto
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("writing JSON stream: %w", err)
	}
	return nil
}

// GetVerifications returns the verifications from the underlying predicate
func (s *Statement) GetVerification() attestation.Verification {
	if s.GetPredicate() == nil {
		return nil
	}
	return s.GetPredicate().GetVerification()
}
