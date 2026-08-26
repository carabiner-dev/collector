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
	"google.golang.org/protobuf/encoding/protojson"

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

// Statement is the collector's in-toto statement. The exported fields are
// the JSON-facing ones; the embedded proto carries the subjects and the raw
// predicate as decoded, and its own type and predicate type fields are kept
// empty so they never render under their Go JSON names.
type Statement struct {
	PredicateType attestation.PredicateType `json:"predicateType"`
	Predicate     attestation.Predicate     `json:"predicate"`
	Type          string                    `json:"_type"`
	gointoto.Statement
}

// MarshalJSON renders the statement in its in-toto JSON form: _type,
// subject, predicateType and predicate. The embedded proto's fields are not
// rendered directly, which keeps its Go JSON names (type, predicate_type)
// out of the output whichever way the statement was built. Subjects are
// rendered with protojson for the same reason: encoding/json would use the
// proto's Go names (download_location, media_type) instead of the in-toto
// ones (downloadLocation, mediaType). An unset type is rendered as the
// in-toto statement type URI.
func (s *Statement) MarshalJSON() ([]byte, error) {
	typ := s.Type
	if typ == "" {
		typ = gointoto.StatementTypeUri
	}

	var subjects []json.RawMessage
	for i, sbj := range s.Subject {
		data, err := protojson.Marshal(sbj)
		if err != nil {
			return nil, fmt.Errorf("marshaling subject %d: %w", i, err)
		}
		subjects = append(subjects, data)
	}

	return json.Marshal(struct {
		Type          string                    `json:"_type"`
		Subject       []json.RawMessage         `json:"subject,omitempty"`
		PredicateType attestation.PredicateType `json:"predicateType"`
		Predicate     attestation.Predicate     `json:"predicate"`
	}{
		Type:          typ,
		Subject:       subjects,
		PredicateType: s.PredicateType,
		Predicate:     s.Predicate,
	})
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

// GetType returns the statement type URI. It shadows the embedded proto's
// getter, which reads the proto field this type keeps empty.
func (s *Statement) GetType() string {
	return s.Type
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
