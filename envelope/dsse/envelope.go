// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"github.com/carabiner-dev/attestation"
	sigstoreProtoDSSE "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"

	"github.com/carabiner-dev/collector/statement"
)

var _ attestation.Envelope = (*Envelope)(nil)

type Envelope struct {
	Signatures   []attestation.Signature  `json:"signatures"`
	Statement    attestation.Statement    `json:"-"`
	Verification attestation.Verification `json:"-"`
	sigstoreProtoDSSE.Envelope
}

func (env *Envelope) GetStatement() attestation.Statement {
	// This should not happen here.
	s, err := statement.Parsers.Parse(env.Payload)
	if err == nil {
		return s
	}
	return nil
}

func (env *Envelope) GetPredicate() attestation.Predicate {
	if s := env.GetStatement(); s != nil {
		return env.GetStatement().GetPredicate()
	}
	return nil
}

func (env *Envelope) GetSignatures() []attestation.Signature {
	return env.Signatures
}

func (env *Envelope) GetCertificate() attestation.Certificate {
	return nil
}

// TODO(puerco): Implement
func (env *Envelope) Verify() error {
	return nil
}

// GetVerifications returns the envelop signtature verifications
func (env *Envelope) GetVerification() attestation.Verification {
	if env.GetStatement() == nil {
		return nil
	}
	return env.GetStatement().GetVerification()
}

// Signature is a clone of the dsse signature struct that can be copied around
type Signature struct {
	KeyID     string
	Signature []byte
}
