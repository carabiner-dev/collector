// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"fmt"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/signer/options"
	sigstoreProtoDSSE "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"

	"github.com/carabiner-dev/collector/statement"
)

var _ attestation.Envelope = (*Envelope)(nil)

type Envelope struct {
	Signatures []attestation.Signature `json:"signatures"`
	Statement  attestation.Statement   `json:"-"`
	*sigstoreProtoDSSE.Envelope
}

// GetStatement parses the envelope state, stetement.
func (env *Envelope) GetStatement() attestation.Statement {
	// Parse the payload bytes if they have not been parsed yet
	if env.Statement == nil {
		s, err := statement.Parsers.Parse(env.Payload)
		if err == nil {
			env.Statement = s
		}
	}
	return env.Statement
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

// Verify checks the envelope signatures against the supplied public keys
// and records the conclusion in the predicate's verification data. The
// function takes either a slice of, or individual key.PublicKeyProvider
// objects. For more information see the carabiner signer public key
// library:
//
//	https://github.com/carabiner-dev/signer/blob/main/key/public.go
//
// Every conclusion is recorded, not only success: an envelope without
// signatures, one verified without any keys to check against, and one
// whose signatures match none of the keys all leave a Verification whose
// status says so. An error is returned only when no conclusion could be
// reached, for example when a key cannot be read.
func (env *Envelope) Verify(args ...any) error {
	pred := env.GetPredicate()
	if pred == nil {
		return fmt.Errorf("unable to set verification, envelope has no predicate")
	}
	if env.Envelope == nil {
		return fmt.Errorf("unable to verify, envelope has no DSSE data")
	}

	// Prepare the keys to verify
	keys := []key.PublicKeyProvider{}
	for _, a := range args {
		switch vm := a.(type) {
		case []key.PublicKeyProvider:
			keys = append(keys, vm...)
		case *key.Private:
			keys = append(keys, vm)
		case *key.Public:
			keys = append(keys, vm)
		}
	}

	verification, err := signer.NewVerifier().VerifyStatement(
		&signer.EnvelopeArtifact{Envelope: env.Envelope},
		options.WithPublicKeys(keys...),
	)
	if err != nil {
		return fmt.Errorf("verifying DSSE signatures: %w", err)
	}

	// Set the verification in the predicate
	pred.SetVerification(verification)

	// Ensure the predicate has the verificationd data
	if pred.GetVerification() == nil {
		return fmt.Errorf("unable to fixate signature verification result in predicate")
	}
	return nil
}

// GetVerifications returns the envelop signtature verifications
func (env *Envelope) GetVerification() attestation.Verification {
	if env.GetPredicate() == nil {
		return nil
	}
	return env.GetStatement().GetVerification()
}

// Signature is a clone of the dsse signature struct that can be copied around
type Signature struct {
	KeyID     string
	Signature []byte
}
