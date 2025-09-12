// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"fmt"

	"github.com/carabiner-dev/attestation"
	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/key"
	sigstoreProtoDSSE "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"google.golang.org/protobuf/types/known/timestamppb"

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

// Verify checks the payload using the supplied signatures. The function takes
// either a slice of, or individual key.PublicKeyProvider objects. For more
// information see the carabiner signer public key library:
//
//	https://github.com/carabiner-dev/signer/blob/main/key/public.go
//
// No signatures should not return an error, a verification status is returned
// but without any identities matched.
func (env *Envelope) Verify(args ...any) error {
	if env.GetPredicate() == nil {
		return fmt.Errorf("unable to set verification, envelope has no predicate")
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

	var ids []*papi.Identity
	verifier := signer.NewVerifier()
	res, err := verifier.VerifyParsedDSSE(env.Envelope, keys)
	if err != nil {
		return err
	}

	// If verification passed, add the key identities
	if res.Verified {
		for _, k := range res.Keys {
			ids = append(ids, &papi.Identity{
				Key: &papi.IdentityKey{
					Id:   k.ID(), // Not implemented yet
					Type: string(k.Scheme),
					Data: k.Data,
				},
			})
		}
	}

	// Set the verification in the predicate
	env.GetPredicate().SetVerification(&papi.Verification{
		Signature: &papi.SignatureVerification{
			Date:       timestamppb.Now(),
			Verified:   len(ids) > 0,
			Identities: ids,
		},
	})

	// Ensure the predicate has the verificationd data
	if env.GetPredicate().GetVerification() == nil {
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
