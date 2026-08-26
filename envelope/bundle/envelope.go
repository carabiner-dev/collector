// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"fmt"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/options"
	sigstore "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/collector/envelope/dsse"
	"github.com/carabiner-dev/collector/statement/intoto"
)

type Envelope struct {
	sigstore.Bundle
	Signatures []attestation.Signature
	Statement  attestation.Statement
}

func (e *Envelope) GetStatementOrErr() (attestation.Statement, error) {
	if e.Statement != nil {
		return e.Statement, nil
	}
	if e.GetDsseEnvelope() == nil {
		return nil, fmt.Errorf("no dsse envelope found in bundle")
	}

	//  TODO(puerco): Select parser from statement parsers list
	if e.GetDsseEnvelope().GetPayloadType() != "application/vnd.in-toto+json" {
		return nil, fmt.Errorf("payload is not an intoto attestation")
	}

	// So, for now, this is fixed to the intoto parser
	ip := intoto.Parser{}
	statement, err := ip.Parse(e.GetDsseEnvelope().GetPayload())
	if err != nil {
		return nil, fmt.Errorf("parsing intoto payload: %w", err)
	}

	// Store the statement
	e.Statement = statement
	logrus.Debugf("Bundled predicate is of type %s", statement.GetPredicateType())
	return statement, nil
}

func (e *Envelope) GetStatement() attestation.Statement {
	statement, err := e.GetStatementOrErr()
	if err != nil {
		logrus.Debugf("ERROR: %v", err)
		return nil
	}
	return statement
}

func (env *Envelope) GetPredicate() attestation.Predicate {
	if s := env.GetStatement(); s != nil {
		return env.GetStatement().GetPredicate()
	}
	return nil
}

func (e *Envelope) GetCertificate() attestation.Certificate {
	return nil
}

// GetSignatures returns the signatures of the DSSE envelope wrapped in the
// bundle. They are extracted lazily on first call.
func (e *Envelope) GetSignatures() []attestation.Signature {
	if e.Signatures == nil {
		if dsseEnv := e.GetDsseEnvelope(); dsseEnv != nil {
			for _, s := range dsseEnv.GetSignatures() {
				e.Signatures = append(e.Signatures, &dsse.Signature{
					KeyID:     s.GetKeyid(),
					Signature: s.GetSig(),
				})
			}
		}
	}
	return e.Signatures
}

// GetVerifications returns the signtature verifications stored in the
// predicate (via the statement)
func (env *Envelope) GetVerification() attestation.Verification {
	if env.GetStatement() == nil {
		return nil
	}
	return env.GetStatement().GetVerification()
}

// Verify checks the bundle signatures against the sigstore or SPIFFE trust
// material configured in the signer library and records the conclusion in
// the predicate's verification data. Every conclusion is recorded, not
// only success: an unsigned envelope, a bundle no configured verifier can
// check, and a bundle whose signatures do not verify all leave a
// Verification whose status says so. An error is returned only when no
// conclusion could be reached.
//
// Signer identities are not matched here; the policy checks them at
// evaluation time against the identities recorded in the verification.
// If the bundle already carries a successful verification, the signatures
// are not verified again.
func (e *Envelope) Verify(_ ...any) error {
	// If the bundle is already verified, don't retry
	if v := e.GetVerification(); v != nil && v.GetVerified() {
		return nil
	}
	pred := e.GetPredicate()
	if pred == nil {
		return fmt.Errorf("unable to set verification, bundle has no predicate")
	}

	verification, err := signer.NewVerifier().VerifyStatement(
		&signer.BundleArtifact{Bundle: &sgbundle.Bundle{Bundle: &e.Bundle}},
		options.WithSkipIdentityCheck(true),
	)
	if err != nil {
		return fmt.Errorf("verifying sigstore signatures: %w", err)
	}

	sig := verification.GetSignature()
	logrus.Debugf("Bundle signature verification: %s", sig.GetStatus())
	for _, id := range sig.GetIdentities() {
		logrus.Debugf("  Signer: %s", id.Principal())
	}
	if !sig.GetVerified() {
		logrus.Debugf("  Reason: %s", sig.GetError())
	}

	pred.SetVerification(verification)
	return nil
}

// MarshalJSON implements the json.Marshaler interface by wrapping the protojson
// package. This allows the bundles to be marshaled correctly with the JSON module.
func (e *Envelope) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(&e.Bundle)
}

func (e *Envelope) UnmarshalJSON(data []byte) error {
	p := Parser{}

	if err := p.unmarshalTo(e, data); err != nil {
		return fmt.Errorf("parsing bundle: %w", err)
	}

	return nil
}
