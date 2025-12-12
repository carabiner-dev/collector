// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"crypto/x509"
	"fmt"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/signer"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/options"
	sigstore "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

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

func (e *Envelope) GetSignatures() []attestation.Signature {
	return nil
}

// GetVerifications returns the signtature verifications stored in the
// predicate (via the statement)
func (env *Envelope) GetVerification() attestation.Verification {
	if env.GetStatement() == nil {
		return nil
	}
	return env.GetStatement().GetVerification()
}

// Verify checks the bundle signatures and generatesit Verification data.
// If the envelope is already verified, the signatures are not verified
// again.
func (e *Envelope) Verify(_ ...any) error {
	// If the bundle is already verified, don't retry
	if e.GetVerification() != nil {
		return nil
	}

	// Verify the sigstore signatures
	verifier := signer.NewVerifier()

	// We skip the identity verification as the policy chekcs it at runtime:
	verifier.Options.SkipIdentityCheck = true

	// Verify the bundle. We discard the result for now as it does not include
	// the signature. We may capture it at some point.
	if _, err := verifier.VerifyParsedBundle(
		&sgbundle.Bundle{Bundle: &e.Bundle},
		options.WithSkipIdentityCheck(true),
	); err != nil {
		return fmt.Errorf("verifying sigstore signatures: %w", err)
	}

	if e.GetVerificationMaterial() == nil {
		return fmt.Errorf("no verification material found in bundle")
	}

	// Fetch the cert, depending on the verification material, it may
	// be in the chain or just the certificate.
	var cert *protocommon.X509Certificate
	if c := e.Bundle.GetVerificationMaterial().GetCertificate(); c != nil {
		cert = c
	}

	if chain := e.Bundle.GetVerificationMaterial().GetX509CertificateChain(); cert == nil && chain != nil && len(chain.GetCertificates()) > 0 {
		cert = chain.GetCertificates()[0]
	}

	if cert == nil {
		return fmt.Errorf("no certificate found in bundle")
	}

	x509cert, err := x509.ParseCertificate(cert.GetRawBytes())
	if err != nil {
		return fmt.Errorf("parsing cert: %w", err)
	}

	summary, err := certificate.SummarizeCertificate(x509cert)
	if err != nil {
		return fmt.Errorf("summarizing cert: %w", err)
	}

	logrus.Debug("Parsed sigstore cert data:")
	logrus.Debugf("  OIDC issuer:  %s", summary.Issuer)
	logrus.Debugf("  Cert SAN:     %s", summary.SubjectAlternativeName)
	logrus.Debugf("  Cert Issuer:  %s", summary.CertificateIssuer)

	// Register the verification data
	e.GetPredicate().SetVerification(&sapi.Verification{
		Signature: &sapi.SignatureVerification{
			Date:     timestamppb.Now(),
			Verified: true,
			Identities: []*sapi.Identity{
				{
					Sigstore: &sapi.IdentitySigstore{
						Issuer:   summary.Issuer,
						Identity: summary.SubjectAlternativeName,
					},
				},
			},
		},
	})

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
