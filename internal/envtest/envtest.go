// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package envtest holds attestation envelopes for tests.
package envtest

import (
	"errors"

	"github.com/carabiner-dev/attestation"
)

// Unserializable is an attestation.Envelope that cannot be serialized to
// JSON. Storers serialize envelopes before storing them, so it exercises
// how they handle an envelope that fails on its own.
type Unserializable struct{}

var _ attestation.Envelope = Unserializable{}

// ErrUnserializable is the error Unserializable fails with.
var ErrUnserializable = errors.New("envelope cannot be serialized")

func (Unserializable) MarshalJSON() ([]byte, error)              { return nil, ErrUnserializable }
func (Unserializable) GetStatement() attestation.Statement       { return nil }
func (Unserializable) GetPredicate() attestation.Predicate       { return nil }
func (Unserializable) GetSignatures() []attestation.Signature    { return nil }
func (Unserializable) GetCertificate() attestation.Certificate   { return nil }
func (Unserializable) GetVerification() attestation.Verification { return nil }
func (Unserializable) Verify(...any) error                       { return nil }
