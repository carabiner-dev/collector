// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package verifier holds the signer verifier shared by every envelope.
package verifier

import (
	"sync"

	"github.com/policylabs/signer"
)

var (
	once   sync.Once
	shared *signer.Verifier
)

// Default returns the process-wide verifier, built from the signer's
// defaults on first use. Envelopes verify with it unless the caller hands
// them one, so trust material resolved for one envelope (the sigstore
// trusted roots, which may come from TUF) serves every envelope after it.
func Default() *signer.Verifier {
	once.Do(func() {
		shared = signer.NewVerifier()
	})
	return shared
}
