// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package repository

import "github.com/carabiner-dev/signer/key"

// SignatureVerifier is implemented by repositories that support key-based
// signature verification. The agent distributes its keys to any
// repository satisfying this interface when repositories are added.
type SignatureVerifier interface {
	SetKeys(keys []key.PublicKeyProvider)
}
