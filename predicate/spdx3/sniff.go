// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package spdx3

import (
	"encoding/json"
	"strings"

	spdx3 "github.com/carabiner-dev/spdx3"
)

// Sniff reports whether data looks like an SPDX 3 document. It reads the
// top-level keys of the JSON object only, so it is cheap enough to run
// against every predicate the collector sees before committing to a full
// parse.
//
// The signal is the JSON-LD @context: SPDX 3 documents pin the spec version
// there, and no other SBOM format the collector reads carries one.
func Sniff(data []byte) bool {
	var doc struct {
		Context json.RawMessage `json:"@context"`

		// SPDX 2 names its version at the document root, SPDX 3 states it in
		// the CreationInfo of its graph. CycloneDX names itself in bomFormat.
		// Either one means this is not an SPDX 3 document, whatever @context
		// may say.
		SPDXVersion string `json:"spdxVersion"`
		BOMFormat   string `json:"bomFormat"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return false
	}

	if doc.SPDXVersion != "" || doc.BOMFormat != "" {
		return false
	}

	if len(doc.Context) == 0 {
		return false
	}

	context := spdx3.Context{}
	if err := context.UnmarshalJSON(doc.Context); err != nil {
		return false
	}

	// Version is empty unless the context references an SPDX context URL.
	// Anything outside the 3.x line belongs to a parser that does not exist
	// yet, so it is not ours either.
	version := context.Version()
	return version == "3" || strings.HasPrefix(version, "3.")
}
