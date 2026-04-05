// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filters

import (
	"github.com/carabiner-dev/attestation"
	"github.com/sirupsen/logrus"
)

type SubjectHashMatcher struct {
	HashSets []map[string]string
}

func (sm *SubjectHashMatcher) Matches(att attestation.Envelope) bool {
	if att.GetStatement() == nil {
		return false
	}

	for _, sb := range att.GetStatement().GetSubjects() {
		if sb.GetDigest() == nil {
			continue
		}

		for _, hs := range sm.HashSets {
			matched := 0
			mismatch := false
			// Iterate over the filter's algorithms to ensure the attestation
			// cannot dodge stronger hash checks by omitting algorithms.
			for algo, expected := range hs {
				actual, ok := sb.GetDigest()[algo]
				if !ok {
					// The attestation doesn't have this algorithm.
					// Skip it — we don't require every algorithm, but
					// every algorithm present must agree.
					continue
				}

				if actual == expected {
					logrus.Debugf("%s:%s = %s", algo, expected, actual)
					matched++
				} else {
					logrus.Debugf("%s != %s ", expected, actual)
					mismatch = true
					break
				}
			}
			// Require at least one algorithm to have matched and no mismatches.
			if matched > 0 && !mismatch {
				return true
			}
		}
	}

	return false
}
